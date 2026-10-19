from __future__ import annotations

import os
import socket
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel

from gasha.domain.models import DecisionPolicy
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.tenant_scope import require_tenant


class PendingEvaluationRecord(BaseModel):
    """An ingested event whose fraud evaluation is not yet durable.

    Created when ``IngestionService`` accepts an event — *before* the
    consumer offset commits — so an acknowledged-but-unevaluated event is
    recoverable without Kafka redelivery. The stored ``event`` envelope
    preserves the original canonical transaction plus adapter/schema and
    policy version provenance; retries evaluate exactly this envelope.

    ``policy`` pins the tenant's ``DecisionPolicy`` snapshot taken at
    enqueue time: every retry re-decides under the same immutable
    policy/config/rule versions, so a tenant policy change mid-retry can
    never produce audit and evaluation records that disagree.

    ``attempts``/``next_attempt_at`` implement bounded retries: each
    failure reschedules the record, and the worker dead-letters it once
    ``attempts`` reaches the configured maximum.

    ``leased_by``/``leased_until`` implement multi-worker work
    ownership: a due record is claimed atomically by one worker for the
    lease window; other workers skip it until the lease expires.
    """

    event: FraudEventEnvelope
    policy: DecisionPolicy | None = None
    attempts: int = 0
    enqueued_at: datetime
    next_attempt_at: datetime
    last_error: str | None = None
    leased_by: str | None = None
    leased_until: datetime | None = None


class PendingEvaluationStore(Protocol):
    """Durable, tenant/event-scoped pending-evaluation ledger.

    Implementations must persist across process restarts for recovery
    guarantees to hold; the in-memory store is the reference/dev
    implementation.

    ``due`` is a claim, not a read: each returned record is atomically
    leased to the calling worker for the store's lease window, so two
    workers reconciling concurrently cannot evaluate the same event.
    ``reschedule``/``complete`` are conditional on that ownership — a
    worker that does not hold the lease leaves the row untouched and
    gets ``None``/a no-op.
    """

    def enqueue(
        self,
        event: FraudEventEnvelope,
        *,
        enqueued_at: datetime,
        policy: DecisionPolicy | None = None,
    ) -> PendingEvaluationRecord: ...

    def due(
        self, now: datetime, *, limit: int = 100
    ) -> tuple[PendingEvaluationRecord, ...]: ...

    def reschedule(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        error: str,
        next_attempt_at: datetime,
        owner: str | None = None,
    ) -> PendingEvaluationRecord | None: ...

    def complete(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        owner: str | None = None,
    ) -> None: ...


class InMemoryPendingEvaluationStore:
    """Reference implementation; see ``PostgresPendingEvaluationStore``
    for the durable production binding.

    ``tenant_ids`` is the worker's authorized tenant scope (``None`` =
    unrestricted dev mode); ``worker_id``/``lease_ttl`` give ``due``
    the same claim semantics as the Postgres store.
    """

    def __init__(
        self,
        *,
        tenant_ids: tuple[str, ...] | None = None,
        worker_id: str | None = None,
        lease_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        self._records: dict[tuple[str, UUID], PendingEvaluationRecord] = {}
        self._tenant_ids = tenant_ids
        self._worker_id = worker_id or (
            f"{socket.gethostname()}-{os.getpid()}"
        )
        self._lease_ttl = lease_ttl

    def enqueue(
        self,
        event: FraudEventEnvelope,
        *,
        enqueued_at: datetime,
        policy: DecisionPolicy | None = None,
    ) -> PendingEvaluationRecord:
        require_tenant(event.tenant_id, self._tenant_ids)
        key = (event.tenant_id, event.event_id)
        existing = self._records.get(key)
        if existing is not None:
            return existing
        record = PendingEvaluationRecord(
            event=event,
            policy=policy,
            enqueued_at=enqueued_at,
            next_attempt_at=enqueued_at,
            leased_by=self._worker_id,
            leased_until=enqueued_at + self._lease_ttl,
        )
        self._records[key] = record
        return record

    def due(
        self, now: datetime, *, limit: int = 100
    ) -> tuple[PendingEvaluationRecord, ...]:
        claimed: list[PendingEvaluationRecord] = []
        for key, record in self._records.items():
            if len(claimed) >= limit:
                break
            if record.next_attempt_at > now:
                continue
            if (
                self._tenant_ids is not None
                and key[0] not in self._tenant_ids
            ):
                continue
            if (
                record.leased_until is not None
                and record.leased_until > now
                and record.leased_by != self._worker_id
            ):
                continue
            claimed.append(
                record.model_copy(
                    update={
                        "leased_by": self._worker_id,
                        "leased_until": now + self._lease_ttl,
                    }
                )
            )
            self._records[key] = claimed[-1]
        claimed.sort(key=lambda record: record.enqueued_at)
        return tuple(claimed)

    def reschedule(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        error: str,
        next_attempt_at: datetime,
        owner: str | None = None,
    ) -> PendingEvaluationRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
        key = (tenant_id, event_id)
        record = self._records.get(key)
        if record is None:
            raise KeyError(
                f"no pending evaluation for tenant {tenant_id!r} "
                f"event {event_id}"
            )
        if record.leased_by is not None and record.leased_by != owner:
            return None
        updated = record.model_copy(
            update={
                "attempts": record.attempts + 1,
                "next_attempt_at": next_attempt_at,
                "last_error": error,
            }
        )
        self._records[key] = updated
        return updated

    def complete(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        owner: str | None = None,
    ) -> None:
        require_tenant(tenant_id, self._tenant_ids)
        record = self._records.get((tenant_id, event_id))
        if (
            record is not None
            and record.leased_by is not None
            and record.leased_by != owner
        ):
            return
        self._records.pop((tenant_id, event_id), None)

