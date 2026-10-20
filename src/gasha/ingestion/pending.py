from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel

from gasha.ingestion.contracts import FraudEventEnvelope


class PendingEvaluationRecord(BaseModel):
    """An ingested event whose fraud evaluation is not yet durable.

    Created when ``IngestionService`` accepts an event — *before* the
    consumer offset commits — so an acknowledged-but-unevaluated event is
    recoverable without Kafka redelivery. The stored ``event`` envelope
    preserves the original canonical transaction plus adapter/schema and
    policy version provenance; retries evaluate exactly this envelope.

    ``attempts``/``next_attempt_at`` implement bounded retries: each
    failure reschedules the record, and the worker dead-letters it once
    ``attempts`` reaches the configured maximum.
    """

    event: FraudEventEnvelope
    attempts: int = 0
    enqueued_at: datetime
    next_attempt_at: datetime
    last_error: str | None = None


class PendingEvaluationStore(Protocol):
    """Durable, tenant/event-scoped pending-evaluation ledger.

    Implementations must persist across process restarts for recovery
    guarantees to hold; the in-memory store is the reference/dev
    implementation.
    """

    def enqueue(
        self, event: FraudEventEnvelope, *, enqueued_at: datetime
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
    ) -> PendingEvaluationRecord: ...

    def complete(self, tenant_id: str, event_id: UUID) -> None: ...


class InMemoryPendingEvaluationStore:
    """Reference implementation; see ``PostgresPendingEvaluationStore``
    for the durable production binding."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, UUID], PendingEvaluationRecord] = {}

    def enqueue(
        self, event: FraudEventEnvelope, *, enqueued_at: datetime
    ) -> PendingEvaluationRecord:
        key = (event.tenant_id, event.event_id)
        existing = self._records.get(key)
        if existing is not None:
            return existing
        record = PendingEvaluationRecord(
            event=event,
            enqueued_at=enqueued_at,
            next_attempt_at=enqueued_at,
        )
        self._records[key] = record
        return record

    def due(
        self, now: datetime, *, limit: int = 100
    ) -> tuple[PendingEvaluationRecord, ...]:
        due = [
            record
            for record in self._records.values()
            if record.next_attempt_at <= now
        ]
        due.sort(key=lambda record: record.enqueued_at)
        return tuple(due[:limit])

    def reschedule(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        error: str,
        next_attempt_at: datetime,
    ) -> PendingEvaluationRecord:
        key = (tenant_id, event_id)
        record = self._records.get(key)
        if record is None:
            raise KeyError(
                f"no pending evaluation for tenant {tenant_id!r} "
                f"event {event_id}"
            )
        updated = record.model_copy(
            update={
                "attempts": record.attempts + 1,
                "next_attempt_at": next_attempt_at,
                "last_error": error,
            }
        )
        self._records[key] = updated
        return updated

    def complete(self, tenant_id: str, event_id: UUID) -> None:
        self._records.pop((tenant_id, event_id), None)
