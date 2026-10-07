from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel

from gasha.ingestion.adapter import BankEventAdapter
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.errors import (
    EventRejection,
    RejectionReason,
    RejectionRecord,
    payload_fingerprint,
)
from gasha.observability.metrics import MetricsRegistry


class IngestionOutcome(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class IngestionRecord(BaseModel):
    """Persisted receipt for an accepted event — the idempotency anchor."""

    envelope: FraudEventEnvelope
    payload_fingerprint: str
    accepted_at: datetime


class IngestionResult(BaseModel):
    outcome: IngestionOutcome
    envelope: FraudEventEnvelope | None = None
    rejection: RejectionRecord | None = None
    original_accepted_at: datetime | None = None


class IngestionStore(Protocol):
    """Tenant-scoped idempotency store keyed by (tenant_id, event_id)."""

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> IngestionRecord | None: ...

    def save(self, record: IngestionRecord) -> IngestionRecord: ...


class InMemoryIngestionStore:
    """Reference store; production storage implements the same contract."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, UUID], IngestionRecord] = {}

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> IngestionRecord | None:
        return self._records.get((tenant_id, event_id))

    def save(self, record: IngestionRecord) -> IngestionRecord:
        key = (record.envelope.tenant_id, record.envelope.event_id)
        existing = self._records.get(key)
        if existing is not None:
            return existing
        self._records[key] = record
        return record


class DeadLetterSink(Protocol):
    """Where rejected events go — vendor-neutral port."""

    def put(self, record: RejectionRecord) -> None: ...


class InMemoryDeadLetterSink:
    def __init__(self) -> None:
        self._records: list[RejectionRecord] = []

    def put(self, record: RejectionRecord) -> None:
        self._records.append(record)

    @property
    def records(self) -> tuple[RejectionRecord, ...]:
        return tuple(self._records)


class IngestionService:
    """Validates, normalizes and deduplicates inbound bank events.

    Deterministic duplicate behavior over ``tenant_id + event_id``:
    an identical resubmission returns the original accepted envelope;
    a same-ID/different-payload resubmission is rejected as
    ``DUPLICATE_CONFLICT`` and dead-lettered — never a silent overwrite.
    """

    def __init__(
        self,
        adapters: Mapping[str, BankEventAdapter],
        *,
        store: IngestionStore | None = None,
        dead_letters: DeadLetterSink | None = None,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._adapters = dict(adapters)
        self._store = store or InMemoryIngestionStore()
        self._dead_letters = dead_letters or InMemoryDeadLetterSink()
        self._metrics = metrics

    @property
    def dead_letter_sink(self) -> DeadLetterSink:
        return self._dead_letters

    def ingest(self, event: InboundBankEvent) -> IngestionResult:
        if self._metrics is not None:
            self._metrics.increment(
                "gasha_events_received",
                labels={
                    "tenant_id": event.tenant_id,
                    "source_system": event.source_system,
                },
            )
        adapter = self._adapters.get(event.source_system)
        if adapter is None:
            return self._reject(
                event,
                RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE,
                f"no adapter registered for source {event.source_system!r}",
            )

        try:
            envelope = adapter.adapt(event)
        except EventRejection as rejection:
            return self._dead_letter(rejection.record)
        except Exception as exc:  # noqa: BLE001 - fail closed on adapter bugs
            return self._reject(
                event,
                RejectionReason.ADAPTER_FAILURE,
                f"adapter {adapter.adapter_type} failed: {type(exc).__name__}",
            )

        fingerprint = (
            payload_fingerprint(event.payload)
            if isinstance(event.payload, Mapping)
            else ""
        )
        existing = self._store.get(envelope.tenant_id, envelope.event_id)
        if existing is not None:
            if existing.payload_fingerprint == fingerprint:
                if self._metrics is not None:
                    self._metrics.increment(
                        "gasha_events_duplicate",
                        labels={"tenant_id": envelope.tenant_id},
                    )
                return IngestionResult(
                    outcome=IngestionOutcome.DUPLICATE,
                    envelope=existing.envelope,
                    original_accepted_at=existing.accepted_at,
                )
            if self._metrics is not None:
                self._metrics.increment(
                    "gasha_events_conflicting_duplicates",
                    labels={"tenant_id": envelope.tenant_id},
                )
            return self._dead_letter(
                RejectionRecord(
                    reason=RejectionReason.DUPLICATE_CONFLICT,
                    detail=(
                        "event_id already ingested with a different payload; "
                        "original preserved"
                    ),
                    tenant_id=envelope.tenant_id,
                    event_id=str(envelope.event_id),
                    source_system=event.source_system,
                    schema_version=event.schema_version,
                    adapter_version=adapter.adapter_version,
                    payload_fingerprint=fingerprint or None,
                )
            )

        record = self._store.save(
            IngestionRecord(
                envelope=envelope,
                payload_fingerprint=fingerprint,
                accepted_at=datetime.now(UTC),
            )
        )
        if self._metrics is not None:
            self._metrics.increment(
                "gasha_events_accepted",
                labels={"tenant_id": envelope.tenant_id},
            )
        return IngestionResult(
            outcome=IngestionOutcome.ACCEPTED,
            envelope=record.envelope,
            original_accepted_at=record.accepted_at,
        )

    def _reject(
        self,
        event: InboundBankEvent,
        reason: RejectionReason,
        detail: str,
    ) -> IngestionResult:
        return self._dead_letter(
            RejectionRecord(
                reason=reason,
                detail=detail,
                tenant_id=event.tenant_id or None,
                source_system=event.source_system,
                schema_version=event.schema_version,
                payload_fingerprint=(
                    payload_fingerprint(event.payload)
                    if isinstance(event.payload, Mapping)
                    else None
                ),
            )
        )

    def _dead_letter(self, record: RejectionRecord) -> IngestionResult:
        self._dead_letters.put(record)
        if self._metrics is not None:
            labels = {"reason": record.reason.value}
            if record.tenant_id:
                labels["tenant_id"] = record.tenant_id
            self._metrics.increment("gasha_events_rejected", labels=labels)
            if record.reason == RejectionReason.ADAPTER_FAILURE:
                self._metrics.increment(
                    "gasha_adapter_failures", labels=labels
                )
        return IngestionResult(
            outcome=IngestionOutcome.REJECTED, rejection=record
        )
