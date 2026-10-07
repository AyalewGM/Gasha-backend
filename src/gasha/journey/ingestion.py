from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel

from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.errors import (
    EventRejection,
    RejectionReason,
    RejectionRecord,
)
from gasha.ingestion.service import DeadLetterSink, InMemoryDeadLetterSink
from gasha.journey.events import JourneyEventEnvelope
from gasha.journey.repository import JourneyEventRepository
from gasha.observability.metrics import MetricsRegistry


class JourneyEventAdapter(Protocol):
    """Adapter contract for normalizing journey-category payloads."""

    @property
    def adapter_type(self) -> str: ...

    @property
    def adapter_version(self) -> str: ...

    def adapt_journey(
        self, event: InboundBankEvent
    ) -> JourneyEventEnvelope: ...


class JourneyIngestionOutcome(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class JourneyIngestionResult(BaseModel):
    outcome: JourneyIngestionOutcome
    envelope: JourneyEventEnvelope | None = None
    rejection: RejectionRecord | None = None


class JourneyIngestionService:
    """Routes inbound journey events into the tenant-scoped repository.

    Idempotent on ``(tenant_id, event_id)`` via the repository's append
    semantics; adapter failures and validation rejections dead-letter
    rather than crash the stream.
    """

    def __init__(
        self,
        adapters: Mapping[str, JourneyEventAdapter],
        repository: JourneyEventRepository,
        *,
        dead_letters: DeadLetterSink | None = None,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._adapters = dict(adapters)
        self._repository = repository
        self._dead_letters = dead_letters or InMemoryDeadLetterSink()
        self._metrics = metrics

    def ingest(self, event: InboundBankEvent) -> JourneyIngestionResult:
        if self._metrics is not None:
            self._metrics.increment(
                "gasha_journey_events_received",
                labels={"tenant_id": event.tenant_id},
            )
        adapter = self._adapters.get(event.source_system)
        if adapter is None:
            return self._dead_letter(
                RejectionRecord(
                    reason=RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE,
                    detail=(
                        f"no adapter for source {event.source_system!r}"
                    ),
                    tenant_id=event.tenant_id,
                    source_system=event.source_system,
                    schema_version=event.schema_version,
                )
            )
        try:
            envelope = adapter.adapt_journey(event)
        except EventRejection as rejection:
            return self._dead_letter(rejection.record)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return self._dead_letter(
                RejectionRecord(
                    reason=RejectionReason.ADAPTER_FAILURE,
                    detail=f"adapter failed: {type(exc).__name__}",
                    tenant_id=event.tenant_id,
                    source_system=event.source_system,
                    schema_version=event.schema_version,
                )
            )

        if not self._repository.append(envelope.event):
            if self._metrics is not None:
                self._metrics.increment(
                    "gasha_journey_events_duplicate",
                    labels={"tenant_id": envelope.tenant_id},
                )
            return JourneyIngestionResult(
                outcome=JourneyIngestionOutcome.DUPLICATE,
                envelope=envelope,
            )
        if self._metrics is not None:
            self._metrics.increment(
                "gasha_journey_events_processed",
                labels={"tenant_id": envelope.tenant_id},
            )
        return JourneyIngestionResult(
            outcome=JourneyIngestionOutcome.ACCEPTED, envelope=envelope
        )

    def _dead_letter(
        self, record: RejectionRecord
    ) -> JourneyIngestionResult:
        self._dead_letters.put(record)
        return JourneyIngestionResult(
            outcome=JourneyIngestionOutcome.REJECTED, rejection=record
        )
