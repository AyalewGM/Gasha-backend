from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.service import (
    DeadLetterSink,
    IngestionOutcome,
    IngestionService,
)
from gasha.observability.metrics import MetricsRegistry
from gasha.poc.historical import MissingTenantPolicyError


class CommittableEventConsumer(Protocol):
    """Source of ``InboundBankEvent`` with an explicit commit point.

    Implemented by ``JsonEventConsumer`` (transport adapter) and by
    in-memory fakes in tests. ``commit`` acknowledges every event
    returned by prior ``poll_events`` calls.
    """

    def poll_events(self, *, max_events: int = 1) -> tuple[InboundBankEvent, ...]:
        ...

    def commit(self) -> None: ...


class IngestionWorker:
    """Event-driven worker: consume -> ingest -> evaluate -> commit.

    The batch commits only after every event in it has been processed, so
    a crash mid-batch redelivers — the idempotency store in
    ``IngestionService`` absorbs the duplicates and the evaluation
    repositories are first-write-wins, making reprocessing safe.

    Accepted envelopes are forwarded to ``evaluate`` (typically
    ``ShadowOrchestrator.evaluate``). Duplicate deliveries skip
    evaluation; evaluation failures are dead-lettered instead of
    poison-looping the partition.
    """

    def __init__(
        self,
        consumer: CommittableEventConsumer,
        ingestion: IngestionService,
        *,
        evaluate: Callable[[FraudEventEnvelope], object] | None = None,
        dead_letters: DeadLetterSink | None = None,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._consumer = consumer
        self._ingestion = ingestion
        self._evaluate = evaluate
        self._dead_letters = dead_letters or ingestion.dead_letter_sink
        self._metrics = metrics

    def run_once(self, *, max_events: int = 1) -> int:
        """Processes at most ``max_events`` and commits. Returns the count."""
        events = self._consumer.poll_events(max_events=max_events)
        for event in events:
            self._process(event)
        if events:
            self._consumer.commit()
        return len(events)

    def _process(self, event: InboundBankEvent) -> None:
        result = self._ingestion.ingest(event)
        if result.outcome != IngestionOutcome.ACCEPTED:
            return
        if result.envelope is None or self._evaluate is None:
            return
        self._evaluate_event(self._evaluate, result.envelope, event)

    def _evaluate_event(
        self,
        evaluate: Callable[[FraudEventEnvelope], object],
        envelope: FraudEventEnvelope,
        event: InboundBankEvent,
    ) -> None:
        try:
            evaluate(envelope)
        except MissingTenantPolicyError:
            self._dead_letter(
                envelope,
                event,
                RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE,
                f"no decision policy registered for tenant "
                f"{envelope.tenant_id!r}",
            )
        except Exception as exc:  # noqa: BLE001 - fail closed, keep consuming
            self._dead_letter(
                envelope,
                event,
                RejectionReason.EVALUATION_FAILURE,
                f"evaluation failed: {type(exc).__name__}",
            )

    def _dead_letter(
        self,
        envelope: FraudEventEnvelope,
        event: InboundBankEvent,
        reason: RejectionReason,
        detail: str,
    ) -> None:
        self._dead_letters.put(
            RejectionRecord(
                reason=reason,
                detail=detail,
                tenant_id=envelope.tenant_id,
                event_id=str(envelope.event_id),
                source_system=event.source_system,
                schema_version=event.schema_version,
            )
        )
        if self._metrics is not None:
            self._metrics.increment(
                "gasha_worker_evaluation_failures",
                labels={
                    "tenant_id": envelope.tenant_id,
                    "reason": reason.value,
                },
            )
