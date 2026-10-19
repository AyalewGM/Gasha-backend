from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from uuid import UUID

from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.service import (
    DeadLetterSink,
    IngestionOutcome,
    IngestionService,
)
from gasha.ingestion.transport import EventBatch
from gasha.observability.metrics import MetricsRegistry
from gasha.poc.historical import MissingTenantPolicyError


class CommittableEventConsumer(Protocol):
    """Source of ``InboundBankEvent`` with an explicit commit point.

    Implemented by ``JsonEventConsumer`` (transport adapter) and by
    in-memory fakes in tests. ``commit`` acknowledges every record pulled
    by prior ``poll_batch`` calls — including undecodable ones, which is
    why the batch also reports ``records_consumed``.
    """

    def poll_batch(self, *, max_events: int = 1) -> EventBatch:
        ...

    def commit(self) -> None: ...


class IngestionWorker:
    """Event-driven worker: consume -> ingest -> evaluate -> commit.

    The batch commits after every consumed record has been handled —
    including malformed ones dead-lettered during decode — so a crash
    mid-batch redelivers safely while a malformed-only batch is still
    acknowledged exactly once.

    ``ACCEPTED`` envelopes are forwarded to ``evaluate`` (typically
    ``ShadowOrchestrator.evaluate``). ``DUPLICATE`` redeliveries are
    re-evaluated when ``evaluation_complete`` reports no durable
    evaluation yet — ingestion acceptance and evaluation completion are
    separate lifecycle steps, and a crash between them must not lose the
    decision. Evaluation failures dead-letter instead of poison-looping.
    """

    def __init__(
        self,
        consumer: CommittableEventConsumer,
        ingestion: IngestionService,
        *,
        evaluate: Callable[[FraudEventEnvelope], object] | None = None,
        evaluation_complete: Callable[[str, UUID], bool] | None = None,
        dead_letters: DeadLetterSink | None = None,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self._consumer = consumer
        self._ingestion = ingestion
        self._evaluate = evaluate
        self._evaluation_complete = evaluation_complete
        self._dead_letters = dead_letters or ingestion.dead_letter_sink
        self._metrics = metrics

    def run_once(self, *, max_events: int = 1) -> int:
        """Processes at most ``max_events`` records and commits them."""
        batch = self._consumer.poll_batch(max_events=max_events)
        for event in batch.events:
            self._process(event)
        if batch.records_consumed:
            self._consumer.commit()
        return batch.records_consumed

    def _process(self, event: InboundBankEvent) -> None:
        result = self._ingestion.ingest(event)
        envelope = result.envelope
        if envelope is None or self._evaluate is None:
            return
        if result.outcome == IngestionOutcome.REJECTED:
            return
        if result.outcome == IngestionOutcome.DUPLICATE and self._already_evaluated(
            envelope
        ):
            return
        self._evaluate_event(self._evaluate, envelope, event)

    def _already_evaluated(self, envelope: FraudEventEnvelope) -> bool:
        if self._evaluation_complete is None:
            # No durability hook supplied: skip re-evaluation of duplicates
            # rather than risk a second evaluation being misread as the first.
            return True
        return self._evaluation_complete(
            envelope.tenant_id, envelope.event_id
        )

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
