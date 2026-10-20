from __future__ import annotations

import os
import socket
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from gasha.domain.models import DecisionPolicy
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.lease import (
    EvaluationLease,
    LeaseLostError,
    current_evaluation_lease,
)
from gasha.ingestion.pending import (
    PendingEvaluationRecord,
    PendingEvaluationStore,
)
from gasha.ingestion.service import (
    DeadLetterSink,
    IngestionOutcome,
    IngestionService,
)
from gasha.ingestion.transport import EventBatch
from gasha.observability.metrics import MetricsRegistry
from gasha.poc.historical import MissingTenantPolicyError
from gasha.tenant_scope import require_tenant


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

    ``ACCEPTED`` envelopes are written to the ``pending`` ledger
    *before* evaluation, then evaluated. Recovery therefore never
    depends on Kafka redelivery: an acknowledged-but-unevaluated event
    is retried from the ledger — across ordinary restarts with no
    re-injected message — until it produces a durable evaluation, is
    dead-lettered after ``max_evaluation_attempts``, or is proven
    complete by ``evaluation_complete``. ``DUPLICATE`` redeliveries
    follow the same path through the ledger.

    Retry semantics: each failure increments ``attempts`` and delays the
    next attempt by ``retry_backoff``; a missing-tenant-policy failure
    is terminal (no retry can help) and dead-letters immediately.
    """

    def __init__(
        self,
        consumer: CommittableEventConsumer,
        ingestion: IngestionService,
        *,
        evaluate: (
            Callable[[FraudEventEnvelope, DecisionPolicy | None], object]
            | None
        ) = None,
        evaluation_complete: Callable[[str, UUID], bool] | None = None,
        policy_for: Callable[[str], DecisionPolicy | None] | None = None,
        pending: PendingEvaluationStore | None = None,
        max_evaluation_attempts: int = 3,
        retry_backoff: timedelta = timedelta(seconds=30),
        clock: Callable[[], datetime] | None = None,
        dead_letters: DeadLetterSink | None = None,
        metrics: MetricsRegistry | None = None,
        worker_id: str | None = None,
        tenant_ids: tuple[str, ...] | None = None,
    ) -> None:
        self._tenant_ids = tenant_ids
        self._consumer = consumer
        self._ingestion = ingestion
        self._evaluate = evaluate
        self._evaluation_complete = evaluation_complete
        self._policy_for = policy_for
        self._pending = pending
        self._max_evaluation_attempts = max_evaluation_attempts
        self._retry_backoff = retry_backoff
        self._clock = clock or (lambda: datetime.now(UTC))
        self._dead_letters = dead_letters or ingestion.dead_letter_sink
        self._metrics = metrics
        self._worker_id = worker_id or (
            f"{socket.gethostname()}-{os.getpid()}"
        )

    def run_once(self, *, max_events: int = 1) -> int:
        """Reconciles due pending evaluations, then processes and
        commits at most ``max_events`` records."""
        self._reconcile_pending()
        batch = self._consumer.poll_batch(max_events=max_events)
        for event in batch.events:
            self._process(event)
        if batch.records_consumed:
            self._consumer.commit()
        return batch.records_consumed

    def _reconcile_pending(self) -> None:
        if self._pending is None or self._evaluate is None:
            return
        for record in self._pending.due(self._clock()):
            envelope = record.event
            require_tenant(envelope.tenant_id, self._tenant_ids)
            if self._evaluation_complete is not None and self._already_evaluated(
                envelope
            ):
                # Evaluation completed durably before the crash; the
                # ledger entry is stale — close it out.
                self._pending.complete(
                    envelope.tenant_id,
                    envelope.event_id,
                    owner=self._worker_id,
                    claim_token=record.claim_token,
                    now=self._clock(),
                )
                continue
            self._evaluate_pending(envelope, record)

    def _process(self, event: InboundBankEvent) -> None:
        require_tenant(event.tenant_id, self._tenant_ids)
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
        if self._pending is not None:
            record = self._pending.enqueue(
                envelope,
                enqueued_at=self._clock(),
                policy=self._pinned_policy(envelope),
            )
            now = self._clock()
            if (record.next_attempt_at <= now
                and record.leased_by == self._worker_id
                and record.leased_until is not None
                and record.leased_until > now):
                # Fresh (or already-due) record owned by this worker.
                # A redelivery during backoff, or a record leased to
                # another worker, is re-acked untouched — the stored
                # attempt schedule is preserved regardless of transport
                # redelivery.
                self._evaluate_pending(envelope, record)
            return
        self._evaluate_event(self._evaluate, envelope, event)

    def _pinned_policy(
        self, envelope: FraudEventEnvelope
    ) -> DecisionPolicy | None:
        if self._policy_for is None:
            return None
        return self._policy_for(envelope.tenant_id)

    def _evaluate_pending(
        self,
        envelope: FraudEventEnvelope,
        record: PendingEvaluationRecord,
    ) -> None:
        assert self._evaluate is not None
        if (not record.claim_token or record.leased_until is None
            or record.leased_until <= self._clock()):
            return
        context_token = current_evaluation_lease.set(
            EvaluationLease(envelope.tenant_id, envelope.event_id, record.claim_token)
        )
        try:
            self._evaluate(envelope, record.policy)
        except LeaseLostError:
            return
        except MissingTenantPolicyError:
            self._dead_letter(
                envelope,
                None,
                RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE,
                f"no decision policy registered for tenant "
                f"{envelope.tenant_id!r}",
            )
            self._pending_complete(envelope, record)
            return
        except Exception as exc:  # noqa: BLE001 - fail closed, retry later
            self._evaluation_failed(envelope, record, exc)
            return
        finally:
            current_evaluation_lease.reset(context_token)
        self._pending_complete(envelope, record)

    def _evaluation_failed(
        self, envelope: FraudEventEnvelope, claim: PendingEvaluationRecord, exc: Exception
    ) -> None:
        assert self._pending is not None
        if claim.leased_until is None or claim.leased_until <= self._clock():
            return
        if claim.attempts + 1 >= self._max_evaluation_attempts:
            self._dead_letter(
                envelope, None, RejectionReason.EVALUATION_FAILURE,
                f"evaluation failed after {claim.attempts + 1} attempts: {type(exc).__name__}",
            )
            self._pending_complete(envelope, claim)
            return
        record = self._pending.reschedule(
            envelope.tenant_id, envelope.event_id,
            error=type(exc).__name__,
            next_attempt_at=self._clock() + self._retry_backoff,
            owner=self._worker_id, claim_token=claim.claim_token, now=self._clock(),
        )
        if record is not None and self._metrics is not None:
            self._metrics.increment(
                "gasha_worker_evaluation_retries", labels={"tenant_id": envelope.tenant_id},
            )

    def _pending_complete(
        self, envelope: FraudEventEnvelope, record: PendingEvaluationRecord
    ) -> None:
        if self._pending is not None:
            self._pending.complete(
                envelope.tenant_id,
                envelope.event_id,
                owner=self._worker_id,
                claim_token=record.claim_token,
                now=self._clock(),
            )

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
        evaluate: Callable[
            [FraudEventEnvelope, DecisionPolicy | None], object
        ],
        envelope: FraudEventEnvelope,
        event: InboundBankEvent,
    ) -> None:
        try:
            evaluate(envelope, None)
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
        event: InboundBankEvent | None,
        reason: RejectionReason,
        detail: str,
    ) -> None:
        self._dead_letters.put(
            RejectionRecord(
                reason=reason,
                detail=detail,
                tenant_id=envelope.tenant_id,
                event_id=str(envelope.event_id),
                source_system=(
                    event.source_system
                    if event is not None
                    else envelope.adapter.source_system
                ),
                schema_version=(
                    event.schema_version
                    if event is not None
                    else envelope.adapter.schema_version
                ),
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

