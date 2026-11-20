from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from math import ceil, floor
from statistics import fmean
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
)
from gasha.poc.outcomes import IncumbentControlOutcome, OutcomeRecord

# Step-up recommendation is friction, not an observed analyst alert or
# confirmed fraud intervention. Missing Bank execution/settlement evidence
# cannot receive TP/alert credit during offline replay.
ALERT_ACTIONS = frozenset(
    {
        DecisionAction.REVIEW,
        DecisionAction.HOLD,
        DecisionAction.BLOCK,
    }
)

_ALERT_ACTIONS = ALERT_ACTIONS


class ConfirmedOutcomeLabel(BaseModel):
    """A confirmed fraud/non-fraud outcome attached to a historical event."""

    is_fraud: bool
    label_source: str = Field(min_length=1)
    confirmed_at: datetime | None = None


class HistoricalTransactionEvent(BaseModel):
    """Sanitized, pseudonymized historical transaction for decision replay.

    ``transaction.occurred_at`` is the preserved historical event time and
    ``intelligence`` carries the point-in-time features assembled upstream by
    the same intelligence layer that feeds the production decision path.
    ``received_at`` records the original receipt timestamp when known.
    Historical bank decision/alert timestamps are not part of this contract;
    replay execution cannot establish historical detection lead time.
    """

    transaction: CanonicalTransaction
    intelligence: IntelligenceSnapshot
    evidence_reason_codes: tuple[str, ...] = ()
    signal_policy_versions: tuple[str, ...] = ()
    label: ConfirmedOutcomeLabel | None = None
    incumbent_outcome: IncumbentControlOutcome | None = None
    received_at: datetime | None = None

    @model_validator(mode="after")
    def validate_recorded_timestamps(self) -> HistoricalTransactionEvent:
        return self._check_recorded_timestamps()

    def _check_recorded_timestamps(self) -> HistoricalTransactionEvent:
        """Reject impossible recorded clock order without asserting source trust.

        Partial historical records may omit receipt and label times. Supplied
        times must be timezone-aware and cannot precede the transaction event.
        This does not establish point-in-time feature or label provenance.
        """
        occurred_at = self.transaction.occurred_at
        received_at = self.received_at
        confirmed_at = self.label.confirmed_at if self.label else None
        # The required event clock must be checked even when optional clocks
        # are absent; otherwise naive event times enter chronological sorting.
        for timestamp in (occurred_at, received_at, confirmed_at):
            if timestamp is not None and timestamp.utcoffset() is None:
                raise ValueError(
                    "recorded historical timestamps must be timezone-aware"
                )
        if received_at is not None and received_at < occurred_at:
            raise ValueError("historical receipt precedes transaction event")
        if confirmed_at is not None and confirmed_at < occurred_at:
            raise ValueError(
                "historical label confirmation precedes transaction event"
            )
        return self


class ReplayClassification(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    UNLABELED = "unlabeled"


class ReplayDecisionSource(StrEnum):
    """Offline replay source, not a Bank evidence attestation."""

    GASHA_DECISION = "gasha_decision"
    INCUMBENT_SCORE_SIMULATION = "incumbent_score_simulation"
    OTHER_OFFLINE_BACKEND = "other_offline_backend"


class MissingTenantPolicyError(ValueError):
    """Raised when a replay event has no policy for its tenant."""


class DecisionBackend(Protocol):
    """Anything with the ``DecisionService.decide`` contract can drive replay."""

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> FraudDecision: ...


@dataclass(frozen=True)
class ReplayedEventResult:
    """Full decision capture for one replayed historical event."""

    event: HistoricalTransactionEvent
    decision: FraudDecision
    classification: ReplayClassification
    decision_latency: timedelta | None
    detection_lead_time: timedelta | None
    evaluation_started_at: datetime | None = None
    evaluation_ended_at: datetime | None = None
    processing_latency: timedelta | None = None
    reconciled_outcome: OutcomeRecord | None = None
    decision_source: ReplayDecisionSource = ReplayDecisionSource.GASHA_DECISION


@dataclass(frozen=True)
class HistoricalReplayMetrics:
    cases: int
    labeled_cases: int
    unlabeled_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    explained_alerts: int
    mean_decision_latency_seconds: float | None
    max_decision_latency_seconds: float | None
    mean_detection_lead_time_seconds: float | None
    mean_processing_latency_ms: float | None = None
    median_processing_latency_ms: float | None = None
    p95_processing_latency_ms: float | None = None
    p99_processing_latency_ms: float | None = None
    max_processing_latency_ms: float | None = None

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def explainability_coverage(self) -> float:
        alerts = self.true_positives + self.false_positives
        return self.explained_alerts / alerts if alerts else 1.0


@dataclass(frozen=True)
class HistoricalReplayReport:
    results: tuple[ReplayedEventResult, ...]
    metrics: HistoricalReplayMetrics
    unmatched_outcomes: tuple[OutcomeRecord, ...] = ()


def replay_historical(
    events: Sequence[HistoricalTransactionEvent],
    policies: Mapping[str, DecisionPolicy],
    *,
    clock: Callable[[], datetime] | None = None,
    service_factory: Callable[[DecisionPolicy], DecisionBackend] | None = None,
) -> HistoricalReplayReport:
    """Replays historical events through the production decision path.

    Events are replayed chronologically by ``occurred_at`` and each is decided
    by a ``DecisionService`` configured with the policy registered for the
    event's own tenant. An event whose tenant has no policy raises
    ``MissingTenantPolicyError``; there is no cross-tenant fallback. When
    ``service_factory`` is supplied it selects the per-tenant backend
    (for example a model-backed scorer for offline candidate evaluation);
    the default remains the deterministic ``DecisionService``.
    """

    services: dict[str, DecisionBackend] = {}
    results: list[ReplayedEventResult] = []
    now = clock or (lambda: datetime.now(UTC))

    # Pydantic models may have been modified after construction or copied with
    # unchecked updates. Validate the full batch before sorting or deciding,
    # so mixed naive/aware clocks fail closed without partial replay evidence.
    for event in events:
        event._check_recorded_timestamps()

    for event in sorted(events, key=lambda item: item.transaction.occurred_at):
        tenant_id = event.transaction.tenant_id
        policy = policies.get(tenant_id)
        if policy is None:
            raise MissingTenantPolicyError(
                f"no decision policy registered for tenant {tenant_id!r}"
            )
        service = services.get(tenant_id)
        if service is None:
            service = services[tenant_id] = (
                service_factory(policy)
                if service_factory is not None
                else DecisionService(policy)
            )

        evaluation_started_at = now()
        decision = service.decide(
            event.transaction,
            event.intelligence,
            event.evidence_reason_codes,
        )
        evaluation_ended_at = now()
        results.append(
            _result(
                event,
                decision,
                evaluation_started_at=evaluation_started_at,
                evaluation_ended_at=evaluation_ended_at,
                decision_source=(
                    ReplayDecisionSource.GASHA_DECISION
                    if type(service) is DecisionService
                    else ReplayDecisionSource.INCUMBENT_SCORE_SIMULATION
                    if getattr(service, "replay_decision_source", None)
                    == ReplayDecisionSource.INCUMBENT_SCORE_SIMULATION
                    else ReplayDecisionSource.OTHER_OFFLINE_BACKEND
                ),
            )
        )

    return HistoricalReplayReport(
        results=tuple(results),
        metrics=_metrics(results),
    )


def pseudonymize_transaction(
    transaction: CanonicalTransaction, *, salt: str
) -> CanonicalTransaction:
    """Returns a copy with stable keyed pseudonyms for identifier fields.

    The same salt and identifier always produce the same pseudonym, preserving
    sender/beneficiary linkage inside a sanitized dataset while remaining
    unlinkable across salts (for example, across tenants). ``tenant_id``,
    timestamps and amounts are preserved so tenant isolation and event-time
    semantics stay intact.
    """

    def pseudonym(value: str) -> str:
        return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:24]

    updates: dict[str, object] = {
        "sender_customer_id": pseudonym(transaction.sender_customer_id),
        "sender_account_id": pseudonym(transaction.sender_account_id),
        "beneficiary_id": pseudonym(transaction.beneficiary_id),
        "correlation_id": pseudonym(transaction.correlation_id),
    }
    if transaction.device_id is not None:
        updates["device_id"] = pseudonym(transaction.device_id)
    if transaction.destination_institution_id is not None:
        updates["destination_institution_id"] = pseudonym(
            transaction.destination_institution_id
        )
    return transaction.model_copy(update=updates)


def _classify(alerted: bool, is_fraud: bool | None) -> ReplayClassification:
    if is_fraud is None:
        return ReplayClassification.UNLABELED
    if alerted and is_fraud:
        return ReplayClassification.TRUE_POSITIVE
    if alerted:
        return ReplayClassification.FALSE_POSITIVE
    if is_fraud:
        return ReplayClassification.FALSE_NEGATIVE
    return ReplayClassification.TRUE_NEGATIVE


def _result(
    event: HistoricalTransactionEvent,
    decision: FraudDecision,
    *,
    evaluation_started_at: datetime | None = None,
    evaluation_ended_at: datetime | None = None,
    decision_source: ReplayDecisionSource = ReplayDecisionSource.GASHA_DECISION,
) -> ReplayedEventResult:
    alerted = decision.action in _ALERT_ACTIONS
    label = event.label
    is_fraud = label.is_fraud if label is not None else None

    # decided_at is a *replay execution* timestamp, not a historical alert
    # timestamp. A confirmed label does not establish when fraud was detected.
    # Never fabricate lead time using the replay wall clock.

    processing_latency = None
    if evaluation_started_at is not None and evaluation_ended_at is not None:
        processing_latency = evaluation_ended_at - evaluation_started_at

    return ReplayedEventResult(
        event=event,
        decision=decision,
        classification=_classify(alerted, is_fraud),
        # Historical decision latency is unknown without the original bank
        # decision timestamp. Processing latency is measured separately.
        decision_latency=None,
        detection_lead_time=None,
        evaluation_started_at=evaluation_started_at,
        evaluation_ended_at=evaluation_ended_at,
        processing_latency=processing_latency,
        decision_source=decision_source,
    )


def reconcile_outcomes(
    report: HistoricalReplayReport, outcomes: Sequence[OutcomeRecord]
) -> HistoricalReplayReport:
    """Attaches post-decision outcome records to replayed results.

    Outcomes arrive after the original decision (T0 decision, T1 outcome) and
    never mutate it. Matching is keyed strictly by ``(tenant_id, event_id)`` so
    an outcome from one tenant can never attach to another tenant's decision.
    Unmatched outcomes are surfaced on the report for auditability.
    """

    by_key: dict[tuple[str, UUID], OutcomeRecord] = {}
    for outcome in outcomes:
        key = (outcome.tenant_id, outcome.event_id)
        existing = by_key.get(key)
        if existing is None or (
            outcome.confirmed_at is not None
            and (
                existing.confirmed_at is None
                or outcome.confirmed_at > existing.confirmed_at
            )
        ):
            by_key[key] = outcome

    matched: set[tuple[str, UUID]] = set()
    reconciled: list[ReplayedEventResult] = []
    for result in report.results:
        key = (result.decision.tenant_id, result.decision.event_id)
        matched_outcome = by_key.get(key)
        if matched_outcome is None:
            reconciled.append(result)
            continue
        matched.add(key)
        alerted = result.decision.action in _ALERT_ACTIONS
        # Outcome confirmation updates classification, not the historical
        # detection clock. Replayed decisions have no observed alert timestamp.
        reconciled.append(
            replace(
                result,
                classification=_classify(alerted, matched_outcome.is_fraud),
                reconciled_outcome=matched_outcome,
            )
        )

    unmatched = tuple(
        outcome
        for key, outcome in by_key.items()
        if key not in matched
    )
    return HistoricalReplayReport(
        results=tuple(reconciled),
        metrics=_metrics(reconciled),
        unmatched_outcomes=unmatched,
    )


def _percentile(values: Sequence[float], percentile: float) -> float:
    """Linear-interpolated percentile over a non-empty sequence."""

    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = floor(rank)
    upper = ceil(rank)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def _metrics(results: list[ReplayedEventResult]) -> HistoricalReplayMetrics:
    counts = {
        classification: 0 for classification in ReplayClassification
    }
    explained = 0
    latencies: list[float] = []
    lead_times: list[float] = []
    processing_latencies: list[float] = []
    for item in results:
        counts[item.classification] += 1
        if (
            item.decision.action in _ALERT_ACTIONS
            and item.decision.reason_codes
            and item.decision.reason_codes != ["NO_HIGH_RISK_SIGNAL"]
        ):
            explained += 1
        if item.decision_latency is not None:
            latencies.append(item.decision_latency.total_seconds())
        if item.detection_lead_time is not None:
            lead_times.append(item.detection_lead_time.total_seconds())
        if item.processing_latency is not None:
            processing_latencies.append(
                item.processing_latency.total_seconds() * 1000.0
            )

    return HistoricalReplayMetrics(
        cases=len(results),
        labeled_cases=counts[ReplayClassification.TRUE_POSITIVE]
        + counts[ReplayClassification.FALSE_POSITIVE]
        + counts[ReplayClassification.TRUE_NEGATIVE]
        + counts[ReplayClassification.FALSE_NEGATIVE],
        unlabeled_cases=counts[ReplayClassification.UNLABELED],
        true_positives=counts[ReplayClassification.TRUE_POSITIVE],
        false_positives=counts[ReplayClassification.FALSE_POSITIVE],
        true_negatives=counts[ReplayClassification.TRUE_NEGATIVE],
        false_negatives=counts[ReplayClassification.FALSE_NEGATIVE],
        explained_alerts=explained,
        mean_decision_latency_seconds=fmean(latencies) if latencies else None,
        max_decision_latency_seconds=max(latencies) if latencies else None,
        mean_detection_lead_time_seconds=fmean(lead_times) if lead_times else None,
        mean_processing_latency_ms=(
            fmean(processing_latencies) if processing_latencies else None
        ),
        median_processing_latency_ms=(
            _percentile(processing_latencies, 0.50)
            if processing_latencies
            else None
        ),
        p95_processing_latency_ms=(
            _percentile(processing_latencies, 0.95)
            if processing_latencies
            else None
        ),
        p99_processing_latency_ms=(
            _percentile(processing_latencies, 0.99)
            if processing_latencies
            else None
        ),
        max_processing_latency_ms=(
            max(processing_latencies) if processing_latencies else None
        ),
    )
