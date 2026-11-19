from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from math import isfinite
from uuid import UUID

from gasha.decision.service import action_for_score
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ALERT_ACTIONS,
    ReplayClassification,
    ReplayedEventResult,
)


@dataclass(frozen=True)
class ConfusionCounts:
    """TP/FP/TN/FN counts with derived rates for one decision source."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

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


@dataclass(frozen=True)
class IncumbentComparison:
    """Measured comparison of Gasha vs a bank's existing controls.

    ``incremental_confirmed_detection`` counts confirmed-fraud cases that
    Gasha detected and the normalized incumbent outcome did not. It reports
    measured incremental signal on the evaluated dataset only — it is not a
    superiority claim and requires confirmed outcome data to be meaningful.
    """

    evaluated_cases: int
    missing_incumbent_outcomes: int
    gasha: ConfusionCounts
    incumbent: ConfusionCounts
    both_detected: int
    gasha_only_detected: int
    incumbent_only_detected: int
    neither_detected: int
    incremental_confirmed_detection: int


def compare_incumbent(
    results: Sequence[ReplayedEventResult],
) -> IncumbentComparison:
    """Compares replayed Gasha decisions with supplied incumbent outcomes.

    Use each replay result's effective classification, including a later
    reconciled outcome, instead of the original event label. This keeps Gasha
    and incumbent on the same currently labeled cohort. Unlabeled results are
    excluded; labeled results with no incumbent outcome are counted as
    missing rather than silently treated as non-alerts. Label maturity and
    provenance are separate bank-data acceptance requirements.
    """

    gasha_tp = gasha_fp = gasha_tn = gasha_fn = 0
    incumbent_tp = incumbent_fp = incumbent_tn = incumbent_fn = 0
    both = gasha_only = incumbent_only = neither = 0
    incremental = 0
    missing = 0

    for result in results:
        classification = result.classification
        if classification == ReplayClassification.UNLABELED:
            continue
        incumbent = result.event.incumbent_outcome
        if incumbent is None:
            missing += 1
            continue

        gasha_alerted = result.decision.action in ALERT_ACTIONS
        incumbent_alerted = incumbent.alerted
        is_fraud = classification in (
            ReplayClassification.TRUE_POSITIVE,
            ReplayClassification.FALSE_NEGATIVE,
        )

        if gasha_alerted:
            if is_fraud:
                gasha_tp += 1
            else:
                gasha_fp += 1
        elif is_fraud:
            gasha_fn += 1
        else:
            gasha_tn += 1

        if incumbent_alerted:
            if is_fraud:
                incumbent_tp += 1
            else:
                incumbent_fp += 1
        elif is_fraud:
            incumbent_fn += 1
        else:
            incumbent_tn += 1

        if gasha_alerted and incumbent_alerted:
            both += 1
        elif gasha_alerted:
            gasha_only += 1
            if is_fraud:
                incremental += 1
        elif incumbent_alerted:
            incumbent_only += 1
        else:
            neither += 1

    return IncumbentComparison(
        evaluated_cases=gasha_tp + gasha_fp + gasha_tn + gasha_fn,
        missing_incumbent_outcomes=missing,
        gasha=ConfusionCounts(
            true_positives=gasha_tp,
            false_positives=gasha_fp,
            true_negatives=gasha_tn,
            false_negatives=gasha_fn,
        ),
        incumbent=ConfusionCounts(
            true_positives=incumbent_tp,
            false_positives=incumbent_fp,
            true_negatives=incumbent_tn,
            false_negatives=incumbent_fn,
        ),
        both_detected=both,
        gasha_only_detected=gasha_only,
        incumbent_only_detected=incumbent_only,
        neither_detected=neither,
        incremental_confirmed_detection=incremental,
    )


class IncumbentScoreUnavailable(ValueError):
    """An event has no recorded incumbent score; replay must not fabricate one."""


class IncumbentScoreBackend:
    """Replay backend that reproduces an external system's own decisions.

    ``scores`` maps ``event_id`` to the incumbent system's normalized risk
    score in ``[0, 1]`` (for example a NetGuardians export prepared by
    :func:`build_incumbent_scores`). Decisions apply the supplied policy's
    thresholds to the incumbent score — the comparison measures the
    incumbent's own scoring at a chosen operating point, not a Gasha signal.
    An event with no recorded score fails closed.
    """

    def __init__(
        self, policy: DecisionPolicy, scores: Mapping[UUID, float]
    ) -> None:
        self._policy = policy
        self._scores = scores

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> FraudDecision:
        try:
            score = self._scores[transaction.event_id]
        except KeyError:
            raise IncumbentScoreUnavailable(
                f"no incumbent score recorded for event {transaction.event_id}"
            ) from None

        action = action_for_score(self._policy, score)

        reasons = list(evidence_reason_codes)
        reasons.append(
            "INCUMBENT_HIGH_SCORE"
            if score >= self._policy.review_threshold
            else "INCUMBENT_BELOW_REVIEW"
        )
        return FraudDecision(
            tenant_id=transaction.tenant_id,
            event_id=transaction.event_id,
            action=action,
            risk_score=score,
            reason_codes=reasons,
            configuration_version=self._policy.configuration_version,
            policy_version=self._policy.policy_version,
            rule_version=self._policy.rule_version,
            model_version=self._policy.model_version,
            decided_at=datetime.now(UTC),
            correlation_id=transaction.correlation_id,
        )


def build_incumbent_scores(
    records: Sequence[Mapping[str, object]],
    *,
    event_id_key: str = "event_id",
    score_key: str = "risk_score",
    score_max: float = 1.0,
) -> dict[UUID, float]:
    """Normalizes an external score export into an ``event_id -> [0,1]`` map.

    Provider-neutral: any export that can be shaped into records carrying an
    event identifier and a numeric score qualifies. ``score_max`` scales
    vendor-native ranges (for example 1000) into the normalized domain.
    Malformed rows, non-finite or out-of-range scores, and duplicate event
    identifiers are all rejected — an incumbent comparison built on partial
    or ambiguous scores would overstate the challenger.
    """
    if not isinstance(score_max, float) or not isfinite(score_max) or score_max <= 0:
        raise IncumbentScoreUnavailable("score_max must be a positive finite float")

    scores: dict[UUID, float] = {}
    for index, record in enumerate(records):
        if event_id_key not in record or score_key not in record:
            raise IncumbentScoreUnavailable(
                f"incumbent score record {index} missing required keys"
            )
        raw_id = record[event_id_key]
        try:
            event_id = raw_id if isinstance(raw_id, UUID) else UUID(str(raw_id))
        except (ValueError, AttributeError, TypeError):
            raise IncumbentScoreUnavailable(
                f"incumbent score record {index} has a malformed event id"
            ) from None
        if event_id in scores:
            raise IncumbentScoreUnavailable(
                f"duplicate incumbent score for event {event_id}"
            )
        raw_score = record[score_key]
        if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
            raise IncumbentScoreUnavailable(
                f"incumbent score record {index} has a non-numeric score"
            )
        normalized = float(raw_score) / score_max
        if not isfinite(normalized) or not 0.0 <= normalized <= 1.0:
            raise IncumbentScoreUnavailable(
                f"incumbent score record {index} is outside [0, {score_max}]"
            )
        scores[event_id] = normalized
    return scores
