from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

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
