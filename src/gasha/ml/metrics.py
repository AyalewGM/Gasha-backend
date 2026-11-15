"""Pure evaluation metrics for model selection and threshold choice.

All metrics consume matured-label score/label pairs only; unlabeled events
never enter any denominator, matching the replay-metric convention that an
absent label is unknown rather than negative.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

_EPSILON = 1e-9


@dataclass(frozen=True, slots=True)
class ConfusionCounts:
    """Binary confusion population at one alert threshold."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def alerted(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float:
        return self.true_positives / self.alerted if self.alerted else 0.0

    @property
    def recall(self) -> float:
        positives = self.true_positives + self.false_negatives
        return self.true_positives / positives if positives else 0.0

    @property
    def false_positive_rate(self) -> float:
        negatives = self.false_positives + self.true_negatives
        return self.false_positives / negatives if negatives else 0.0

    @property
    def f1(self) -> float:
        denominator = 2 * self.true_positives + self.false_positives + self.false_negatives
        return 2 * self.true_positives / denominator if denominator else 0.0


def confusion_at_threshold(
    scores: Sequence[float], labels: Sequence[bool], threshold: float
) -> ConfusionCounts:
    """Counts the confusion population for ``score >= threshold`` alerts."""
    if len(scores) != len(labels):
        raise ValueError("score/label length mismatch")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be within [0, 1]")
    tp = fp = tn = fn = 0
    for score, is_fraud in zip(scores, labels):
        alerted = score >= threshold
        if alerted and is_fraud:
            tp += 1
        elif alerted:
            fp += 1
        elif is_fraud:
            fn += 1
        else:
            tn += 1
    return ConfusionCounts(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
    )


def auc(scores: Sequence[float], labels: Sequence[bool]) -> float | None:
    """Rank-based (Mann-Whitney) AUC; ``None`` when a class is absent."""
    if len(scores) != len(labels):
        raise ValueError("score/label length mismatch")
    pairs = sorted(zip(scores, labels), key=lambda pair: pair[0])
    positives = sum(1 for _, y in pairs if y)
    negatives = len(pairs) - positives
    if positives == 0 or negatives == 0:
        return None
    rank_sum = 0.0
    index = 0
    while index < len(pairs):
        end = index
        while end + 1 < len(pairs) and pairs[end + 1][0] == pairs[index][0]:
            end += 1
        mean_rank = (index + 1 + end + 1) / 2.0
        rank_sum += sum(mean_rank for _, y in pairs[index : end + 1] if y)
        index = end + 1
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def threshold_for_fpr(
    scores: Sequence[float], labels: Sequence[bool], target_fpr: float
) -> tuple[float, float]:
    """Returns ``(threshold, realized_fpr)`` for the smallest threshold
    whose validation false-positive rate does not exceed ``target_fpr``.

    The realized FPR is returned alongside the threshold so a degenerate
    negative population (for example negatives tied at the maximum score)
    is surfaced honestly rather than silently violating the target.
    """
    if len(scores) != len(labels):
        raise ValueError("score/label length mismatch")
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("target FPR must be within [0, 1]")
    negatives = sorted(
        (score for score, is_fraud in zip(scores, labels) if not is_fraud),
        reverse=True,
    )
    if not negatives:
        raise ValueError("cannot choose a threshold without negative labels")
    allowed_fp = int(target_fpr * len(negatives))
    if allowed_fp >= len(negatives):
        return 0.0, 1.0
    threshold = min(1.0, negatives[allowed_fp] + _EPSILON)
    realized = sum(1 for score in negatives if score >= threshold) / len(negatives)
    return threshold, realized
