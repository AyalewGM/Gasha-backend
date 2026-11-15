"""Equal-budget metrics for offline evaluation of scored synthetic cohorts."""

from __future__ import annotations

from collections.abc import Sequence

from gasha.poc.historical import HistoricalTransactionEvent


def _rate(numerator: int, denominator: int, reason: str) -> dict[str, object]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
        "undefined_reason": None if denominator else reason,
    }


def measure_same_budget(
    results: Sequence[tuple[HistoricalTransactionEvent, float]], *, alert_budget: int,
) -> dict[str, object]:
    """Score a labeled cohort whose unreconciled labels have already been removed."""
    # Budget consumes all selected events, including those whose labels are unavailable.
    ordered = sorted(results, key=lambda row: (
        -row[1], row[0].transaction.occurred_at, row[0].transaction.event_id,
    ))
    alerted_ids = {event.transaction.event_id for event, _ in ordered[:alert_budget]}
    tp = fp = tn = fn = unlabeled = alerted_unlabeled = 0
    for event, _ in results:
        alerted = event.transaction.event_id in alerted_ids
        label = event.label
        if label is None:
            unlabeled += 1
            alerted_unlabeled += int(alerted)
        elif label.is_fraud:
            tp += int(alerted)
            fn += int(not alerted)
        else:
            fp += int(alerted)
            tn += int(not alerted)

    return {
        "alert_count": len(alerted_ids),
        "alerts_with_unavailable_label": alerted_unlabeled,
        "confusion_counts": {
            "true_positive": tp, "false_positive": fp, "true_negative": tn,
            "false_negative": fn, "unlabeled": unlabeled,
        },
        "precision": _rate(tp, tp + fp, "no_alerted_labeled_cases"),
        "recall": _rate(tp, tp + fn, "no_labeled_positives"),
        "f1": _rate(2 * tp, 2 * tp + fp + fn, "no_positive_labels_or_alerts"),
        "false_positive_rate": _rate(fp, fp + tn, "no_labeled_negatives"),
        "false_negative_rate": _rate(fn, tp + fn, "no_labeled_positives"),
    }
