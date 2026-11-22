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
    """Measure one tenant's cohort with exactly K selected rows, labels or not.

    A transaction UUID is only unique *within* a tenant. Accepting a mixed
    cohort, duplicate composite identity or an invalid K could silently
    distort fraud denominators or consume another tenant's alert budget.
    """
    if type(alert_budget) is not int or not 0 <= alert_budget <= len(results):
        raise ValueError("alert budget must be an integer from 0 to cohort size")
    tenants = {event.transaction.tenant_id for event, _ in results}
    if len(tenants) > 1:
        raise ValueError("mixed-tenant alert-budget cohort is not permitted")
    identities = [
        (event.transaction.tenant_id, event.transaction.event_id)
        for event, _ in results
    ]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate tenant/event identity in alert-budget cohort")

    # Each selected event consumes one slot even if its label is unavailable.
    # The tenant is part of both the stable tie-break and the membership key.
    ordered = sorted(results, key=lambda row: (
        -row[1], row[0].transaction.tenant_id,
        row[0].transaction.occurred_at, row[0].transaction.event_id,
    ))
    alerted_ids = {
        (event.transaction.tenant_id, event.transaction.event_id)
        for event, _ in ordered[:alert_budget]
    }
    tp = fp = tn = fn = unlabeled = alerted_unlabeled = 0
    for event, _ in results:
        alerted = (event.transaction.tenant_id, event.transaction.event_id) in alerted_ids
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
        "tenant_id": next(iter(tenants), None),
        "cohort_size": len(results),
        "alert_budget": alert_budget,
        "alert_count": len(alerted_ids),
        "selected_row_count": len(alerted_ids),
        "evaluated_labeled_rows": tp + fp + tn + fn,
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
