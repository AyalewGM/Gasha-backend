from __future__ import annotations

from typing import Any, cast

import pytest

from gasha.poc.synthetic_rules_comparison import compare_synthetic_rules


def test_same_budget_rules_comparison_is_reproducible_and_keeps_unlabeled_alerts() -> None:
    report = compare_synthetic_rules()
    assert report == compare_synthetic_rules(alert_budget=4)
    assert report["cohort_size"] == 8
    assert report["dataset_digest"] != report["comparison_digest"]
    assert report["comparison_digest"] != compare_synthetic_rules(alert_budget=3)["comparison_digest"]
    assert report["netguardians_outputs_compared"] is False
    assert report["enforcement_activated"] is False
    variants = cast(dict[str, Any], report["variants"])
    baseline, candidate = variants["transaction_risk_only"], variants["full_signal_fusion"]
    assert baseline["maturity"] == candidate["maturity"] == {
        "matured_positive": 3, "matured_negative": 3, "excluded_future_labels": 1,
        "excluded_unconfirmed_labels": 0, "absent_labels": 1,
    }
    assert baseline["evaluation_digest"] != candidate["evaluation_digest"]
    assert baseline["alert_count"] == candidate["alert_count"] == 4
    assert baseline["alerts_with_unavailable_label"] == candidate["alerts_with_unavailable_label"] == 1
    assert baseline["confusion_counts"] == {
        "true_positive": 1, "false_positive": 2, "true_negative": 1, "false_negative": 2,
        "unlabeled": 2,
    }
    assert candidate["confusion_counts"] == {
        "true_positive": 2, "false_positive": 1, "true_negative": 2, "false_negative": 1,
        "unlabeled": 2,
    }
    assert candidate["f1"]["value"] == pytest.approx(2 / 3)


def test_zero_budget_leaves_precision_undefined() -> None:
    report = compare_synthetic_rules(alert_budget=0)
    for variant in cast(dict[str, Any], report["variants"]).values():
        assert variant["alert_count"] == 0
        assert variant["precision"] == {
            "numerator": 0, "denominator": 0, "value": None,
            "undefined_reason": "no_alerted_labeled_cases",
        }
        assert variant["false_negative_rate"]["value"] == 1.0


@pytest.mark.parametrize("budget", [-1, 9, True, 1.0])
def test_invalid_alert_budget_is_rejected(budget: int) -> None:
    with pytest.raises(ValueError, match="alert budget"):
        compare_synthetic_rules(alert_budget=budget)
