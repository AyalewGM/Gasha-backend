"""Machine-readable POC rates must not turn absent populations into zero scores."""

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.ablation import AblationComparison
from gasha.poc.historical import (
    HistoricalReplayMetrics,
    HistoricalReplayReport,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.report import (
    _ablation_summary,
    _confusion_summary,
    _rate_evidence,
    build_poc_report,
)


def empty_metrics() -> HistoricalReplayMetrics:
    return HistoricalReplayMetrics(
        cases=0,
        labeled_cases=0,
        unlabeled_cases=0,
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        explained_alerts=0,
        mean_decision_latency_seconds=None,
        max_decision_latency_seconds=None,
        mean_detection_lead_time_seconds=None,
    )


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ((0, 0, 0, 0), (None, None, None, None, None)),
        ((0, 0, 3, 0), (None, None, 0.0, None, None)),
        ((0, 1, 0, 0), (None, 0.0, 1.0, 0.0, None)),
        ((2, 1, 3, 1), (2 / 3, 2 / 3, 1 / 4, 2 / 3, 1 / 3)),
    ],
)
def test_confusion_rates_use_actual_denominators(
    counts: tuple[int, int, int, int],
    expected: tuple[float | None, float | None, float | None, float | None, float | None],
) -> None:
    summary = _confusion_summary(*counts)
    actual = (
        summary.recall,
        summary.precision,
        summary.false_positive_rate,
        summary.f1,
        summary.false_negative_rate,
    )
    assert actual == pytest.approx(expected)
    tp, fp, tn, fn = counts
    evidence = summary.rate_evidence
    assert (evidence["recall"].numerator, evidence["recall"].denominator) == (
        tp,
        tp + fn,
    )
    assert (evidence["precision"].numerator, evidence["precision"].denominator) == (
        tp,
        tp + fp,
    )
    assert (evidence["f1"].numerator, evidence["f1"].denominator) == (
        2 * tp,
        2 * tp + fp + fn,
    )
    assert (
        evidence["false_positive_rate"].numerator,
        evidence["false_positive_rate"].denominator,
    ) == (fp, fp + tn)
    assert (
        evidence["false_negative_rate"].numerator,
        evidence["false_negative_rate"].denominator,
    ) == (fn, tp + fn)
    for rate in evidence.values():
        assert (rate.value is None) == (rate.denominator == 0)
        assert (rate.undefined_reason is not None) == (rate.denominator == 0)


@pytest.mark.parametrize("numerator,denominator", [(-1, 1), (2, 1), (0, -1)])
def test_rate_evidence_rejects_inconsistent_populations(
    numerator: int, denominator: int
) -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        _rate_evidence(numerator, denominator, "not_applicable")


def test_empty_poc_report_serializes_nulls_and_reasons() -> None:
    replay = HistoricalReplayReport(results=(), metrics=empty_metrics())
    poc = build_poc_report(
        tenant_id="tenant-synthetic",
        dataset_id="empty-synthetic-cohort",
        report=replay,
        policies={},
    )
    payload = poc.model_dump(mode="json")
    assert payload["confusion"]["recall"] is None
    assert payload["confusion"]["precision"] is None
    assert payload["confusion"]["f1"] is None
    assert payload["confusion"]["false_positive_rate"] is None
    assert payload["confusion"]["false_negative_rate"] is None
    assert payload["confusion"]["rate_evidence"]["precision"] == {
        "numerator": 0,
        "denominator": 0,
        "value": None,
        "undefined_reason": "no_labeled_alerts",
    }
    assert payload["explainability_coverage"] is None
    assert payload["explainability_coverage_evidence"]["denominator"] == 0
    assert payload["explainability_coverage_evidence"]["undefined_reason"] == (
        "no_alerts"
    )
    assert all(
        family["share_of_detected_fraud"] is None
        and family["share_of_detected_fraud_evidence"]["undefined_reason"]
        == "no_detected_fraud"
        for family in payload["signal_attribution"]
    )
    assert any("precision undefined" in caveat for caveat in payload["limitations"])


def test_ablation_reports_undefined_recall_delta_not_zero() -> None:
    comparison = AblationComparison(
        configuration_name="without_device_session",
        removed_families=(),
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        recall=0.0,
        precision=0.0,
        false_positive_rate=0.0,
        recall_delta=0.0,
        incremental_recall_contribution=0.0,
        false_positive_delta=0,
        detections_lost=0,
    )
    output = _ablation_summary(comparison, empty_metrics()).model_dump(
        mode="json"
    )
    assert output["recall"] is None
    assert output["recall_delta"] is None
    assert output["incremental_recall_contribution"] is None
    assert output["recall_delta_undefined_reason"] == "no_confirmed_fraud"
    assert output["rate_evidence"]["f1"]["undefined_reason"] == (
        "no_positive_labels_or_alerts"
    )


def test_unlabeled_alert_counts_in_explainability_denominator() -> None:
    transaction = CanonicalTransaction(
        tenant_id="tenant-synthetic",
        event_id=uuid4(),
        occurred_at=datetime(2026, 2, 10, tzinfo=UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("2500.00"),
        currency="ETB",
        sender_customer_id="customer-synthetic",
        sender_account_id="account-synthetic",
        beneficiary_id="beneficiary-synthetic",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-synthetic",
        correlation_id="corr-synthetic",
    )
    event = HistoricalTransactionEvent(
        transaction=transaction,
        intelligence=IntelligenceSnapshot(network_risk=0.96),
    )
    policies = {
        "tenant-synthetic": DecisionPolicy(
            configuration_version="config-synthetic",
            policy_version="policy-synthetic",
            rule_version="rules-synthetic",
        )
    }
    replay = replay_historical((event,), policies)
    assert replay.metrics.labeled_cases == 0
    assert replay.metrics.explained_alerts == 1

    poc = build_poc_report(
        tenant_id="tenant-synthetic",
        dataset_id="unlabeled-alert-synthetic",
        report=replay,
        policies=policies,
    )
    assert poc.confusion.precision is None
    assert poc.explainability_coverage == 1.0
    assert poc.explainability_coverage_evidence.numerator == 1
    assert poc.explainability_coverage_evidence.denominator == 1
    assert poc.explainability_coverage_evidence.undefined_reason is None
