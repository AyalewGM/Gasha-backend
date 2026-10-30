"""Versioned POC report consumers must not confuse undefined and measured rates."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from gasha.poc.historical import HistoricalReplayMetrics, HistoricalReplayReport
from gasha.poc.report import (
    POC_REPORT_SCHEMA_VERSION,
    POCReport,
    RateEvidence,
    _confusion_summary,
    build_poc_report,
)


def _empty_replay() -> HistoricalReplayReport:
    metrics = HistoricalReplayMetrics(
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
    return HistoricalReplayReport(results=(), metrics=metrics)


def _v2_payload() -> dict[str, Any]:
    return build_poc_report(
        tenant_id="synthetic-tenant",
        dataset_id="synthetic-empty-cohort",
        report=_empty_replay(),
        policies={},
    ).model_dump(mode="json")


def test_v2_report_round_trip_and_schema_contract() -> None:
    payload = _v2_payload()
    assert POC_REPORT_SCHEMA_VERSION == "poc-report-2"
    assert payload["report_version"] == POC_REPORT_SCHEMA_VERSION
    assert payload["confusion"]["recall"] is None
    assert payload["confusion"]["rate_evidence"]["recall"]["denominator"] == 0
    assert payload["confusion"]["rate_evidence"]["recall"]["undefined_reason"]
    assert POCReport.model_validate_json(json.dumps(payload)).report_version == (
        POC_REPORT_SCHEMA_VERSION
    )
    schema = POCReport.model_json_schema()
    assert schema["properties"]["report_version"]["const"] == POC_REPORT_SCHEMA_VERSION
    assert "report_version" in schema["required"]


@pytest.mark.parametrize("version", ["poc-report-1", "poc-report-3", ""])
def test_report_consumer_rejects_legacy_unknown_or_blank_version(version: str) -> None:
    payload = _v2_payload()
    payload["report_version"] = version
    with pytest.raises(ValidationError, match="report_version"):
        POCReport.model_validate_json(json.dumps(payload))


def test_report_consumer_rejects_missing_version() -> None:
    payload = _v2_payload()
    del payload["report_version"]
    with pytest.raises(ValidationError, match="report_version"):
        POCReport.model_validate(payload)


@pytest.mark.parametrize(
    "missing_field",
    ["rate_evidence", "precision"],
)
def test_v2_consumer_rejects_legacy_confusion_shape(missing_field: str) -> None:
    payload = _v2_payload()
    del payload["confusion"][missing_field]
    with pytest.raises(ValidationError, match=missing_field):
        POCReport.model_validate(payload)


def test_v2_consumer_requires_explainability_population_evidence() -> None:
    payload = _v2_payload()
    del payload["explainability_coverage_evidence"]
    with pytest.raises(ValidationError, match="explainability_coverage_evidence"):
        POCReport.model_validate(payload)


@pytest.mark.parametrize("version", ["poc-report-1", "poc-report-3"])
def test_report_builder_rejects_version_override(version: str) -> None:
    with pytest.raises(ValueError, match="unsupported POC report schema version"):
        build_poc_report(
            tenant_id="synthetic-tenant",
            dataset_id="synthetic-empty-cohort",
            report=_empty_replay(),
            policies={},
            report_version=version,
        )


def _change(payload: dict[str, Any], path: str, value: Any) -> None:
    """Alter exactly one nested JSON field, including a signal-family array entry."""

    parts = path.split(".")
    current: Any = payload
    for part in parts[:-1]:
        current = current[int(part)] if part.isdecimal() else current[part]
    last = parts[-1]
    current[int(last) if last.isdecimal() else last] = value


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("confusion.rate_evidence.recall.numerator", 1),
        ("confusion.rate_evidence.recall.numerator", True),
        ("confusion.rate_evidence.recall.denominator", -1),
        ("confusion.rate_evidence.recall.value", 0.0),
        ("confusion.rate_evidence.recall.undefined_reason", None),
        ("confusion.rate_evidence.recall.undefined_reason", ""),
        ("confusion.rate_evidence.recall.undefined_reason", "wrong_reason"),
        ("confusion.rate_evidence.recall", {}),
        ("confusion.rate_evidence", {}),
        ("confusion.rate_evidence.unrecognized", {"numerator": 0, "denominator": 0, "value": None, "undefined_reason": "no_data"}),
        ("confusion.recall", 0.0),
        ("confusion.true_negatives", -1),
        ("confusion.false_positives", 1),
        ("total_events", 1),
        ("total_events", True),
        ("labeled_events", 1),
        ("unresolved_outcomes", 1),
        ("fraud_prevalence", 0.0),
        ("explainability_coverage", 0.0),
        ("explainability_coverage_evidence.denominator", 1),
        ("explainability_coverage_evidence.undefined_reason", "wrong_reason"),
        ("signal_attribution.0.share_of_detected_fraud", 0.0),
        ("signal_attribution.0.true_positives_influenced", 1),
        ("signal_attribution.0.share_of_detected_fraud_evidence.denominator", 1),
        ("signal_attribution.0.alerts_influenced", -1),
        ("unmatched_outcomes", -1),
    ],
)
def test_v2_report_rejects_cross_field_tampering(path: str, value: Any) -> None:
    payload = _v2_payload()
    _change(payload, path, value)
    with pytest.raises(ValidationError):
        POCReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("numerator", "denominator", "value", "reason"),
    [
        (1, 2, 0.99, None),
        (1, 2, None, None),
        (1, 2, 0.5, "unexpected"),
        (1, 0, None, "not_measurable"),
        (0, 0, 1.0, "not_measurable"),
        (0, 0, None, None),
        (0, 0, None, "  "),
        (0, 1, float("nan"), None),
        (0, 1, float("inf"), None),
        (3, 2, 1.5, None),
    ],
)
def test_rate_consumer_rejects_invalid_rate_arithmetic(
    numerator: int, denominator: int, value: float | None, reason: str | None
) -> None:
    with pytest.raises(ValidationError):
        RateEvidence(numerator=numerator, denominator=denominator, value=value, undefined_reason=reason)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("precision", 0.99),
        ("rate_evidence.precision.value", 0.99),
        ("rate_evidence.recall.numerator", 1),
        ("rate_evidence.false_positive_rate.denominator", 100),
    ],
)
def test_nonzero_confusion_rejects_tampering(path: str, value: Any) -> None:
    original = _confusion_summary(2, 1, 3, 1).model_dump(mode="json")
    _change(original, path, value)
    from gasha.poc.report import ConfusionSummary

    with pytest.raises(ValidationError):
        ConfusionSummary.model_validate(original)


def _with_empty_ablation() -> dict[str, Any]:
    payload = _v2_payload()
    payload["ablation"] = [{
        "configuration_name": "without_network",
        "removed_families": ["network"],
        **payload["confusion"],
        "recall_delta": None,
        "incremental_recall_contribution": None,
        "recall_delta_undefined_reason": "no_confirmed_fraud",
        "false_positive_delta": 0,
        "detections_lost": 0,
    }]
    return payload


def test_v2_accepts_valid_empty_ablation_and_rejects_fabricated_delta() -> None:
    payload = _with_empty_ablation()
    assert POCReport.model_validate(payload).ablation[0].recall_delta is None
    payload["ablation"][0]["recall_delta"] = 0.0
    with pytest.raises(ValidationError, match="ablation recall delta"):
        POCReport.model_validate(payload)


def test_v2_rejects_inconsistent_incumbent_partitions() -> None:
    payload = _v2_payload()
    empty_confusion = payload["confusion"]
    payload["incumbent_comparison"] = {
        "evaluated_cases": 0,
        "missing_incumbent_outcomes": 0,
        "both_detected": 0,
        "gasha_only_detected": 0,
        "incumbent_only_detected": 0,
        "neither_detected": 0,
        "incremental_confirmed_detection": 0,
        "gasha": empty_confusion,
        "incumbent": empty_confusion,
    }
    assert POCReport.model_validate(payload).incumbent_comparison is not None
    payload["incumbent_comparison"]["both_detected"] = 1
    with pytest.raises(ValidationError, match="incumbent comparison population"):
        POCReport.model_validate(payload)
