"""Versioned POC report consumers must not confuse undefined and measured rates."""

from __future__ import annotations

import json
from dataclasses import replace
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


# These tests cross the full installed POCReport JSON boundary rather than
# validating isolated Pydantic count classes.
_STRICT_COUNT_PATHS = [
    "signal_attribution.0.alerts_influenced",
    "signal_attribution.0.driving_alerts",
    "signal_attribution.0.true_positives_influenced",
    "signal_attribution.0.false_positives_influenced",
    "ablation.0.true_positives",
    "ablation.0.false_positives",
    "ablation.0.true_negatives",
    "ablation.0.false_negatives",
    "ablation.0.detections_lost",
    "unique_detections.0.detections",
    "multi_signal.detections",
    "multi_signal.family_combination_counts.synthetic",
    "multi_signal.named_combination_detections.synthetic",
]


def _count_payload(path: str) -> dict[str, Any]:
    payload = _with_empty_ablation() if path.startswith("ablation.") else _v2_payload()
    if path.startswith("unique_detections."):
        payload["unique_detections"] = [
            {"family": "network", "reason": "synthetic", "detections": 0, "event_ids": []}
        ]
    if "family_combination_counts." in path:
        payload["multi_signal"]["family_combination_counts"]["synthetic"] = 0
    if "named_combination_detections." in path:
        payload["multi_signal"]["named_combination_detections"]["synthetic"] = 0
    return payload


@pytest.mark.parametrize("path", _STRICT_COUNT_PATHS)
@pytest.mark.parametrize("invalid", [True, "0", 0.0, -1])
def test_v2_report_rejects_non_strict_count_payloads(
    path: str, invalid: Any
) -> None:
    payload = _count_payload(path)
    POCReport.model_validate_json(json.dumps(payload))
    _change(payload, path, invalid)
    with pytest.raises(ValidationError):
        POCReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("invalid", [True, "0", 0.0])
def test_v2_report_rejects_non_strict_signed_delta(invalid: Any) -> None:
    payload = _with_empty_ablation()
    payload["ablation"][0]["false_positive_delta"] = invalid
    with pytest.raises(ValidationError):
        POCReport.model_validate_json(json.dumps(payload))


def test_v2_report_allows_negative_signed_false_positive_delta() -> None:
    payload = _with_empty_ablation()
    payload["ablation"][0]["false_positive_delta"] = -1
    assert (
        POCReport.model_validate_json(json.dumps(payload))
        .ablation[0].false_positive_delta == -1
    )


_LATENCY_FIELDS = [
    "mean_decision_latency_seconds",
    "mean_detection_lead_time_seconds",
    "mean_processing_latency_ms",
    "median_processing_latency_ms",
    "p95_processing_latency_ms",
    "p99_processing_latency_ms",
    "max_processing_latency_ms",
]


@pytest.mark.parametrize("field", _LATENCY_FIELDS)
@pytest.mark.parametrize(
    "invalid", [-1.0, float("nan"), float("inf"), float("-inf"), "1", "NaN"]
)
def test_v2_report_rejects_invalid_latency_json(field: str, invalid: Any) -> None:
    payload = _v2_payload()
    payload["latency"][field] = invalid
    with pytest.raises(ValidationError):
        POCReport.model_validate_json(json.dumps(payload))


def _measured_latency_payload() -> dict[str, Any]:
    payload = _v2_payload()
    payload["latency"].update({
        "mean_processing_latency_ms": 2.0,
        "median_processing_latency_ms": 1.0,
        "p95_processing_latency_ms": 2.0,
        "p99_processing_latency_ms": 3.0,
        "max_processing_latency_ms": 4.0,
    })
    return payload


def test_v2_report_accepts_finite_coherent_latency_and_unknown_timing() -> None:
    payload = _measured_latency_payload()
    validated = POCReport.model_validate_json(json.dumps(payload))
    assert validated.latency.mean_decision_latency_seconds is None
    assert validated.latency.mean_detection_lead_time_seconds is None
    assert validated.latency.p95_processing_latency_ms == 2.0


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("median_processing_latency_ms", 2.5),
        ("p95_processing_latency_ms", 0.5),
        ("p99_processing_latency_ms", 1.5),
        ("max_processing_latency_ms", 2.5),
        ("mean_processing_latency_ms", 4.5),
    ],
)
def test_v2_report_rejects_incoherent_processing_latencies(
    field: str, invalid: float
) -> None:
    payload = _measured_latency_payload()
    payload["latency"][field] = invalid
    with pytest.raises(ValidationError, match="processing latency|mean processing"):
        POCReport.model_validate_json(json.dumps(payload))


def test_v2_report_rejects_nonadjacent_percentile_inversion() -> None:
    payload = _measured_latency_payload()
    payload["latency"]["p95_processing_latency_ms"] = None
    payload["latency"]["p99_processing_latency_ms"] = 0.5
    with pytest.raises(ValidationError, match="processing latency"):
        POCReport.model_validate_json(json.dumps(payload))


def test_v2_report_builder_keeps_negative_replay_lead_unknown() -> None:
    empty = _empty_replay()
    replay = HistoricalReplayReport(
        results=empty.results,
        metrics=replace(empty.metrics, mean_detection_lead_time_seconds=-3.0),
    )
    payload = build_poc_report(
        tenant_id="synthetic-tenant",
        dataset_id="synthetic-negative-replay-clock",
        report=replay,
        policies={},
    ).model_dump(mode="json")
    assert payload["latency"]["mean_detection_lead_time_seconds"] is None
    POCReport.model_validate_json(json.dumps(payload))
