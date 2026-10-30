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
