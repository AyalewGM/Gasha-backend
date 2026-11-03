"""Aggregate-only eight-scenario data coverage regression matrix."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from json import dumps
from uuid import UUID

import pytest

from gasha.poc.scenario_coverage_batch import (
    REPORT_VERSION,
    ScenarioBatchScope,
    inspect_scenario_coverage_batch,
)
from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
    FieldEvidence,
    FieldState,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
)

AT = datetime(2026, 11, 3, 12, tzinfo=UTC)
DATASET = "sha256:" + "a" * 64
EVIDENCE = "sha256:" + "b" * 64


def scope() -> ScenarioBatchScope:
    return ScenarioBatchScope(
        installation_ref="synthetic-install", tenant_ref="synthetic-tenant",
        dataset_digest=DATASET, source_schema_version="v1", mapping_version="v1",
        configuration_version="v1", window_start=AT, window_end=AT,
        report_as_of=AT,
    )


def observation(
    scenario: ScenarioId, *, event_number: int = 1, omit: str | None = None,
) -> ScenarioObservation:
    fields = tuple(
        FieldEvidence(
            name=name, state=FieldState.OBSERVED, source_ref="synthetic-source",
            source_version="v1", evidence_digest=EVIDENCE,
            observed_at=AT, available_at=AT,
        )
        for name in SCENARIO_FIELDS[scenario].required if name != omit
    )
    return ScenarioObservation(
        scenario_id=scenario, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DATASET,
        event_id=UUID(int=event_number), source_system="synthetic-source",
        source_schema_version="v1", mapping_version="v1",
        configuration_version="v1", occurred_at=AT, received_at=AT,
        decision_cutoff=AT, fields=fields,
    )


def report(*rows: ScenarioObservation) -> dict[str, object]:
    return inspect_scenario_coverage_batch(scope(), tuple(rows)).to_dict()


def test_all_eight_scenarios_are_separate_and_non_authoritative() -> None:
    result = report(*(observation(s) for s in ScenarioId))
    assert result["report_version"] == REPORT_VERSION
    assert result["input_rows"] == 8
    assert result["unique_scenario_events"] == 8
    summaries = result["scenarios"]
    assert isinstance(summaries, list)
    assert [item["scenario_id"] for item in summaries] == [s.value for s in ScenarioId]
    assert all(item["required_coverage"]["value"] == 1.0 for item in summaries)
    assert all(item["bank_evaluable"] is False for item in summaries)
    assert result["downstream_evaluation"]["precision"] is None
    assert result["downstream_evaluation"]["confusion_counts"] is None
    for flag in (
        "bank_data_verified", "historical_replay_authorized",
        "detection_executed", "readiness_authorized", "enforcement_activated",
    ):
        assert result[flag] is False


def test_empty_and_partial_coverage_have_real_denominators() -> None:
    empty = report()
    for item in empty["scenarios"]:
        assert item["status"] == "no_observations"
        assert item["required_coverage"] == {
            "numerator": 0, "denominator": 0, "value": None,
            "undefined_reason": "no_scenario_events",
        }
    scenario = ScenarioId.MM_02
    missing = SCENARIO_FIELDS[scenario].required[0]
    partial = report(
        observation(scenario, event_number=1, omit=missing),
        observation(scenario, event_number=2),
    )
    section = next(i for i in partial["scenarios"] if i["scenario_id"] == scenario.value)
    assert section["input_events"] == 2
    assert section["complete_required_events"] == 1
    assert section["blocked_required_events"] == 1
    assert section["required_coverage"]["value"] == 0.5
    assert section["missing_required_counts"][missing] == 1
    assert section["unavailable_optional_counts"]["sender_baseline"] == 2
    assert section["status"] == "partial_synthetic_coverage"


@pytest.mark.parametrize("scenario", list(ScenarioId))
def test_no_observed_fields_are_not_inferred_as_zero_risk(scenario: ScenarioId) -> None:
    item = observation(scenario)
    absent = replace(item, fields=())
    result = report(absent)
    section = next(i for i in result["scenarios"] if i["scenario_id"] == scenario.value)
    assert section["status"] == "blocked_by_data"
    assert section["complete_required_events"] == 0
    assert section["required_coverage"]["value"] == 0.0
    assert section["bank_evaluable"] is False


def test_identical_retry_is_counted_once_and_order_independent() -> None:
    a = observation(ScenarioId.MM_02)
    b = observation(ScenarioId.ATO_02)
    one = report(a, b)
    same = report(b, a, a)
    assert same["input_rows"] == 3
    assert same["duplicate_rows"] == 1
    assert same["unique_scenario_events"] == 2
    assert same["batch_digest"] == one["batch_digest"]
    assert same["scenarios"] == one["scenarios"]
    offset = timezone(timedelta(hours=-5))
    equivalent = replace(a, occurred_at=AT.astimezone(offset))
    assert report(b, equivalent)["batch_digest"] == one["batch_digest"]


def test_same_scenario_event_with_conflicting_evidence_fails_closed() -> None:
    original = observation(ScenarioId.MM_02)
    conflict = replace(original, source_system="other-source")
    with pytest.raises(ScenarioContractError, match="conflicting"):
        report(original, conflict)


@pytest.mark.parametrize("field,value", [
    ("installation_ref", "other-install"),
    ("tenant_ref", "other-tenant"),
    ("dataset_digest", "sha256:" + "c" * 64),
    ("source_schema_version", "v2"),
    ("mapping_version", "v2"),
    ("configuration_version", "v2"),
])
def test_cross_scope_and_version_substitution_rejected(field: str, value: str) -> None:
    row = replace(observation(ScenarioId.APP_01), **{field: value})
    with pytest.raises(ScenarioContractError):
        report(row)


def test_time_window_and_snapshot_cutoff_are_bounded() -> None:
    row = observation(ScenarioId.APP_05)
    later = AT + timedelta(seconds=1)
    with pytest.raises(ScenarioContractError, match="time boundary"):
        report(replace(row, occurred_at=later, received_at=later, decision_cutoff=later))
    with pytest.raises(ScenarioContractError, match="time boundary"):
        report(replace(row, decision_cutoff=later))
    assert report(row)["unique_scenario_events"] == 1


def test_mutations_and_deleted_attributes_fail_closed() -> None:
    original = observation(ScenarioId.MM_01)
    object.__setattr__(original, "fields", list(original.fields))
    with pytest.raises(ScenarioContractError):
        report(original)
    late = observation(ScenarioId.MM_02)
    object.__setattr__(late.fields[0], "available_at", AT + timedelta(seconds=1))
    with pytest.raises(ScenarioContractError):
        report(late)
    deleted = observation(ScenarioId.MM_05)
    object.__delattr__(deleted, "mapping_version")
    with pytest.raises(ScenarioContractError):
        report(deleted)
    with pytest.raises(ScenarioContractError, match="immutable tuple"):
        inspect_scenario_coverage_batch(scope(), [observation(ScenarioId.APP_02)])


def test_scope_is_revalidated_and_output_omits_event_and_customer_refs() -> None:
    batch_scope = scope()
    object.__setattr__(batch_scope, "mapping_version", "invalid version")
    with pytest.raises(ScenarioContractError):
        inspect_scenario_coverage_batch(batch_scope, ())
    row = observation(ScenarioId.APP_02)
    result = report(row)
    text = dumps(result)
    assert str(row.event_id) not in text
    assert "synthetic-source" not in text
    assert EVIDENCE not in text
    assert "fraud_determined" not in result
    assert "alert_budget_approved" in result["downstream_evaluation"]


def test_exported_report_mutation_cannot_rewrite_frozen_evidence() -> None:
    """Regression for PO/Security/QA alias finding on a real batch report."""
    scenario = ScenarioId.MM_02
    missing_name = SCENARIO_FIELDS[scenario].required[0]
    optional_name = SCENARIO_FIELDS[scenario].optional[0]
    built = inspect_scenario_coverage_batch(
        scope(),
        (
            observation(scenario, event_number=1, omit=missing_name),
            observation(scenario, event_number=2),
        ),
    )
    digest = built.batch_digest
    canonical = built.to_dict()
    canonical_json = dumps(canonical, sort_keys=True)

    # Each exported level must be a new, disconnected JSON container.
    altered = built.to_dict()
    summaries = altered["scenarios"]
    assert isinstance(summaries, list)
    target = next(item for item in summaries if item["scenario_id"] == scenario.value)
    target["input_events"] = 999
    target["complete_required_events"] = 999
    target["blocked_required_events"] = 999
    target["required_coverage"]["numerator"] = 999
    target["required_coverage"]["denominator"] = 999
    target["required_coverage"]["value"] = 100.0
    target["required_coverage"]["undefined_reason"] = "fake"
    target["missing_required_counts"][missing_name] = 999
    target["unavailable_optional_counts"][optional_name] = 999
    summaries.clear()
    altered["scope"]["tenant_ref"] = "other-tenant"
    altered["downstream_evaluation"]["precision"] = 1.0
    altered["limitations"].append("forged evidence")

    assert dumps(built.to_dict(), sort_keys=True) == canonical_json
    assert built.to_dict() == canonical
    assert built.batch_digest == digest

    # A caller cannot mutate the retained summary, nested rate, or count pairs.
    retained = next(x for x in built.scenarios if x.scenario_id == scenario.value)
    assert retained.complete_required_events == 1
    assert retained.blocked_required_events == 1
    assert retained.required_coverage.value == 0.5
    with pytest.raises(FrozenInstanceError):
        setattr(retained, "complete_required_events", 999)
    with pytest.raises(FrozenInstanceError):
        setattr(retained.required_coverage, "value", 100.0)
    with pytest.raises(TypeError):
        retained.missing_required_counts[0] = (missing_name, 999)
    with pytest.raises(TypeError):
        retained.unavailable_optional_counts[0] = (optional_name, 999)
    assert built.to_dict() == canonical
    assert built.batch_digest == digest
