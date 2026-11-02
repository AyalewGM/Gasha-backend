"""MM-05 is a synthetic aggregate hypothesis, never a Bank-approved detector."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.mm05_synthetic import (
    MM05AccountState,
    MM05Context,
    MM05Status,
    MM05SyntheticMetrics,
    MM05SyntheticPolicy,
    evaluate_mm05_synthetic,
)
from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
    FieldEvidence,
    FieldState,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
)

AT = datetime(2026, 11, 2, 12, tzinfo=UTC)
DATASET = "sha256:" + "a" * 64
EVENT_ID = UUID("e6ecba61-e59a-4c9a-b42b-1c1c252fab11")


def evidence(name: str) -> FieldEvidence:
    return FieldEvidence(
        name=name, state=FieldState.OBSERVED, source_ref="synthetic-source",
        source_version="1", evidence_digest="sha256:" + "b" * 64,
        observed_at=AT, available_at=AT,
    )


def packet(*, context: bool = False) -> ScenarioObservation:
    fields = list(SCENARIO_FIELDS[ScenarioId.MM_05].required)
    if context:
        fields.extend(SCENARIO_FIELDS[ScenarioId.MM_05].optional)
    return ScenarioObservation(
        scenario_id=ScenarioId.MM_05, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DATASET,
        event_id=EVENT_ID, source_system="synthetic-only", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=AT, received_at=AT, decision_cutoff=AT,
        fields=tuple(evidence(name) for name in fields),
    )


def policy() -> MM05SyntheticPolicy:
    return MM05SyntheticPolicy(
        version="synthetic-p1", configuration_version="1",
        min_prior_days=60, max_current_hours=24, max_gap_hours=0,
        max_prior_count=2, max_prior_value=Decimal(100),
        min_current_count=6, min_current_value=Decimal(1000),
        min_count_increase=4, min_value_increase=Decimal(900),
    )


def metrics(row: ScenarioObservation) -> MM05SyntheticMetrics:
    return MM05SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="synthetic-p1",
        account_ref="synthetic-pseudonym", currency="ETB",
        account_state=MM05AccountState.ACTIVE,
        prior_start=AT - timedelta(days=91),
        prior_end=AT - timedelta(hours=12),
        current_start=AT - timedelta(hours=12),
        current_end=AT, available_at=AT,
        prior_count=1, prior_value=Decimal(50),
        current_count=10, current_value=Decimal(3000),
    )


def evaluate(
    row: ScenarioObservation, *, values: MM05SyntheticMetrics | None,
    thresholds: MM05SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_mm05_synthetic(
        row, policy=policy() if thresholds is None else thresholds, metrics=values,
        expected_installation="synthetic-install", expected_tenant="synthetic-tenant",
        expected_dataset_digest=DATASET,
    ).to_dict()


def test_unknown_exception_context_never_becomes_false_or_confirmed_fraud() -> None:
    row = packet()
    result = evaluate(row, values=metrics(row))
    assert result["status"] == MM05Status.CONTEXT_REVIEW_REQUIRED.value
    assert result["reasons"] == ["optional_exception_context_unknown"]
    assert result["heuristic_evaluated"] is True
    for key in ("bank_verified", "fraud_determined", "readiness_authorized",
                "enforcement_activated"):
        assert result[key] is False
    for forbidden in ("risk_score", "account_ref", "current_value", "prior_value",
                      "customer_id", "bank_approved", "hold_action"):
        assert forbidden not in result


def test_explicitly_observed_exception_negatives_allow_only_synthetic_hypothesis() -> None:
    row = packet(context=True)
    values = replace(metrics(row), reactivation_reason=MM05Context.REPORTED_ABSENT,
                     scheduled_bulk_activity=MM05Context.REPORTED_ABSENT)
    result = evaluate(row, values=values)
    assert result["status"] == MM05Status.SYNTHETIC_CHANGE_HYPOTHESIS.value
    assert result["fraud_determined"] is False


@pytest.mark.parametrize("name", ["reactivation_reason", "scheduled_bulk_activity"])
def test_reported_exception_suppresses_hypothesis_without_proving_legitimacy(name: str) -> None:
    row = packet(context=True)
    values = replace(metrics(row), **{name: MM05Context.REPORTED})
    result = evaluate(row, values=values)
    assert result["status"] == MM05Status.CONTEXT_EXCLUSION_REPORTED.value
    assert result["bank_verified"] is False


@pytest.mark.parametrize("name", ["reactivation_reason", "scheduled_bulk_activity"])
def test_context_assertion_requires_observed_optional_field(name: str) -> None:
    row = packet()
    values = replace(metrics(row), **{name: MM05Context.REPORTED_ABSENT})
    with pytest.raises(ScenarioContractError, match="without observed"):
        evaluate(row, values=values)


@pytest.mark.parametrize("count,value", [(2, Decimal(99)), (3, Decimal(101))])
def test_non_dormant_baseline_is_not_a_candidate(count: int, value: Decimal) -> None:
    row = packet()
    result = evaluate(row, values=replace(metrics(row), prior_count=count, prior_value=value))
    if count <= 2 and value <= 100:
        assert result["status"] == MM05Status.CONTEXT_REVIEW_REQUIRED.value
    else:
        assert result["status"] == MM05Status.BASELINE_NOT_DORMANT.value


@pytest.mark.parametrize(
    "change",
    [
        {"current_count": 5}, {"current_value": Decimal(999)},
        {"current_count": 4, "prior_count": 1},
        {"current_value": Decimal(949), "prior_value": Decimal(50)},
    ],
)
def test_every_threshold_must_pass_and_boundary_is_inclusive(change: dict[str, object]) -> None:
    row = packet()
    result = evaluate(row, values=replace(metrics(row), **change))
    assert result["status"] == MM05Status.NO_ACTIVITY_SURGE.value


@pytest.mark.parametrize(
    ("count_field", "value_field"),
    [("prior_count", "prior_value"), ("current_count", "current_value")],
)
def test_zero_transaction_count_rejects_nonzero_aggregate_value(
    count_field: str, value_field: str,
) -> None:
    row = packet()
    invalid = {count_field: 0, value_field: Decimal(1)}
    with pytest.raises(ScenarioContractError, match="zero transactions"):
        evaluate(row, values=replace(metrics(row), **invalid))


def test_mutated_zero_transaction_count_is_revalidated_at_consumption() -> None:
    row = packet()
    values = metrics(row)
    object.__setattr__(values, "current_count", 0)
    with pytest.raises(ScenarioContractError, match="zero transactions"):
        evaluate(row, values=values)


def test_zero_baseline_uses_delta_not_undefined_ratio() -> None:
    row = packet(context=True)
    values = replace(metrics(row), prior_count=0, prior_value=Decimal(0),
                     current_count=6, current_value=Decimal(1000),
                     reactivation_reason=MM05Context.REPORTED_ABSENT,
                     scheduled_bulk_activity=MM05Context.REPORTED_ABSENT)
    assert evaluate(row, values=values)["status"] == "synthetic_change_hypothesis"


@pytest.mark.parametrize("state", [MM05AccountState.CLOSED, MM05AccountState.FROZEN,
                                     MM05AccountState.UNKNOWN])
def test_closed_frozen_unknown_lifecycle_never_emits_hypothesis(
    state: MM05AccountState,
) -> None:
    row = packet()
    assert evaluate(row, values=replace(metrics(row), account_state=state))[
        "status"] == MM05Status.BLOCKED_ACCOUNT_STATE.value


def test_missing_required_fields_and_missing_metrics_never_fabricate_zero() -> None:
    row = packet()
    missing = replace(row, fields=tuple(f for f in row.fields
                                        if f.name != "prior_transaction_count"))
    assert evaluate(missing, values=None)["status"] == "blocked_required_fields"
    assert evaluate(row, values=None)["status"] == "blocked_metrics"
    no_policy = evaluate_mm05_synthetic(
        row, policy=None, metrics=None, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    )
    assert no_policy.status is MM05Status.BLOCKED_POLICY


@pytest.mark.parametrize("field", ["observation_digest", "policy_version"])
def test_wrong_dataset_binding_or_policy_version_fails_closed(field: str) -> None:
    row = packet()
    substituted = "sha256:" + "c" * 64 if field == "observation_digest" else "other"
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(row, values=replace(metrics(row), **{field: substituted}))


def test_configuration_version_mismatch_fails_closed() -> None:
    row = packet()
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(row, values=metrics(row),
                 thresholds=replace(policy(), configuration_version="2"))


def test_later_collected_metric_and_wrong_event_window_rejected() -> None:
    row = packet()
    with pytest.raises(ScenarioContractError, match="chronology"):
        replace(metrics(row), available_at=AT - timedelta(seconds=1))
    later = replace(row, decision_cutoff=AT + timedelta(hours=1))
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(later, values=metrics(row))
    shifted = replace(metrics(row), current_start=AT - timedelta(hours=5),
                      prior_end=AT - timedelta(hours=5))
    assert evaluate(row, values=shifted)["status"] == "context_review_required"


def test_qualifying_windows_are_required_no_silent_window_length_coercion() -> None:
    row = packet()
    too_short = replace(metrics(row), prior_start=AT - timedelta(days=3))
    assert evaluate(row, values=too_short)["status"] == "blocked_window"
    gap = replace(metrics(row), prior_end=AT - timedelta(days=2))
    assert evaluate(row, values=gap)["status"] == "blocked_window"


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("prior_count", True), ("current_count", 1.0),
        ("current_value", float("nan")), ("prior_value", Decimal("NaN")),
        ("current_value", Decimal("Infinity")),
        ("currency", "ETB/USD"), ("account_ref", "customer@email.test"),
        ("reactivation_reason", True),
        ("current_start", datetime(2026, 11, 2, 0)),
    ],
)
def test_invalid_untrusted_metric_types_rejected(attribute: str, value: object) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), **{attribute: value})


def test_forged_frozen_metrics_and_policy_rechecked_at_consumption() -> None:
    row = packet()
    values = metrics(row)
    object.__setattr__(values, "currency", "raw account ID")
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=values)
    thresholds = policy()
    object.__setattr__(thresholds, "max_prior_count", True)
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=metrics(row), thresholds=thresholds)


def test_dst_fold_aware_windows_consistent_with_utc() -> None:
    zone = ZoneInfo("America/New_York")
    first_fold = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=0)
    second_fold = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    assert first_fold.astimezone(UTC) < second_fold.astimezone(UTC)
    row = packet()
    values = metrics(row)
    assert replace(values, current_start=first_fold, prior_end=first_fold).current_start == (
        first_fold.astimezone(UTC)
    )
    assert replace(values, current_start=second_fold, prior_end=second_fold).current_start == (
        second_fold.astimezone(UTC)
    )


def test_wrong_tenant_or_dataset_expected_scope_fails_closed() -> None:
    row = packet()
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate_mm05_synthetic(
            row, policy=policy(), metrics=metrics(row),
            expected_installation="synthetic-install", expected_tenant="different",
            expected_dataset_digest=DATASET,
        )


@pytest.mark.parametrize(
    "path", ["src/gasha/api/main.py", "src/gasha/worker.py",
             "src/gasha/decision/service.py", "src/gasha/poc/readiness.py",
             "src/gasha/ingestion/postgres_atomic_outcomes.py"],
)
def test_mm05_is_not_wired_to_bank_or_advisory_routes(path: str) -> None:
    assert "mm05_synthetic" not in Path(path).read_text(encoding="utf-8")
