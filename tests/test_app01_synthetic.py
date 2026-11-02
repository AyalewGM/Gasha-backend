"""APP-01 synthetic-only candidate: exact and adversarial source-shape checks."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from gasha.poc.app01_synthetic import (
    APP01Context,
    APP01History,
    APP01PaymentState,
    APP01Status,
    APP01SyntheticMetrics,
    APP01SyntheticPolicy,
    evaluate_app01_synthetic,
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
EVENT_ID = UUID("e6ecba61-e59a-4c9a-b42b-1c1c252fab12")


def packet(*, include_context: bool = False) -> ScenarioObservation:
    keys = list(SCENARIO_FIELDS[ScenarioId.APP_01].required)
    if include_context:
        keys.extend(SCENARIO_FIELDS[ScenarioId.APP_01].optional)
    return ScenarioObservation(
        scenario_id=ScenarioId.APP_01, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DATASET,
        event_id=EVENT_ID, source_system="synthetic-only", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=AT, received_at=AT, decision_cutoff=AT,
        fields=tuple(FieldEvidence(
            name=name, state=FieldState.OBSERVED,
            source_ref="synthetic-source", source_version="1",
            evidence_digest="sha256:" + "b" * 64,
            observed_at=AT, available_at=AT,
        ) for name in keys),
    )


def policy() -> APP01SyntheticPolicy:
    return APP01SyntheticPolicy(
        version="synthetic-p1", configuration_version="1",
        min_history_days=30, min_baseline_samples=3,
        min_payment_amount=Decimal(1000), min_baseline_multiple=Decimal(5),
    )


def metrics(row: ScenarioObservation) -> APP01SyntheticMetrics:
    return APP01SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="synthetic-p1",
        beneficiary_ref="synthetic-beneficiary", payment_currency="ETB",
        baseline_currency="ETB", payment_state=APP01PaymentState.ATTEMPTED,
        payment_amount=Decimal(2500), history_state=APP01History.COMPLETE,
        history_start=AT - timedelta(days=90), history_end=AT,
        beneficiary_first_seen_at=AT - timedelta(hours=1),
        prior_beneficiary_payments=0, baseline_typical_amount=Decimal(200),
        baseline_sample_count=20, baseline_as_of=AT - timedelta(hours=1),
        available_at=AT,
    )


def evaluate(
    row: ScenarioObservation, values: APP01SyntheticMetrics | None,
    thresholds: APP01SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_app01_synthetic(
        row, policy=policy() if thresholds is None else thresholds,
        metrics=values, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).to_dict()


def test_complete_synthetic_first_beneficiary_large_amount_requires_exception_context() -> None:
    row = packet(include_context=True)
    values = replace(metrics(row), recurring_payment=APP01Context.REPORTED_ABSENT)
    result = evaluate(row, values)
    assert result["status"] == APP01Status.SYNTHETIC_HYPOTHESIS.value
    assert result["heuristic_evaluated"] is True
    for key in ("bank_verified", "fraud_determined", "readiness_authorized",
                "enforcement_activated"):
        assert result[key] is False
    for secret in ("payment_amount", "beneficiary_ref", "payment_currency",
                   "customer_id", "risk_score", "hold_action", "customer_baseline"):
        assert secret not in result
    assert evaluate(row, values) == result


def test_unknown_context_requires_review_never_proves_fraud() -> None:
    row = packet()
    result = evaluate(row, metrics(row))
    assert result["status"] == APP01Status.CONTEXT_REVIEW_REQUIRED.value
    assert result["fraud_determined"] is False


def test_reported_recurring_exception_is_not_a_legitimacy_verdict() -> None:
    row = packet(include_context=True)
    result = evaluate(row, replace(metrics(row), recurring_payment=APP01Context.REPORTED))
    assert result["status"] == APP01Status.CONTEXT_EXCEPTION_REPORTED.value
    assert result["bank_verified"] is False


@pytest.mark.parametrize("context", [APP01Context.REPORTED, APP01Context.REPORTED_ABSENT])
def test_claimed_recurring_context_requires_observed_optional_evidence(
    context: APP01Context,
) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError, match="without observed"):
        evaluate(row, replace(metrics(row), recurring_payment=context))


@pytest.mark.parametrize("history", [APP01History.UNKNOWN, APP01History.INCOMPLETE])
def test_missing_or_partial_beneficiary_history_is_blocked(history: APP01History) -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), history_state=history))[
        "status"
    ] == APP01Status.BLOCKED_HISTORY.value


def test_too_short_covered_history_and_weak_baseline_are_blocked() -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), history_start=AT - timedelta(days=29)))[
        "status"
    ] == APP01Status.BLOCKED_HISTORY.value
    assert evaluate(row, replace(metrics(row), baseline_sample_count=2))[
        "status"
    ] == APP01Status.BLOCKED_METRICS.value


def test_prior_transfer_in_covered_history_defeats_first_time() -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), prior_beneficiary_payments=1))[
        "status"
    ] == APP01Status.BENEFICIARY_NOT_NEW.value


@pytest.mark.parametrize("state", [
    APP01PaymentState.REJECTED, APP01PaymentState.REVERSED, APP01PaymentState.UNKNOWN,
])
def test_ineligible_or_unresolved_payment_states_do_not_emit_hypothesis(
    state: APP01PaymentState,
) -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), payment_state=state))[
        "status"
    ] == APP01Status.BLOCKED_PAYMENT_STATE.value


def test_posted_payment_and_boundary_are_inclusive_for_proposed_thresholds() -> None:
    row = packet(include_context=True)
    values = replace(
        metrics(row), payment_state=APP01PaymentState.POSTED,
        payment_amount=Decimal(1000), recurring_payment=APP01Context.REPORTED_ABSENT,
    )
    assert evaluate(row, values)["status"] == APP01Status.SYNTHETIC_HYPOTHESIS.value


@pytest.mark.parametrize("amount", [Decimal(999), Decimal(900)])
def test_below_one_or_more_proposed_amount_thresholds_is_not_candidate(
    amount: Decimal,
) -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), payment_amount=amount))[
        "status"
    ] == APP01Status.AMOUNT_NOT_UNUSUAL.value


def test_cross_currency_refuses_unapproved_fx_even_with_source_presence() -> None:
    row = packet(include_context=True)
    result = evaluate(row, replace(metrics(row), payment_currency="USD"))
    assert result["status"] == APP01Status.BLOCKED_CURRENCY.value
    assert result["bank_verified"] is False


def test_missing_required_observation_and_missing_inputs_fail_closed() -> None:
    row = packet()
    missing = replace(row, fields=tuple(f for f in row.fields
                                        if f.name != "beneficiary_history"))
    assert evaluate(missing, None)["status"] == APP01Status.BLOCKED_REQUIRED_FIELDS.value
    assert evaluate(row, None)["status"] == APP01Status.BLOCKED_METRICS.value
    assert evaluate_app01_synthetic(
        row, policy=None, metrics=None, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).status is APP01Status.BLOCKED_POLICY


def test_version_and_scope_binding_reject_substitutions() -> None:
    row = packet()
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(row, replace(metrics(row), policy_version="other"))
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(row, replace(metrics(row), observation_digest="sha256:" + "c" * 64))
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(row, metrics(row), replace(policy(), configuration_version="2"))
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate_app01_synthetic(
            row, policy=policy(), metrics=metrics(row),
            expected_installation="synthetic-install", expected_tenant="other",
            expected_dataset_digest=DATASET,
        )


def test_wrong_event_and_late_source_availability_rejected() -> None:
    row = packet()
    later = replace(metrics(row), available_at=AT + timedelta(seconds=1))
    with pytest.raises(ScenarioContractError, match="post-cutoff"):
        evaluate(row, later)
    with pytest.raises(ScenarioContractError, match="wrong-event"):
        evaluate(row, replace(metrics(row), history_end=AT - timedelta(seconds=1)))
    with pytest.raises(ScenarioContractError, match="wrong-event"):
        evaluate(row, replace(metrics(row), baseline_as_of=AT + timedelta(seconds=1),
                              available_at=AT + timedelta(seconds=1)))


@pytest.mark.parametrize("attribute,value", [
    ("prior_beneficiary_payments", True),
    ("baseline_sample_count", 1.0),
    ("payment_amount", 2500.0),
    ("payment_amount", Decimal("NaN")),
    ("baseline_typical_amount", Decimal("Infinity")),
    ("payment_currency", "ETB/USD"),
    ("beneficiary_ref", "raw@example.org"),
    ("recurring_payment", "reported_absent"),
    ("payment_state", "attempted"),
    ("history_state", True),
    ("history_start", datetime(2026, 11, 2, 12)),
])
def test_invalid_caller_metrics_types_rejected(attribute: str, value: object) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), **{attribute: value})


@pytest.mark.parametrize("attribute,value", [
    ("min_history_days", True), ("min_baseline_samples", -1),
    ("min_payment_amount", Decimal(0)), ("min_baseline_multiple", Decimal(1)),
])
def test_invalid_policy_rejected(attribute: str, value: object) -> None:
    with pytest.raises(ScenarioContractError):
        replace(policy(), **{attribute: value})


def test_frozen_object_forgery_is_revalidated_at_use_boundary() -> None:
    row = packet()
    values = metrics(row)
    object.__setattr__(values, "baseline_sample_count", True)
    with pytest.raises(ScenarioContractError):
        evaluate(row, values)
    thresholds = policy()
    object.__setattr__(thresholds, "min_baseline_multiple", Decimal("NaN"))
    with pytest.raises(ScenarioContractError):
        evaluate(row, metrics(row), thresholds)


@pytest.mark.parametrize("path", [
    "src/gasha/api/main.py", "src/gasha/worker.py",
    "src/gasha/decision/service.py", "src/gasha/poc/readiness.py",
    "src/gasha/ingestion/postgres_atomic_outcomes.py",
])
def test_app01_synthetic_is_not_wired_to_protected_or_bank_paths(path: str) -> None:
    assert "app01_synthetic" not in Path(path).read_text(encoding="utf-8")
