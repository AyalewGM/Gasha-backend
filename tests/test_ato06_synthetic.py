"""Bounded offline ATO-06 hypothesis and fail-closed coverage regressions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from gasha.poc.ato06_synthetic import (
    ATO06BeneficiaryStatus,
    ATO06MaintenanceContext,
    ATO06RetryContext,
    ATO06Status,
    ATO06SyntheticMetrics,
    ATO06SyntheticPolicy,
    ATO06TransferStatus,
    evaluate_ato06_synthetic,
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
EVENT = UUID("e6ecba61-e59a-4c9a-b42b-1c1c252fab35")


def packet(*, execution: bool = False, settlement: bool = False) -> ScenarioObservation:
    keys = list(SCENARIO_FIELDS[ScenarioId.ATO_06].required)
    if execution:
        keys.append("transfer_executed_at")
    if settlement:
        keys.append("transfer_settled_at")
    return ScenarioObservation(
        scenario_id=ScenarioId.ATO_06,
        installation_ref="synthetic-install", tenant_ref="synthetic-tenant",
        dataset_digest=DATASET, event_id=EVENT, source_system="synthetic-only",
        source_schema_version="1", mapping_version="1", configuration_version="1",
        occurred_at=AT, received_at=AT, decision_cutoff=AT + timedelta(minutes=5),
        fields=tuple(
            FieldEvidence(
                name=name, state=FieldState.OBSERVED, source_ref="synthetic-source",
                source_version="1", evidence_digest="sha256:" + "b" * 64,
                observed_at=AT + timedelta(seconds=(
                    20 if name == "transfer_executed_at"
                    else 30 if name == "transfer_settled_at" else 0
                )),
                available_at=AT + timedelta(seconds=(
                    20 if name == "transfer_executed_at"
                    else 30 if name == "transfer_settled_at" else 0
                )),
            )
            for name in keys
        ),
    )


def policy() -> ATO06SyntheticPolicy:
    return ATO06SyntheticPolicy(
        version="proposed-1", configuration_version="1",
        max_addition_to_transfer_seconds=300, min_history_days=30,
        max_prior_beneficiary_additions=1,
        min_transfer_amount=Decimal(500), min_transfer_currency="ETB",
    )


def metrics(row: ScenarioObservation) -> ATO06SyntheticMetrics:
    return ATO06SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="proposed-1",
        beneficiary_ref="synthetic-beneficiary",
        beneficiary_created_at=AT - timedelta(minutes=3),
        beneficiary_activated_at=AT - timedelta(minutes=2),
        beneficiary_status=ATO06BeneficiaryStatus.ACTIVE,
        history_start=AT - timedelta(days=40),
        history_end=AT - timedelta(minutes=3),
        history_complete=True,
        prior_beneficiary_additions=0,
        transfer_attempted_at=AT,
        transfer_status=ATO06TransferStatus.ATTEMPTED,
        transfer_amount=Decimal(500), transfer_currency="ETB",
        available_at=AT, attempt_deduplicated=True,
        maintenance_context=ATO06MaintenanceContext.UNKNOWN,
    )


def evaluate(
    row: ScenarioObservation,
    value: ATO06SyntheticMetrics | None,
    thresholds: ATO06SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_ato06_synthetic(
        row, policy=policy() if thresholds is None else thresholds,
        metrics=value, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).to_dict()


def test_positive_inclusive_time_and_amount_boundaries_are_non_authoritative() -> None:
    row = packet()
    item = replace(
        metrics(row), beneficiary_activated_at=AT - timedelta(minutes=4),
        beneficiary_created_at=AT - timedelta(minutes=5),
        history_end=AT - timedelta(minutes=5),
    )
    result = evaluate(row, item)
    assert result["status"] == ATO06Status.SYNTHETIC_HYPOTHESIS.value
    assert result["heuristic_evaluated"] is True
    assert result["reasons"] == [
        "low_addition_frequency_in_claimed_precreation_baseline",
        "addition_to_attempt_within_proposed_window",
        "maintenance_context_unknown_unassessed",
        "retry_context_unknown_unassessed",
    ]
    assert result == evaluate(row, item)
    for flag in ("bank_verified", "fraud_determined", "readiness_authorized",
                 "enforcement_activated"):
        assert result[flag] is False
    assert isinstance(result["effective_input_digest"], str)
    for secret in ("beneficiary_ref", "transfer_amount", "transfer_currency",
                   "tenant_ref", "event_id", "fraud_score", "payment_action"):
        assert secret not in result


def test_missing_required_field_blocks_instead_of_inventing_zero_risk() -> None:
    row = packet()
    row = replace(row, fields=tuple(field for field in row.fields
                                    if field.name != "beneficiary_baseline"))
    result = evaluate(row, replace(metrics(packet()), observation_digest=row.fingerprint()))
    assert result["status"] == ATO06Status.BLOCKED_REQUIRED_FIELDS.value
    assert "beneficiary_baseline" in result["reasons"]


def test_missing_policy_or_metrics_blocks() -> None:
    row = packet()
    assert evaluate(row, None)["status"] == ATO06Status.BLOCKED_METRICS.value
    assert evaluate_ato06_synthetic(
        row, policy=None, metrics=metrics(row),
        expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).status is ATO06Status.BLOCKED_POLICY


@pytest.mark.parametrize("change,status", [
    ({"history_complete": False}, ATO06Status.BLOCKED_HISTORY),
    ({"history_start": AT - timedelta(days=20)}, ATO06Status.BLOCKED_HISTORY),
    ({"prior_beneficiary_additions": 2}, ATO06Status.ADDITION_NOT_UNUSUAL),
    ({"transfer_amount": Decimal(499)}, ATO06Status.AMOUNT_BELOW_FLOOR),
    ({"beneficiary_status": ATO06BeneficiaryStatus.PENDING}, ATO06Status.BLOCKED_STATUS),
    ({"transfer_status": ATO06TransferStatus.FAILED}, ATO06Status.BLOCKED_STATUS),
])
def test_negative_cases_are_explicit(change: dict[str, object], status: ATO06Status) -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), **change))["status"] == status.value


def test_rapid_window_expiry_and_activation_order() -> None:
    row = packet()
    outside = replace(
        metrics(row), beneficiary_created_at=AT - timedelta(minutes=10),
        beneficiary_activated_at=AT - timedelta(minutes=6),
        history_end=AT - timedelta(minutes=10),
    )
    assert evaluate(row, outside)["status"] == ATO06Status.OUTSIDE_WINDOW.value
    with pytest.raises(ScenarioContractError, match="chronology"):
        replace(metrics(row), beneficiary_activated_at=AT + timedelta(seconds=1))


def test_executed_or_settled_claims_require_observed_optional_evidence() -> None:
    row = packet()
    executed = replace(
        metrics(row), transfer_status=ATO06TransferStatus.EXECUTED,
        transfer_executed_at=AT + timedelta(seconds=20),
        available_at=AT + timedelta(seconds=20),
    )
    with pytest.raises(ScenarioContractError, match="claimed without observed evidence"):
        evaluate(row, executed)
    full = packet(execution=True)
    assert evaluate(full, replace(executed, observation_digest=full.fingerprint()))[
        "status"
    ] == ATO06Status.SYNTHETIC_HYPOTHESIS.value

    settled = replace(
        executed, transfer_status=ATO06TransferStatus.SETTLED,
        transfer_settled_at=AT + timedelta(seconds=30),
        available_at=AT + timedelta(seconds=30),
    )
    with pytest.raises(ScenarioContractError, match="claimed without observed evidence"):
        evaluate(full, replace(settled, observation_digest=full.fingerprint()))
    both = packet(execution=True, settlement=True)
    assert evaluate(both, replace(settled, observation_digest=both.fingerprint()))[
        "status"
    ] == ATO06Status.SYNTHETIC_HYPOTHESIS.value

    # An observed optional field must not predate its purported event.
    forged_fields = tuple(
        replace(field, observed_at=AT, available_at=AT)
        if field.name == "transfer_settled_at" else field
        for field in both.fields
    )
    forged = replace(both, fields=forged_fields)
    with pytest.raises(ScenarioContractError, match="impossible evidence availability"):
        evaluate(forged, replace(settled, observation_digest=forged.fingerprint()))


def test_post_cutoff_settlement_and_metrics_rejected() -> None:
    row = packet(execution=True, settlement=True)
    value = metrics(row)
    with pytest.raises(ScenarioContractError, match="post-cutoff"):
        evaluate(row, replace(value, available_at=AT + timedelta(minutes=6)))


def test_wrong_event_dataset_tenant_policy_or_digests_never_promote() -> None:
    row = packet()
    value = metrics(row)
    with pytest.raises(ScenarioContractError, match="not bound"):
        evaluate(row, replace(value, transfer_attempted_at=AT - timedelta(seconds=1)))
    with pytest.raises(ScenarioContractError, match="version mismatch"):
        evaluate(row, replace(value, observation_digest="sha256:" + "0" * 64))
    with pytest.raises(ScenarioContractError, match="version mismatch"):
        evaluate(row, value, replace(policy(), configuration_version="other"))
    with pytest.raises(ScenarioContractError, match="installation/tenant/dataset"):
        evaluate_ato06_synthetic(
            row, policy=policy(), metrics=value,
            expected_installation="synthetic-install",
            expected_tenant="wrong-tenant", expected_dataset_digest=DATASET,
        )


@pytest.mark.parametrize("invalid", [True, "1", -1, 1.5, 1000001])
def test_strict_policy_counts(invalid: object) -> None:
    with pytest.raises(ScenarioContractError):
        replace(policy(), max_prior_beneficiary_additions=invalid)  # type: ignore[arg-type]


@pytest.mark.parametrize("invalid", [float("nan"), Decimal("NaN"),
                                     Decimal("Infinity"), 0, Decimal(-1)])
def test_strict_amounts(invalid: object) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), transfer_amount=invalid)  # type: ignore[arg-type]


def test_post_construction_mutation_is_rejected_at_consumption() -> None:
    row = packet()
    value = metrics(row)
    object.__setattr__(value, "transfer_amount", Decimal("NaN"))
    with pytest.raises(ScenarioContractError):
        evaluate(row, value)
    value = metrics(row)
    object.__setattr__(value, "history_complete", "yes")
    with pytest.raises(ScenarioContractError):
        evaluate(row, value)
    candidate = policy()
    object.__setattr__(candidate, "min_transfer_amount", Decimal("NaN"))
    with pytest.raises(ScenarioContractError):
        evaluate(row, metrics(row), candidate)



def test_creation_anchor_inclusive_and_one_second_outside() -> None:
    row = packet()
    boundary = replace(
        metrics(row), beneficiary_created_at=AT - timedelta(minutes=5),
        beneficiary_activated_at=AT - timedelta(minutes=4),
        history_end=AT - timedelta(minutes=5),
    )
    assert evaluate(row, boundary)["status"] == ATO06Status.SYNTHETIC_HYPOTHESIS.value
    outside = replace(
        boundary, beneficiary_created_at=AT - timedelta(minutes=5, seconds=1),
        history_end=AT - timedelta(minutes=5, seconds=1),
    )
    assert evaluate(row, outside)["status"] == ATO06Status.OUTSIDE_WINDOW.value
    old_created_recently_active = replace(
        boundary, beneficiary_created_at=AT - timedelta(days=1),
        history_end=AT - timedelta(days=1),
    )
    assert evaluate(row, old_created_recently_active)["status"] == (
        ATO06Status.OUTSIDE_WINDOW.value
    )


def test_history_closes_at_addition_and_covers_exact_minimum() -> None:
    row = packet()
    base = metrics(row)
    exact = replace(base, history_start=base.beneficiary_created_at - timedelta(days=30))
    assert evaluate(row, exact)["status"] == ATO06Status.SYNTHETIC_HYPOTHESIS.value
    gap = replace(base, history_end=base.beneficiary_created_at - timedelta(seconds=1))
    assert evaluate(row, gap)["status"] == ATO06Status.BLOCKED_HISTORY.value
    short = replace(
        base, history_start=base.beneficiary_created_at - timedelta(days=30)
        + timedelta(seconds=1),
    )
    assert evaluate(row, short)["status"] == ATO06Status.BLOCKED_HISTORY.value


def test_transfer_unit_is_policy_bound_before_negative() -> None:
    row = packet()
    base = metrics(row)
    assert evaluate(row, base)["status"] == ATO06Status.SYNTHETIC_HYPOTHESIS.value
    assert evaluate(row, replace(base, transfer_amount=Decimal("499.99")))[
        "status"
    ] == ATO06Status.AMOUNT_BELOW_FLOOR.value
    assert evaluate(row, replace(base, transfer_currency="USD"))[
        "status"
    ] == ATO06Status.BLOCKED_CURRENCY.value
    with pytest.raises(ScenarioContractError, match="currency"):
        replace(policy(), min_transfer_currency="")
    with pytest.raises(ScenarioContractError, match="currency"):
        replace(base, transfer_currency="")
    assert evaluate(row, base, replace(policy(), min_transfer_currency="USD"))[
        "status"
    ] == ATO06Status.BLOCKED_CURRENCY.value


@pytest.mark.parametrize("context", [
    ATO06MaintenanceContext.PLANNED_SETUP,
    ATO06MaintenanceContext.APPROVED_PAYEE_MIGRATION,
    ATO06MaintenanceContext.PAYROLL_VENDOR_ENROLLMENT,
    ATO06MaintenanceContext.BANK_ADMIN_CORRECTION,
])
def test_reported_legitimate_context_is_explicit_exclusion(
    context: ATO06MaintenanceContext,
) -> None:
    row = packet()
    item = replace(
        metrics(row), maintenance_context=context,
        maintenance_source_ref=row.source_system,
        maintenance_source_version=row.source_schema_version,
        maintenance_observed_at=AT - timedelta(minutes=1),
        maintenance_available_at=AT - timedelta(minutes=1),
    )
    assert evaluate(row, item)["status"] == ATO06Status.CONTEXTUAL_EXCLUSION.value


def test_reported_absent_context_requires_bound_source_and_cutoff() -> None:
    row = packet()
    base = metrics(row)
    absent = replace(
        base, maintenance_context=ATO06MaintenanceContext.REPORTED_ABSENT,
        maintenance_source_ref=row.source_system,
        maintenance_source_version=row.source_schema_version,
        maintenance_observed_at=AT - timedelta(minutes=1),
        maintenance_available_at=AT - timedelta(minutes=1),
    )
    result = evaluate(row, absent)
    assert result["status"] == ATO06Status.SYNTHETIC_HYPOTHESIS.value
    assert "maintenance_context_unknown_unassessed" not in result["reasons"]
    with pytest.raises(ScenarioContractError, match="source/version"):
        evaluate(row, replace(absent, maintenance_source_version="invalid"))
    with pytest.raises(ScenarioContractError, match="source"):
        replace(absent, maintenance_source_ref="")
    with pytest.raises(ScenarioContractError, match="maintenance"):
        replace(absent, maintenance_available_at=AT + timedelta(seconds=1))
    with pytest.raises(ScenarioContractError, match="unknown context"):
        replace(base, maintenance_source_ref="unbound")


def test_deduplication_and_retry_context_do_not_invent_payment_lineage() -> None:
    row = packet()
    base = metrics(row)
    assert evaluate(row, replace(base, attempt_deduplicated=False))[
        "status"
    ] == ATO06Status.BLOCKED_ATTEMPT_LINEAGE.value
    assert evaluate(row, replace(base, retry_context=ATO06RetryContext.TECHNICAL_RETRY))[
        "status"
    ] == ATO06Status.CONTEXTUAL_EXCLUSION.value
    reported = evaluate(row, replace(
        base, retry_context=ATO06RetryContext.REPORTED_NOT_RETRY,
    ))
    assert "retry_context_unknown_unassessed" not in reported["reasons"]


def test_effective_input_fingerprint_binds_values_thresholds_and_context() -> None:
    row = packet()
    base = metrics(row)
    first = evaluate(row, base)
    assert first == evaluate(row, base)
    cases = [
        (replace(base, transfer_amount=Decimal(501)), policy()),
        (base, replace(policy(), min_transfer_amount=Decimal(499))),
        (replace(base, retry_context=ATO06RetryContext.REPORTED_NOT_RETRY), policy()),
        (replace(base, transfer_currency="USD"), policy()),
        (replace(base, beneficiary_activated_at=AT - timedelta(minutes=1)), policy()),
    ]
    for candidate, threshold in cases:
        result = evaluate(row, candidate, threshold)
        assert result["observation_digest"] == first["observation_digest"]
        assert result["effective_input_digest"] != first["effective_input_digest"]
    # Canonically equal UTC instants with different offsets share identity.
    from datetime import timezone
    offset = timezone(timedelta(hours=3))
    changed = replace(base, transfer_attempted_at=AT.astimezone(offset))
    assert evaluate(row, changed)["effective_input_digest"] == (
        first["effective_input_digest"]
    )


def test_creation_field_must_be_available_by_metrics_snapshot() -> None:
    row = packet()
    updated = replace(row, fields=tuple(
        replace(
            field, observed_at=AT + timedelta(seconds=1),
            available_at=AT + timedelta(seconds=1),
        ) if field.name == "beneficiary_created_at" else field for field in row.fields
    ))
    item = metrics(updated)
    assert evaluate(updated, item)["status"] == ATO06Status.BLOCKED_REQUIRED_FIELDS.value


def test_no_operational_imports_or_bank_readiness_wiring() -> None:
    root = Path(__file__).resolve().parents[1]
    for path in (
        "src/gasha/api/main.py", "src/gasha/worker.py",
        "src/gasha/poc/readiness.py",
    ):
        source = (root / path).read_text()
        assert "gasha.poc.ato06_synthetic" not in source
        assert "evaluate_ato06_synthetic" not in source
