"""APP-02 point-in-time, source, tenant, context and synthetic-safety regressions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from gasha.poc.app02_synthetic import (
    APP02ChangeKind,
    APP02MaintenanceContext,
    APP02PaymentStatus,
    APP02Status,
    APP02SyntheticMetrics,
    APP02SyntheticPolicy,
    evaluate_app02_synthetic,
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
CHANGE = AT - timedelta(minutes=5)
DATASET = "sha256:" + "a" * 64
EVENT = UUID("3e201ab7-08ea-4c41-b074-84f1ae0f151c")
CHANGE_FIELDS = {"authorized_change_event", "change_occurred_at"}


def packet(
    *, maintenance: bool = False, change_at: datetime = CHANGE,
    payment_at: datetime = AT,
) -> ScenarioObservation:
    names = list(SCENARIO_FIELDS[ScenarioId.APP_02].required)
    if maintenance:
        names.append("approved_maintenance_reset")
    return ScenarioObservation(
        scenario_id=ScenarioId.APP_02, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DATASET, event_id=EVENT,
        source_system="synthetic-payment", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=payment_at, received_at=payment_at,
        decision_cutoff=payment_at + timedelta(minutes=5),
        fields=tuple(
            FieldEvidence(
                name=name, state=FieldState.OBSERVED,
                source_ref="change-system" if name in CHANGE_FIELDS else "payment-system",
                source_version="1", evidence_digest="sha256:" + "b" * 64,
                observed_at=change_at if name in CHANGE_FIELDS else payment_at,
                available_at=change_at if name in CHANGE_FIELDS else payment_at,
            ) for name in names
        ),
    )


def policy() -> APP02SyntheticPolicy:
    return APP02SyntheticPolicy(
        version="proposed-1", configuration_version="1",
        max_change_to_payment_seconds=300, min_baseline_days=30,
        min_baseline_samples=10, min_payment_amount=Decimal(50),
        min_baseline_multiple=Decimal(3), payment_currency="ETB",
    )


def metrics(row: ScenarioObservation) -> APP02SyntheticMetrics:
    return APP02SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="proposed-1",
        payment_event_id=EVENT, change_ref="change-pseudonym",
        change_kind=APP02ChangeKind.DEVICE, change_at=CHANGE,
        change_source_ref="change-system", change_source_version="1",
        payment_at=AT, payment_status=APP02PaymentStatus.POSTED,
        payment_amount=Decimal(100), payment_currency="ETB",
        baseline_typical_amount=Decimal(10), baseline_currency="ETB",
        baseline_samples=20, baseline_start=CHANGE - timedelta(days=31),
        baseline_end=CHANGE, baseline_complete=True, available_at=AT,
    )


def evaluate(
    row: ScenarioObservation, candidate: APP02SyntheticMetrics,
    thresholds: APP02SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_app02_synthetic(
        row, policy=policy() if thresholds is None else thresholds, metrics=candidate,
        expected_installation="synthetic-install", expected_tenant="synthetic-tenant",
        expected_dataset_digest=DATASET,
    ).to_dict()


def test_candidate_without_optional_context_is_explicitly_unassessed() -> None:
    row = packet()
    candidate = metrics(row)
    result = evaluate(row, candidate)
    assert result["status"] == APP02Status.CONTEXT_UNASSESSED.value
    assert result["reasons"] == ["maintenance_or_reset_context_unavailable"]
    assert result == evaluate(row, candidate)
    assert result["effective_input_digest"].startswith("sha256:")
    assert result["source"] == "synthetic_caller_asserted"
    for key in ("bank_verified", "fraud_determined", "social_engineering_determined",
                "readiness_authorized", "enforcement_activated"):
        assert result[key] is False
    for private in ("tenant_ref", "change_ref", "payment_event_id", "payment_amount",
                    "change_source_ref"):
        assert private not in result


@pytest.mark.parametrize("kind", list(APP02ChangeKind))
def test_positive_when_source_reports_no_maintenance_and_amount_unusual(
    kind: APP02ChangeKind,
) -> None:
    row = packet(maintenance=True)
    candidate = replace(
        metrics(row), change_kind=kind,
        maintenance_context=APP02MaintenanceContext.REPORTED_ABSENT,
        maintenance_source_ref="payment-system", maintenance_source_version="1",
        maintenance_observed_at=AT, maintenance_available_at=AT,
    )
    result = evaluate(row, candidate)
    assert result["status"] == APP02Status.SYNTHETIC_HYPOTHESIS.value
    assert result["heuristic_evaluated"] is True


@pytest.mark.parametrize(("changes", "expected"), [
    ({"payment_status": APP02PaymentStatus.REVERSED}, APP02Status.BLOCKED_PAYMENT),
    ({"payment_status": APP02PaymentStatus.FAILED}, APP02Status.BLOCKED_PAYMENT),
    ({"payment_status": APP02PaymentStatus.UNKNOWN}, APP02Status.BLOCKED_PAYMENT),
    ({"payment_currency": "USD"}, APP02Status.BLOCKED_CURRENCY),
    ({"baseline_currency": "USD"}, APP02Status.BLOCKED_CURRENCY),
    ({"baseline_complete": False}, APP02Status.BLOCKED_HISTORY),
    ({"baseline_samples": 9}, APP02Status.BLOCKED_HISTORY),
    ({"baseline_start": CHANGE - timedelta(days=29)}, APP02Status.BLOCKED_HISTORY),
    ({"baseline_end": CHANGE + timedelta(seconds=1)}, APP02Status.BLOCKED_HISTORY),
    ({"payment_amount": Decimal(49)}, APP02Status.AMOUNT_ORDINARY),
    ({"baseline_typical_amount": Decimal(34)}, APP02Status.AMOUNT_ORDINARY),
    ({"change_at": AT - timedelta(seconds=301)}, APP02Status.OUTSIDE_WINDOW),
])
def test_negative_and_blocked_cases(
    changes: dict[str, object], expected: APP02Status,
) -> None:
    candidate_change = changes.get("change_at", CHANGE)
    assert isinstance(candidate_change, datetime)
    row = packet(change_at=candidate_change)
    candidate = replace(metrics(row), **changes)
    # Keep claimed baseline no later than the changed event for true window negatives.
    if "change_at" in changes:
        candidate = replace(
            candidate, baseline_end=candidate.change_at,
            baseline_start=candidate.change_at - timedelta(days=31),
        )
    result = evaluate(row, candidate)
    assert result["status"] == expected.value
    assert result["enforcement_activated"] is False


def test_time_and_amount_threshold_boundaries() -> None:
    row = packet()
    proposed = replace(policy(), min_payment_amount=Decimal(30))
    exact = replace(metrics(row), payment_amount=Decimal(30))
    assert evaluate(row, exact, proposed)["status"] == APP02Status.CONTEXT_UNASSESSED.value
    assert evaluate(row, replace(exact, payment_amount=Decimal("29.99")), proposed)[
        "status"
    ] == APP02Status.AMOUNT_ORDINARY.value
    assert evaluate(row, replace(exact, baseline_typical_amount=Decimal(10)), proposed)[
        "status"
    ] == APP02Status.CONTEXT_UNASSESSED.value
    assert evaluate(
        row, replace(exact, baseline_typical_amount=Decimal("10.01")), proposed,
    )["status"] == APP02Status.AMOUNT_ORDINARY.value


@pytest.mark.parametrize("field_name", SCENARIO_FIELDS[ScenarioId.APP_02].required)
def test_required_evidence_after_metrics_snapshot_blocks_before_base_negatives(
    field_name: str,
) -> None:
    row = packet()
    changed = replace(row, fields=tuple(
        replace(item, available_at=AT + timedelta(seconds=1))
        if item.name == field_name else item for item in row.fields
    ))
    candidate = replace(
        metrics(changed), observation_digest=changed.fingerprint(),
        payment_amount=Decimal(1),
    )
    result = evaluate(changed, candidate)
    assert result["status"] == APP02Status.BLOCKED_FIELDS.value
    assert result["reasons"] == [
        f"required_evidence_after_metrics_snapshot:{field_name}",
    ]
    assert result["heuristic_evaluated"] is False


def test_missing_required_field_blocks() -> None:
    row = packet()
    incomplete = replace(row, fields=tuple(
        item for item in row.fields if item.name != "payment_baseline"
    ))
    candidate = replace(metrics(row), observation_digest=incomplete.fingerprint())
    assert evaluate(incomplete, candidate)["status"] == APP02Status.BLOCKED_FIELDS.value


def test_reported_approved_maintenance_excludes_only_qualifying_candidate() -> None:
    row = packet(maintenance=True)
    maintenance = {
        "maintenance_context": APP02MaintenanceContext.REPORTED_APPROVED,
        "maintenance_source_ref": "payment-system",
        "maintenance_source_version": "1",
        "maintenance_observed_at": AT,
        "maintenance_available_at": AT,
    }
    candidate = replace(metrics(row), **maintenance)
    assert evaluate(row, candidate)["status"] == APP02Status.MAINTENANCE_EXCEPTION.value
    assert evaluate(row, replace(candidate, payment_amount=Decimal(1)))[
        "status"
    ] == APP02Status.AMOUNT_ORDINARY.value
    assert evaluate(row, replace(candidate, payment_status=APP02PaymentStatus.FAILED))[
        "status"
    ] == APP02Status.BLOCKED_PAYMENT.value
    with pytest.raises(ScenarioContractError, match="maintenance claim"):
        evaluate(row, replace(candidate, maintenance_source_version="spoofed"))
    without = packet()
    with pytest.raises(ScenarioContractError, match="maintenance claim"):
        evaluate(without, replace(candidate, observation_digest=without.fingerprint()))


def test_payment_before_change_is_blocked_not_labelled_as_fraud() -> None:
    after_payment = AT + timedelta(seconds=1)
    row = packet(change_at=after_payment)
    candidate = replace(metrics(row), change_at=after_payment)
    result = evaluate(row, candidate)
    assert result["status"] == APP02Status.BLOCKED_CHRONOLOGY.value
    assert result["heuristic_evaluated"] is False


def test_tenant_event_version_and_source_mismatch_fail_closed() -> None:
    row = packet()
    candidate = metrics(row)
    with pytest.raises(ScenarioContractError, match="installation/tenant/dataset"):
        evaluate_app02_synthetic(
            row, policy=policy(), metrics=candidate,
            expected_installation="synthetic-install",
            expected_tenant="different-tenant", expected_dataset_digest=DATASET,
        )
    with pytest.raises(ScenarioContractError, match="identity"):
        evaluate(row, replace(candidate, payment_event_id=UUID(int=1)))
    with pytest.raises(ScenarioContractError, match="identity"):
        evaluate(row, replace(candidate, policy_version="other-policy"))
    with pytest.raises(ScenarioContractError, match="source/time"):
        evaluate(row, replace(candidate, change_source_version="spoofed"))
    with pytest.raises(ScenarioContractError, match="post-cutoff"):
        evaluate(row, replace(candidate, available_at=AT + timedelta(minutes=6)))


def test_utc_equivalence_and_input_fingerprint_mutations() -> None:
    row = packet()
    candidate = metrics(row)
    shifted = timezone(timedelta(hours=-5))
    converted = replace(
        candidate, payment_at=AT.astimezone(shifted),
        change_at=CHANGE.astimezone(shifted),
    )
    assert evaluate(row, candidate) == evaluate(row, converted)
    assert evaluate(row, candidate)["effective_input_digest"] != evaluate(
        row, replace(candidate, change_kind=APP02ChangeKind.PROFILE)
    )["effective_input_digest"]
    assert evaluate(row, candidate)["effective_input_digest"] != evaluate(
        row, candidate, replace(policy(), max_change_to_payment_seconds=301)
    )["effective_input_digest"]


@pytest.mark.parametrize("bad", [
    {"baseline_complete": 1}, {"baseline_samples": True},
    {"payment_amount": Decimal("NaN")}, {"payment_currency": "EtB"},
    {"change_kind": "device_change"}, {"payment_status": "posted"},
    {"maintenance_context": "unknown_unassessed"},
    {"available_at": datetime(2026, 11, 2, 12)},
])
def test_invalid_assertions_rejected_at_construction(bad: dict[str, object]) -> None:
    with pytest.raises(ScenarioContractError):
        replace(metrics(packet()), **bad)


def test_frozen_postconstruction_mutation_is_rechecked() -> None:
    row = packet()
    candidate = metrics(row)
    object.__setattr__(candidate, "baseline_samples", -1)
    with pytest.raises(ScenarioContractError, match="strict bounded"):
        evaluate(row, candidate)
    proposed = policy()
    object.__setattr__(proposed, "min_baseline_days", 0)
    with pytest.raises(ScenarioContractError, match="strict bounded"):
        evaluate(row, metrics(row), proposed)


def test_no_protected_runtime_imports_of_offline_app02() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "gasha"
    for path in root.rglob("*.py"):
        if path.name == "app02_synthetic.py":
            continue
        source = path.read_text(encoding="utf-8")
        assert "from gasha.poc.app02_synthetic import" not in source
        assert "import gasha.poc.app02_synthetic" not in source
        assert "evaluate_app02_synthetic(" not in source
