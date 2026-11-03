"""Synthetic MM-02 common-beneficiary window regression; no Bank event source."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.mm02_synthetic import (
    MM02Context, MM02Institution, MM02Status, MM02SyntheticMetrics,
    MM02SyntheticPolicy, MM02Transfer, MM02TransferStatus, evaluate_mm02_synthetic,
)
from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS, FieldEvidence, FieldState, ScenarioContractError,
    ScenarioId, ScenarioObservation,
)

AT = datetime(2026, 11, 3, 12, tzinfo=UTC)
EVENT = UUID("77777777-7777-4777-8777-777777777777")
DATASET = "sha256:" + "a" * 64


def packet(*, contexts: bool = False) -> ScenarioObservation:
    names = list(SCENARIO_FIELDS[ScenarioId.MM_02].required)
    if contexts:
        names.extend(SCENARIO_FIELDS[ScenarioId.MM_02].optional)
    return ScenarioObservation(
        scenario_id=ScenarioId.MM_02, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DATASET,
        event_id=EVENT, source_system="synthetic-only", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=AT, received_at=AT, decision_cutoff=AT,
        fields=tuple(FieldEvidence(
            name=name, state=FieldState.OBSERVED, source_ref="synthetic-ledger",
            source_version="1", evidence_digest="sha256:" + "b" * 64,
            observed_at=AT, available_at=AT,
        ) for name in names),
    )


def policy() -> MM02SyntheticPolicy:
    return MM02SyntheticPolicy("synthetic-p1", "1", 3600, 3)


def transfer(
    sender: str, *, event: str = "other", time: datetime = AT,
    beneficiary: str = "common", status: MM02TransferStatus = MM02TransferStatus.SETTLED,
) -> MM02Transfer:
    return MM02Transfer(
        event_ref=event, sender_ref=sender, beneficiary_ref=beneficiary,
        status=status, occurred_at=time, available_at=AT,
        source_ref="synthetic-ledger", source_version="1",
        evidence_digest="sha256:" + "c" * 64,
    )


def metrics(row: ScenarioObservation) -> MM02SyntheticMetrics:
    return MM02SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="synthetic-p1",
        installation_ref="synthetic-install", tenant_ref="synthetic-tenant",
        dataset_digest=DATASET, beneficiary_ref="common",
        window_start=AT - timedelta(hours=1), window_end=AT, available_at=AT,
        window_complete=True, deduplicated_event_set=True,
        external_institution=MM02Institution.EXTERNAL,
        transfers=(
            transfer("sender-a", event=str(EVENT)),
            transfer("sender-b", event="two", time=AT - timedelta(minutes=20)),
            transfer("sender-c", event="three", time=AT - timedelta(hours=1)),
        ),
    )


def evaluate(row: ScenarioObservation, value: MM02SyntheticMetrics | None,
             rule: MM02SyntheticPolicy | None = None) -> dict[str, object]:
    return evaluate_mm02_synthetic(
        row, policy=policy() if rule is None else rule, metrics=value,
        expected_installation="synthetic-install", expected_tenant="synthetic-tenant",
        expected_dataset_digest=DATASET,
    ).to_dict()


def test_unknown_context_requires_review_not_hypothesis() -> None:
    row = packet()
    output = evaluate(row, metrics(row))
    assert output["status"] == MM02Status.CONTEXT_REVIEW_REQUIRED.value
    assert output["contributing_event_refs"] == []
    for name in ("bank_verified", "fraud_determined", "funds_traced",
                 "readiness_authorized", "enforcement_activated"):
        assert output[name] is False
    for forbidden in ("risk_score", "customer_id", "sender_ref", "beneficiary_ref",
                      "payment_action", "prevented_loss"):
        assert forbidden not in output


def test_three_unique_confirmed_senders_yield_only_synthetic_hypothesis() -> None:
    row = packet(contexts=True)
    values = replace(metrics(row), sender_baseline=MM02Context.REPORTED_ABSENT,
                     payroll_merchant_exclusion=MM02Context.REPORTED_ABSENT)
    output = evaluate(row, values)
    assert output["status"] == MM02Status.SYNTHETIC_FAN_IN_HYPOTHESIS.value
    assert output["contributing_event_refs"] == ["three", "two", str(EVENT)]


@pytest.mark.parametrize("context", ["sender_baseline", "payroll_merchant_exclusion"])
def test_known_payroll_merchant_or_routine_baseline_excludes(context: str) -> None:
    row = packet(contexts=True)
    values = replace(metrics(row), **{context: MM02Context.REPORTED})
    assert evaluate(row, values)["status"] == MM02Status.CONTEXT_EXCLUSION_REPORTED.value


@pytest.mark.parametrize("context", ["sender_baseline", "payroll_merchant_exclusion"])
def test_optional_context_claim_without_observation_rejected(context: str) -> None:
    row = packet()
    values = replace(metrics(row), **{context: MM02Context.REPORTED_ABSENT})
    with pytest.raises(ScenarioContractError, match="without observed"):
        evaluate(row, values)


def test_unique_sender_threshold_boundary_and_retries() -> None:
    row = packet(contexts=True)
    values = replace(metrics(row), sender_baseline=MM02Context.REPORTED_ABSENT,
                     payroll_merchant_exclusion=MM02Context.REPORTED_ABSENT)
    assert evaluate(row, replace(values, transfers=values.transfers[:2]))[
        "status"
    ] == MM02Status.BELOW_UNIQUE_SENDER_THRESHOLD.value
    assert evaluate(row, replace(values, transfers=values.transfers + (
        values.transfers[1], transfer("sender-a", event="repeat-same-sender"),
    )))["status"] == MM02Status.SYNTHETIC_FAN_IN_HYPOTHESIS.value
    assert evaluate(row, values, replace(policy(), min_unique_senders=4))[
        "status"
    ] == MM02Status.BELOW_UNIQUE_SENDER_THRESHOLD.value


@pytest.mark.parametrize("status", [
    MM02TransferStatus.FAILED, MM02TransferStatus.REVERSED, MM02TransferStatus.PENDING,
])
def test_failed_reversed_pending_not_contributing(status: MM02TransferStatus) -> None:
    row = packet(contexts=True)
    values = metrics(row)
    revised = replace(values.transfers[2], status=status)
    assert evaluate(row, replace(values, transfers=values.transfers[:2] + (revised,)))[
        "status"
    ] == MM02Status.BELOW_UNIQUE_SENDER_THRESHOLD.value
    revised_target = replace(values.transfers[0], status=status)
    assert evaluate(row, replace(values, transfers=(revised_target,) +
                                 values.transfers[1:]))[
        "status"
    ] == MM02Status.BLOCKED_TARGET_STATUS.value


def test_conflicting_duplicate_event_rejected() -> None:
    row = packet()
    value = metrics(row)
    with pytest.raises(ScenarioContractError, match="conflicting duplicate"):
        evaluate(row, replace(value, transfers=value.transfers + (
            replace(value.transfers[1], sender_ref="different"),
        )))


def test_out_of_window_or_different_beneficiary_not_counted() -> None:
    row = packet()
    value = metrics(row)
    outside = replace(value.transfers[2],
                      occurred_at=AT - timedelta(hours=1, seconds=1))
    assert evaluate(row, replace(value, transfers=value.transfers[:2] + (outside,)))[
        "status"
    ] == MM02Status.BELOW_UNIQUE_SENDER_THRESHOLD.value
    changed = replace(value.transfers[2], beneficiary_ref="other-beneficiary")
    assert evaluate(row, replace(value, transfers=value.transfers[:2] + (changed,)))[
        "status"
    ] == MM02Status.BELOW_UNIQUE_SENDER_THRESHOLD.value


@pytest.mark.parametrize("change,status", [
    ({"window_complete": False}, MM02Status.BLOCKED_WINDOW),
    ({"deduplicated_event_set": False}, MM02Status.BLOCKED_WINDOW),
    ({"external_institution": MM02Institution.UNKNOWN}, MM02Status.BLOCKED_INSTITUTION),
])
def test_incomplete_required_window_fails_closed(
    change: dict[str, object], status: MM02Status,
) -> None:
    row = packet()
    assert evaluate(row, replace(metrics(row), **change))["status"] == status.value


def test_missing_required_metrics_policy_and_tenant_scope() -> None:
    row = packet()
    missing = replace(row, fields=tuple(
        f for f in row.fields if f.name != "deduplicated_event_set"
    ))
    assert evaluate(missing, None)["status"] == MM02Status.BLOCKED_REQUIRED_FIELDS.value
    assert evaluate(row, None)["status"] == MM02Status.BLOCKED_METRICS.value
    assert evaluate_mm02_synthetic(
        row, policy=None, metrics=None, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).status == MM02Status.BLOCKED_POLICY
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate(row, replace(metrics(row), tenant_ref="other-tenant"))


def test_temporal_target_and_post_cutoff_evidence_rejected() -> None:
    row = packet()
    values = metrics(row)
    with pytest.raises(ScenarioContractError, match="late transfer"):
        evaluate(row, replace(values, transfers=values.transfers + (
            replace(values.transfers[1], event_ref="later",
                    available_at=AT + timedelta(seconds=1)),
        )))
    with pytest.raises(ScenarioContractError, match="target event"):
        evaluate(row, replace(values, transfers=values.transfers[1:]))
    with pytest.raises(ScenarioContractError, match="incorrect window"):
        evaluate(row, replace(values, window_start=AT - timedelta(seconds=3601)))


def test_input_order_and_timezone_are_deterministic() -> None:
    row = packet(contexts=True)
    values = replace(metrics(row), sender_baseline=MM02Context.REPORTED_ABSENT,
                     payroll_merchant_exclusion=MM02Context.REPORTED_ABSENT)
    expected = evaluate(row, values)
    assert evaluate(row, replace(values, transfers=tuple(reversed(values.transfers)))) == expected
    zone = ZoneInfo("America/New_York")
    local = replace(values.transfers[2],
                    occurred_at=values.transfers[2].occurred_at.astimezone(zone))
    assert evaluate(row, replace(values, transfers=values.transfers[:2] + (local,))) == expected


@pytest.mark.parametrize("attr,value", [
    ("window_complete", 1), ("external_institution", "external"),
    ("deduplicated_event_set", "yes"), ("transfers", []),
])
def test_invalid_shapes_rejected(attr: str, value: object) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), **{attr: value})


def test_mutated_frozen_inputs_are_revalidated() -> None:
    row = packet()
    values = metrics(row)
    object.__setattr__(values.transfers[1], "status", "settled")
    with pytest.raises(ScenarioContractError):
        evaluate(row, values)
    rule = policy()
    object.__setattr__(rule, "min_unique_senders", True)
    with pytest.raises(ScenarioContractError):
        evaluate(row, metrics(row), rule)


@pytest.mark.parametrize("path", [
    "src/gasha/api/main.py", "src/gasha/worker.py",
    "src/gasha/decision/service.py", "src/gasha/poc/readiness.py",
])
def test_no_operational_or_readiness_wiring(path: str) -> None:
    assert "mm02_synthetic" not in Path(path).read_text(encoding="utf-8")
