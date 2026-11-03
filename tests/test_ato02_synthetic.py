"""ATO-02 offline synthetic candidate: security negatives, temporal and context guards."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

from gasha.poc.ato02_synthetic import (
    ATO02AuthOutcome,
    ATO02ResetContext,
    ATO02Status,
    ATO02SyntheticMetrics,
    ATO02SyntheticPolicy,
    evaluate_ato02_synthetic,
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


def packet(*, reset: bool = False) -> ScenarioObservation:
    fields = list(SCENARIO_FIELDS[ScenarioId.ATO_02].required)
    if reset:
        fields.append("approved_device_reset")
    return ScenarioObservation(
        scenario_id=ScenarioId.ATO_02,
        installation_ref="synthetic-install", tenant_ref="synthetic-tenant",
        dataset_digest=DATASET, event_id=EVENT,
        source_system="synthetic-source", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=AT, received_at=AT, decision_cutoff=AT + timedelta(minutes=5),
        fields=tuple(FieldEvidence(
            name=name, state=FieldState.OBSERVED,
            source_ref="synthetic-source", source_version="1",
            evidence_digest="sha256:" + "b" * 64,
            observed_at=AT - timedelta(minutes=1) if name == "approved_device_reset" else AT,
            available_at=AT - timedelta(minutes=1) if name == "approved_device_reset" else AT,
        ) for name in fields),
    )


def policy() -> ATO02SyntheticPolicy:
    return ATO02SyntheticPolicy(
        version="proposed-1", configuration_version="1",
        minimum_history_days=30, maximum_new_device_age_seconds=300,
    )


def metrics(row: ScenarioObservation) -> ATO02SyntheticMetrics:
    return ATO02SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="proposed-1",
        device_ref="pseudonymous-device",
        first_seen_at=AT - timedelta(minutes=3),
        history_start=AT - timedelta(days=40), history_end=AT,
        history_complete=True, prior_device_sessions=0,
        authentication_at=AT, authentication_outcome=ATO02AuthOutcome.SUCCESS,
        session_anomalous=True, available_at=AT,
    )


def evaluate(
    row: ScenarioObservation, value: ATO02SyntheticMetrics | None,
    thresholds: ATO02SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_ato02_synthetic(
        row, policy=policy() if thresholds is None else thresholds, metrics=value,
        expected_installation="synthetic-install", expected_tenant="synthetic-tenant",
        expected_dataset_digest=DATASET,
    ).to_dict()


def test_synthetic_candidate_inclusive_first_seen_boundary_has_no_bank_authority() -> None:
    row = packet()
    case = replace(metrics(row), first_seen_at=AT - timedelta(seconds=300))
    result = evaluate(row, case)
    assert result["status"] == ATO02Status.SYNTHETIC_HYPOTHESIS.value
    assert result["heuristic_evaluated"] is True
    assert result["reasons"] == [
        "zero_prior_sessions_in_claimed_continuous_lookback",
        "first_seen_within_proposed_window",
        "session_anomaly_caller_asserted",
        "approved_reset_context_unknown_unassessed",
    ]
    assert result == evaluate(row, case)
    assert result["effective_input_digest"].startswith("sha256:")
    for field in (
        "bank_verified", "account_takeover_determined", "fraud_determined",
        "readiness_authorized", "enforcement_activated",
    ):
        assert result[field] is False
    for private_field in (
        "tenant_ref", "device_ref", "event_id", "customer_id", "authentication_at",
    ):
        assert private_field not in result


@pytest.mark.parametrize(("changes", "expected"), [
    ({"history_complete": False}, ATO02Status.BLOCKED_HISTORY),
    ({"history_start": AT - timedelta(days=29)}, ATO02Status.BLOCKED_HISTORY),
    ({"history_end": AT - timedelta(seconds=1)}, ATO02Status.BLOCKED_HISTORY),
    ({"prior_device_sessions": 1}, ATO02Status.KNOWN_DEVICE),
    ({"session_anomalous": False}, ATO02Status.ORDINARY_SESSION),
    ({"session_anomalous": None}, ATO02Status.BLOCKED_ANOMALY),
    ({"authentication_outcome": ATO02AuthOutcome.FAILED}, ATO02Status.BLOCKED_AUTH),
    ({"authentication_outcome": ATO02AuthOutcome.UNKNOWN}, ATO02Status.BLOCKED_AUTH),
    ({"authentication_outcome": ATO02AuthOutcome.CHALLENGED}, ATO02Status.BLOCKED_AUTH),
    ({"first_seen_at": AT - timedelta(seconds=301)}, ATO02Status.NOT_RECENT),
])
def test_explicit_negative_and_blocked_cases(
    changes: dict[str, object], expected: ATO02Status,
) -> None:
    row = packet()
    outcome = evaluate(row, replace(metrics(row), **changes))
    assert outcome["status"] == expected.value
    assert outcome["bank_verified"] is False


def test_required_device_history_absence_blocks_even_when_values_are_supplied() -> None:
    row = packet()
    absent = replace(
        row, fields=tuple(item for item in row.fields if item.name != "device_lookback"),
    )
    value = replace(metrics(row), observation_digest=absent.fingerprint())
    result = evaluate(absent, value)
    assert result["status"] == ATO02Status.BLOCKED_FIELDS.value
    assert "device_lookback" in result["reasons"]


def test_approved_reset_and_reenrolment_are_contextual_exclusions_not_fraud() -> None:
    row = packet(reset=True)
    for context in (
        ATO02ResetContext.APPROVED_RESET, ATO02ResetContext.APPROVED_REENROLMENT,
    ):
        value = replace(
            metrics(row), reset_context=context,
            reset_source_ref="synthetic-source", reset_source_version="1",
            reset_observed_at=AT - timedelta(minutes=1),
            reset_available_at=AT - timedelta(minutes=1),
        )
        outcome = evaluate(row, value)
        assert outcome["status"] == ATO02Status.LEGITIMATE_RESET.value
        assert outcome["fraud_determined"] is False



@pytest.mark.parametrize("reset_context", list(ATO02ResetContext))
@pytest.mark.parametrize("authentication", list(ATO02AuthOutcome))
@pytest.mark.parametrize("anomalous", [True, False, None])
@pytest.mark.parametrize("known", [True, False])
@pytest.mark.parametrize("recent", [True, False])
def test_reset_context_cannot_mask_auth_anomaly_or_base_signal_negatives(
    reset_context: ATO02ResetContext,
    authentication: ATO02AuthOutcome,
    anomalous: bool | None,
    known: bool,
    recent: bool,
) -> None:
    """144 cross-product cases enforce PO's blocker/base-signal precedence."""
    with_reset = reset_context is not ATO02ResetContext.UNKNOWN
    row = packet(reset=with_reset)
    value = replace(
        metrics(row),
        authentication_outcome=authentication,
        session_anomalous=anomalous,
        prior_device_sessions=int(known),
        first_seen_at=AT - timedelta(seconds=300 if recent else 301),
        reset_context=reset_context,
        reset_source_ref="synthetic-source" if with_reset else None,
        reset_source_version="1" if with_reset else None,
        reset_observed_at=AT - timedelta(minutes=1) if with_reset else None,
        reset_available_at=AT - timedelta(minutes=1) if with_reset else None,
    )
    outcome = evaluate(row, value)
    if authentication is not ATO02AuthOutcome.SUCCESS:
        expected = ATO02Status.BLOCKED_AUTH
    elif anomalous is None:
        expected = ATO02Status.BLOCKED_ANOMALY
    elif known:
        expected = ATO02Status.KNOWN_DEVICE
    elif anomalous is False:
        expected = ATO02Status.ORDINARY_SESSION
    elif not recent:
        expected = ATO02Status.NOT_RECENT
    elif with_reset:
        expected = ATO02Status.LEGITIMATE_RESET
    else:
        expected = ATO02Status.SYNTHETIC_HYPOTHESIS
    assert outcome["status"] == expected.value
    assert outcome["heuristic_evaluated"] is (
        expected not in {ATO02Status.BLOCKED_AUTH, ATO02Status.BLOCKED_ANOMALY}
    )
    assert outcome["bank_verified"] is False
    assert outcome["enforcement_activated"] is False


@pytest.mark.parametrize("required_name", SCENARIO_FIELDS[ScenarioId.ATO_02].required)
@pytest.mark.parametrize("arrival_delay_seconds", [0, 1])
@pytest.mark.parametrize("changes", [
    {}, {"prior_device_sessions": 1}, {"session_anomalous": False},
])
def test_required_evidence_must_precede_metrics_snapshot_even_for_negatives(
    required_name: str, arrival_delay_seconds: int, changes: dict[str, object],
) -> None:
    row = packet()
    evidence = tuple(
        replace(field, available_at=AT + timedelta(seconds=arrival_delay_seconds))
        if field.name == required_name else field
        for field in row.fields
    )
    row = replace(row, fields=evidence)
    value = replace(metrics(row), observation_digest=row.fingerprint(), **changes)
    outcome = evaluate(row, value)
    if arrival_delay_seconds:
        assert outcome["status"] == ATO02Status.BLOCKED_FIELDS.value
        assert outcome["reasons"] == [
            f"required_evidence_after_metrics_snapshot:{required_name}",
        ]
        assert outcome["heuristic_evaluated"] is False
    else:
        expected = (
            ATO02Status.KNOWN_DEVICE if changes.get("prior_device_sessions")
            else ATO02Status.ORDINARY_SESSION if changes.get("session_anomalous") is False
            else ATO02Status.SYNTHETIC_HYPOTHESIS
        )
        assert outcome["status"] == expected.value


def test_optional_reset_must_be_observed_and_source_bound() -> None:
    row = packet(reset=True)
    value = replace(
        metrics(row), reset_context=ATO02ResetContext.APPROVED_RESET,
        reset_source_ref="synthetic-source", reset_source_version="1",
        reset_observed_at=AT - timedelta(minutes=1),
        reset_available_at=AT - timedelta(minutes=1),
    )
    with pytest.raises(ScenarioContractError, match="reset claim"):
        evaluate(packet(), replace(value, observation_digest=packet().fingerprint()))
    with pytest.raises(ScenarioContractError, match="reset claim"):
        evaluate(row, replace(value, reset_source_version="wrong"))
    with pytest.raises(ScenarioContractError, match="reset claim"):
        evaluate(row, replace(value, reset_available_at=AT))


@pytest.mark.parametrize("changes", [
    {"history_complete": 1},
    {"session_anomalous": "true"},
    {"prior_device_sessions": True},
    {"authentication_outcome": "success"},
    {"reset_context": "unknown_unassessed"},
    {"authentication_at": datetime(2026, 11, 2, 12)},
    {"first_seen_at": AT + timedelta(seconds=1)},
    {"available_at": AT - timedelta(seconds=1)},
    {"reset_source_ref": "synthetic-source"},
])
def test_untyped_or_impossible_assertions_rejected(changes: dict[str, object]) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), **changes)


def test_contextual_reset_after_authentication_is_rejected() -> None:
    row = packet(reset=True)
    with pytest.raises(ScenarioContractError, match="reset not available"):
        replace(
            metrics(row), reset_context=ATO02ResetContext.APPROVED_RESET,
            reset_source_ref="synthetic-source", reset_source_version="1",
            reset_observed_at=AT, reset_available_at=AT + timedelta(seconds=1),
        )


def test_scope_event_cutoff_and_configuration_are_fail_closed() -> None:
    row = packet()
    value = metrics(row)
    with pytest.raises(ScenarioContractError, match="tenant/dataset"):
        evaluate_ato02_synthetic(
            row, policy=policy(), metrics=value, expected_installation="synthetic-install",
            expected_tenant="other-tenant", expected_dataset_digest=DATASET,
        )
    with pytest.raises(ScenarioContractError, match="version mismatch"):
        evaluate(row, replace(value, policy_version="different"))
    with pytest.raises(ScenarioContractError, match="event"):
        evaluate(row, replace(value, authentication_at=AT + timedelta(seconds=1),
                              available_at=AT + timedelta(seconds=1)))
    with pytest.raises(ScenarioContractError, match="post-cutoff"):
        evaluate(row, replace(value, available_at=AT + timedelta(minutes=6)))


def test_mutated_frozen_dataclasses_are_revalidated_at_consumption() -> None:
    row = packet()
    value = metrics(row)
    object.__setattr__(value, "prior_device_sessions", -3)
    with pytest.raises(ScenarioContractError, match="strict bounded"):
        evaluate(row, value)
    proposed = policy()
    object.__setattr__(proposed, "minimum_history_days", 0)
    with pytest.raises(ScenarioContractError, match="history"):
        evaluate_ato02_synthetic(
            row, policy=proposed, metrics=metrics(row),
            expected_installation="synthetic-install",
            expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
        )


def test_same_instant_different_offsets_give_same_effective_fingerprint() -> None:
    row = packet()
    base = metrics(row)
    shift = timezone(timedelta(hours=-5))
    converted = replace(
        base, authentication_at=AT.astimezone(shift),
        first_seen_at=base.first_seen_at.astimezone(shift),
    )
    assert evaluate(row, base) == evaluate(row, converted)


def test_effective_digest_changes_when_threshold_or_session_claim_changes() -> None:
    row = packet()
    base = evaluate(row, metrics(row))
    changed = evaluate(row, replace(metrics(row), prior_device_sessions=1))
    tighter = evaluate(row, metrics(row), replace(policy(), maximum_new_device_age_seconds=1))
    assert base["effective_input_digest"] != changed["effective_input_digest"]
    assert base["effective_input_digest"] != tighter["effective_input_digest"]


def test_synthetic_detector_is_not_imported_by_protected_or_worker_runtime() -> None:
    code_root = Path(__file__).resolve().parents[1] / "src" / "gasha"
    for path in code_root.rglob("*.py"):
        if path.name == "ato02_synthetic.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert "from gasha.poc.ato02_synthetic import" not in text
        assert "import gasha.poc.ato02_synthetic" not in text
        assert "evaluate_ato02_synthetic(" not in text
