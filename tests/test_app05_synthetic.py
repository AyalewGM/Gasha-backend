"""Adversarial offline APP-05 attempted-payment escalation shape regressions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.app05_synthetic import (
    APP05Attempt,
    APP05AttemptState,
    APP05RetryContext,
    APP05Status,
    APP05SyntheticPolicy,
    APP05SyntheticSequence,
    evaluate_app05_synthetic,
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
EVENT_ID = UUID("e6ecba61-e59a-4c9a-b42b-1c1c252fab35")


def packet(
    *, optional: bool = False, at: datetime = AT,
) -> ScenarioObservation:
    keys = list(SCENARIO_FIELDS[ScenarioId.APP_05].required)
    if optional:
        keys.extend(SCENARIO_FIELDS[ScenarioId.APP_05].optional)
    return ScenarioObservation(
        scenario_id=ScenarioId.APP_05, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DATASET,
        event_id=EVENT_ID, source_system="synthetic-only", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=at, received_at=at, decision_cutoff=at,
        fields=tuple(
            FieldEvidence(
                name=key, state=FieldState.OBSERVED,
                source_ref="synthetic-source", source_version="1",
                evidence_digest="sha256:" + "b" * 64,
                observed_at=at, available_at=at,
            )
            for key in keys
        ),
    )


def policy() -> APP05SyntheticPolicy:
    return APP05SyntheticPolicy(
        version="proposed-p1", configuration_version="1",
        min_attempts=3, max_window_seconds=120,
        min_step_increase=Decimal(100), min_total_multiple=Decimal(4),
    )


def sequence(row: ScenarioObservation) -> APP05SyntheticSequence:
    at = row.occurred_at
    attempts = tuple(
        APP05Attempt(
            event_id=row.event_id if index == 2 else UUID(int=100 + index),
            occurred_at=at - timedelta(minutes=2 - index),
            available_at=at - timedelta(minutes=2 - index),
            amount=Decimal(amount), currency="ETB",
            state=APP05AttemptState.ATTEMPTED,
            claimed_customer_initiated=True,
        )
        for index, amount in enumerate((100, 200, 400))
    )
    return APP05SyntheticSequence(
        observation_digest=row.fingerprint(), policy_version="proposed-p1",
        correlation_ref="synthetic-journey", sequence_complete=True,
        attempts=attempts,
    )


def evaluate(
    row: ScenarioObservation, value: APP05SyntheticSequence | None,
    thresholds: APP05SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_app05_synthetic(
        row, policy=policy() if thresholds is None else thresholds, sequence=value,
        expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).to_dict()


def test_positive_exact_boundary_requires_observed_absent_retry_context() -> None:
    row = packet(optional=True)
    value = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED_ABSENT)
    result = evaluate(row, value)
    assert result["status"] == APP05Status.SYNTHETIC_HYPOTHESIS.value
    assert result["status"] == "synthetic_repeated_or_escalating_attempts_hypothesis"
    assert result["reasons"] == ["rapid_escalating_attempts", "rapid_repeated_attempts"]
    assert result["heuristic_evaluated"] is True
    assert result == evaluate(row, value)
    for field in ("bank_verified", "fraud_determined", "readiness_authorized",
                  "enforcement_activated"):
        assert result[field] is False
    for secret in ("correlation_ref", "event_id", "attempts", "amount", "currency",
                   "tenant_ref", "customer_id", "risk_score", "hold_action"):
        assert secret not in result


def test_unknown_retry_context_needs_review_not_a_fraud_finding() -> None:
    row = packet()
    result = evaluate(row, sequence(row))
    assert result["status"] == APP05Status.RETRY_CONTEXT_REVIEW.value
    assert result["fraud_determined"] is False


def test_evidence_backed_reported_technical_retry_suppresses_only_synthetic_candidate() -> None:
    row = packet(optional=True)
    value = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED)
    result = evaluate(row, value)
    assert result["status"] == APP05Status.TECHNICAL_RETRY_REPORTED.value
    assert result["bank_verified"] is False


@pytest.mark.parametrize("context", [
    APP05RetryContext.REPORTED, APP05RetryContext.REPORTED_ABSENT,
])
@pytest.mark.parametrize("change", ["too_few", "not_rising", "outside_window"])
def test_unsubstantiated_retry_claim_never_yields_evaluated_negative(
    context: APP05RetryContext, change: str,
) -> None:
    row = packet()
    seq = sequence(row)
    if change == "too_few":
        seq = replace(seq, attempts=seq.attempts[1:])
    elif change == "not_rising":
        seq = replace(seq, attempts=(
            seq.attempts[0], replace(seq.attempts[1], amount=Decimal(100)),
            seq.attempts[2],
        ))
    else:
        seq = replace(seq, attempts=(
            replace(seq.attempts[0], occurred_at=AT - timedelta(seconds=121),
                    available_at=AT - timedelta(seconds=121)),
            seq.attempts[1], seq.attempts[2],
        ))
    with pytest.raises(ScenarioContractError, match="known retry context"):
        evaluate(row, replace(seq, technical_retry=context))


@pytest.mark.parametrize("amounts", [
    (100, 100, 400), (100, 300, 250), (100, 199, 400), (100, 200, 399),
])
def test_equal_falling_substep_or_submultiple_amounts_match_repeated_only(
    amounts: tuple[int, int, int],
) -> None:
    row = packet(optional=True)
    seq = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED_ABSENT)
    seq = replace(seq, attempts=tuple(
        replace(item, amount=Decimal(amount))
        for item, amount in zip(seq.attempts, amounts)
    ))
    outcome = evaluate(row, seq)
    assert outcome["status"] == APP05Status.SYNTHETIC_HYPOTHESIS.value
    assert outcome["status"] == "synthetic_repeated_or_escalating_attempts_hypothesis"
    assert outcome["reasons"] == ["rapid_repeated_attempts"]


@pytest.mark.parametrize("state", [
    APP05AttemptState.ABANDONED, APP05AttemptState.REVERSED,
    APP05AttemptState.TECHNICAL_FAILURE, APP05AttemptState.UNKNOWN,
])
def test_failed_abandoned_reversed_or_unknown_states_do_not_emit_hypothesis(
    state: APP05AttemptState,
) -> None:
    row = packet(optional=True)
    seq = sequence(row)
    seq = replace(
        seq, technical_retry=APP05RetryContext.REPORTED_ABSENT,
        attempts=(seq.attempts[0], replace(seq.attempts[1], state=state), seq.attempts[2]),
    )
    assert evaluate(row, seq)["status"] == APP05Status.BLOCKED_STATUS.value


def test_approved_attempts_remain_an_offline_hypothesis_only() -> None:
    row = packet(optional=True)
    seq = sequence(row)
    seq = replace(seq, technical_retry=APP05RetryContext.REPORTED_ABSENT,
                  attempts=tuple(replace(x, state=APP05AttemptState.APPROVED)
                                 for x in seq.attempts))
    assert evaluate(row, seq)["status"] == APP05Status.SYNTHETIC_HYPOTHESIS.value


def test_missing_or_incomplete_attempts_fail_closed() -> None:
    row = packet()
    assert evaluate(row, None)["status"] == APP05Status.BLOCKED_SEQUENCE.value
    assert evaluate(row, replace(sequence(row), sequence_complete=False))[
        "status"
    ] == APP05Status.BLOCKED_SEQUENCE.value


def test_missing_required_evidence_never_fabricates_zero_risk() -> None:
    row = packet()
    fields = tuple(
        FieldEvidence(
            name=item.name, state=FieldState.UNAVAILABLE, unavailable_reason="no_source"
        ) if item.name == "deduplicated_attempts" else item
        for item in row.fields
    )
    row = replace(row, fields=fields)
    assert evaluate(row, replace(sequence(packet()), observation_digest=row.fingerprint()))[
        "status"
    ] == APP05Status.BLOCKED_REQUIRED_FIELDS.value


def test_count_and_window_boundaries_are_inclusive() -> None:
    row = packet()
    value = sequence(row)
    assert evaluate(row, value)["status"] == APP05Status.RETRY_CONTEXT_REVIEW.value
    fewer = replace(value, attempts=value.attempts[1:])
    assert evaluate(row, fewer)["status"] == APP05Status.INSUFFICIENT_ATTEMPTS.value
    outside = replace(value, attempts=(
        replace(value.attempts[0], occurred_at=AT - timedelta(seconds=121),
                available_at=AT - timedelta(seconds=121)),
        *value.attempts[1:],
    ))
    assert evaluate(row, outside)["status"] == APP05Status.OUTSIDE_WINDOW.value


def test_order_independent_for_same_correlated_attempt_set() -> None:
    row = packet()
    value = sequence(row)
    shuffled = replace(value, attempts=value.attempts[::-1])
    assert evaluate(row, value) == evaluate(row, shuffled)


def test_duplicate_event_and_ambiguous_same_timestamp_rejected_or_blocked() -> None:
    row = packet()
    value = sequence(row)
    with pytest.raises(ScenarioContractError, match="duplicate"):
        replace(value, attempts=(value.attempts[0], value.attempts[0], value.attempts[2]))
    tied = replace(value, attempts=(
        value.attempts[0],
        replace(value.attempts[1], occurred_at=value.attempts[0].occurred_at,
                available_at=value.attempts[0].occurred_at),
        value.attempts[2],
    ))
    assert evaluate(row, tied)["status"] == APP05Status.BLOCKED_SEQUENCE.value


def test_mixed_currency_is_blocked_without_fake_fx_conversion() -> None:
    row = packet()
    value = sequence(row)
    mixed = replace(value, attempts=(
        value.attempts[0], replace(value.attempts[1], currency="USD"), value.attempts[2],
    ))
    assert evaluate(row, mixed)["status"] == APP05Status.BLOCKED_CURRENCY.value


def test_scope_dataset_policy_and_fingerprint_substitution_are_rejected() -> None:
    row = packet()
    value = sequence(row)
    with pytest.raises(ScenarioContractError, match="installation/tenant/dataset"):
        evaluate_app05_synthetic(
            row, policy=policy(), sequence=value,
            expected_installation="synthetic-install",
            expected_tenant="another-tenant", expected_dataset_digest=DATASET,
        )
    with pytest.raises(ScenarioContractError, match="version mismatch"):
        evaluate(row, replace(value, policy_version="other"))
    with pytest.raises(ScenarioContractError, match="version mismatch"):
        evaluate(row, replace(value, observation_digest="sha256:" + "0" * 64))
    with pytest.raises(ScenarioContractError, match="version mismatch"):
        evaluate(row, value, replace(policy(), configuration_version="other"))


def test_post_cutoff_late_attempt_rejected_not_assumed_available() -> None:
    row = packet()
    value = sequence(row)
    altered = replace(value, attempts=(
        replace(value.attempts[0], available_at=AT + timedelta(seconds=1)),
        *value.attempts[1:],
    ))
    with pytest.raises(ScenarioContractError, match="post-cutoff"):
        evaluate(row, altered)


def test_wrong_event_identity_rejected_even_at_matching_timestamp() -> None:
    row = packet()
    value = sequence(row)
    changed = replace(value, attempts=(
        *value.attempts[:-1], replace(value.attempts[-1], event_id=UUID(int=999)),
    ))
    with pytest.raises(ScenarioContractError, match="wrong-event"):
        evaluate(row, changed)


def test_wrong_event_sequence_endpoint_rejected() -> None:
    row = packet()
    value = sequence(row)
    altered = replace(value, attempts=(
        value.attempts[0], value.attempts[1],
        replace(value.attempts[2], occurred_at=AT - timedelta(seconds=1),
                available_at=AT - timedelta(seconds=1)),
    ))
    with pytest.raises(ScenarioContractError, match="wrong-event"):
        evaluate(row, altered)


def test_different_offset_and_dst_fold_compare_utc_instants() -> None:
    zone = ZoneInfo("America/New_York")
    last = datetime(2026, 11, 1, 1, 45, tzinfo=zone, fold=1)
    row = packet(optional=True, at=last)
    seq = sequence(row)
    amounts = seq.attempts
    moved = replace(seq, technical_retry=APP05RetryContext.REPORTED_ABSENT,
                    attempts=(
                        replace(amounts[0],
                                occurred_at=datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=0),
                                available_at=datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=0)),
                        replace(amounts[1],
                                occurred_at=datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0),
                                available_at=datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)),
                        replace(amounts[2], occurred_at=last, available_at=last),
                    ))
    window = replace(policy(), max_window_seconds=5400)
    assert evaluate(row, moved, window)["status"] == APP05Status.SYNTHETIC_HYPOTHESIS.value
    assert evaluate(row, moved)["status"] == APP05Status.OUTSIDE_WINDOW.value


@pytest.mark.parametrize("invalid", [True, 1, "3", -1, 1001])
def test_strict_policy_counts(invalid: object) -> None:
    with pytest.raises(ScenarioContractError):
        replace(policy(), min_attempts=invalid)  # type: ignore[arg-type]


@pytest.mark.parametrize("invalid", [float("nan"), 100, Decimal("NaN"),
                                     Decimal("Infinity"), Decimal(-1)])
def test_strict_attempt_amounts(invalid: object) -> None:
    row = packet()
    item = sequence(row).attempts[0]
    with pytest.raises(ScenarioContractError):
        replace(item, amount=invalid)  # type: ignore[arg-type]


def test_mutated_frozen_attempt_and_sequence_cannot_bypass_consumption_checks() -> None:
    row = packet()
    value = sequence(row)
    object.__setattr__(value.attempts[1], "amount", Decimal("NaN"))
    with pytest.raises(ScenarioContractError):
        evaluate(row, value)

    value = sequence(row)
    object.__setattr__(value, "attempts", [*value.attempts])
    with pytest.raises(ScenarioContractError):
        evaluate(row, value)

    value = sequence(row)
    object.__setattr__(value, "technical_retry", "reported_absent")
    with pytest.raises(ScenarioContractError):
        evaluate(row, value)


def test_no_operational_imports_or_readiness_wiring() -> None:
    root = Path(__file__).resolve().parents[1]
    for path in (
        "src/gasha/api/main.py",
        "src/gasha/worker.py",
        "src/gasha/poc/readiness.py",
    ):
        source = (root / path).read_text()
        assert "gasha.poc.app05_synthetic" not in source
        assert "evaluate_app05_synthetic" not in source


@pytest.mark.parametrize("state", [
    APP05AttemptState.ATTEMPTED, APP05AttemptState.APPROVED,
    APP05AttemptState.DECLINED,
])
@pytest.mark.parametrize("intent", [None, False])
def test_missing_or_negative_customer_initiation_blocks_all_eligible_states(
    state: APP05AttemptState, intent: bool | None,
) -> None:
    row = packet(optional=True)
    seq = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED_ABSENT)
    attempts = (
        replace(seq.attempts[0], state=state, claimed_customer_initiated=intent),
        *seq.attempts[1:],
    )
    assert evaluate(row, replace(seq, attempts=attempts))[
        "status"
    ] == APP05Status.BLOCKED_STATUS.value


def test_claimed_customer_declines_then_approval_match_escalating_and_repeated() -> None:
    row = packet(optional=True)
    seq = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED_ABSENT)
    attempts = (
        replace(seq.attempts[0], state=APP05AttemptState.DECLINED),
        replace(seq.attempts[1], state=APP05AttemptState.DECLINED),
        replace(seq.attempts[2], state=APP05AttemptState.APPROVED),
    )
    outcome = evaluate(row, replace(seq, attempts=attempts))
    assert outcome["status"] == APP05Status.SYNTHETIC_HYPOTHESIS.value
    assert outcome["reasons"] == ["rapid_escalating_attempts", "rapid_repeated_attempts"]
    assert outcome["fraud_determined"] is False


@pytest.mark.parametrize("state", [
    APP05AttemptState.TECHNICAL_FAILURE, APP05AttemptState.REVERSED,
    APP05AttemptState.UNKNOWN, APP05AttemptState.ABANDONED,
])
def test_all_ineligible_status_attempts_block(
    state: APP05AttemptState,
) -> None:
    row = packet(optional=True)
    seq = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED_ABSENT)
    attempts = tuple(replace(item, state=state) for item in seq.attempts)
    assert evaluate(row, replace(seq, attempts=attempts))[
        "status"
    ] == APP05Status.BLOCKED_STATUS.value


@pytest.mark.parametrize("context", [
    APP05RetryContext.REPORTED, APP05RetryContext.REPORTED_ABSENT,
])
@pytest.mark.parametrize("amounts", [
    (100, 100, 100), (200, 100, 150), (100, 200, 400),
])
def test_unsupported_retry_context_rejected_before_both_pattern_paths(
    context: APP05RetryContext, amounts: tuple[int, int, int],
) -> None:
    row = packet()
    seq = sequence(row)
    attempts = tuple(
        replace(item, amount=Decimal(amount))
        for item, amount in zip(seq.attempts, amounts)
    )
    with pytest.raises(ScenarioContractError, match="known retry context"):
        evaluate(row, replace(seq, attempts=attempts, technical_retry=context))


@pytest.mark.parametrize("amounts,expected_reasons", [
    ((100, 100, 100), ["rapid_repeated_attempts"]),
    ((200, 100, 150), ["rapid_repeated_attempts"]),
    ((100, 200, 400), ["rapid_escalating_attempts", "rapid_repeated_attempts"]),
])
def test_pattern_determinism_100_repeated_fixtures(
    amounts: tuple[int, int, int], expected_reasons: list[str],
) -> None:
    row = packet(optional=True)
    seq = replace(sequence(row), technical_retry=APP05RetryContext.REPORTED_ABSENT)
    attempts = tuple(
        replace(item, amount=Decimal(amount))
        for item, amount in zip(seq.attempts, amounts)
    )
    candidate = replace(seq, attempts=attempts)
    first = evaluate(row, candidate)
    assert first["reasons"] == expected_reasons
    assert first["status"] == APP05Status.SYNTHETIC_HYPOTHESIS.value
    assert first["status"] == "synthetic_repeated_or_escalating_attempts_hypothesis"
    for _ in range(100):
        assert evaluate(row, candidate) == first


def test_mutated_customer_initiation_claim_rejected_on_consumption() -> None:
    row = packet()
    seq = sequence(row)
    object.__setattr__(seq.attempts[0], "claimed_customer_initiated", "yes")
    with pytest.raises(ScenarioContractError, match="customer-initiation"):
        evaluate(row, seq)
