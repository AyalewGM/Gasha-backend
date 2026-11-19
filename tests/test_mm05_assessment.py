"""Offline MM-05 assessment tests; no API, fraud label, case or bank assertions."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from gasha.intelligence.mm05_activity import (
    AccountActivity,
    ActivityDirection,
    ActivityStatus,
    ActivityWindowPolicy,
    compute_mm05_activity,
)
from gasha.intelligence.mm05_assessment import (
    MM05Reason,
    MM05State,
    MM05ThresholdPolicy,
    evaluate_mm05_activity,
)

NOW = datetime(2026, 11, 19, 10, tzinfo=UTC)
DIGEST = "sha256:" + "b" * 64
WINDOW = ActivityWindowPolicy("synthetic-window-v1", 30, 24, ActivityDirection.CREDIT, 90)
POLICY = MM05ThresholdPolicy(
    "synthetic-threshold-v1", WINDOW.version,
    min_current_count=3, min_current_value=Decimal(300),
    min_count_ratio=Decimal(3), min_value_ratio=Decimal(3),
    max_low_baseline_count=2, max_low_baseline_active_days=2,
)


def entry(name: str, hours: int, amount: str = "100", *,
          account: str = "a", tenant: str = "tenant-a",
          direction: ActivityDirection = ActivityDirection.CREDIT,
          status: ActivityStatus = ActivityStatus.SETTLED,
          received_hours: int | None = None) -> AccountActivity:
    return AccountActivity(
        tenant, name, account, NOW + timedelta(hours=hours),
        NOW + timedelta(hours=hours if received_hours is None else received_hours),
        direction, status, Decimal(amount), "ETB",
    )


def assess(history: tuple[AccountActivity, ...] | None, *,
           target_amount: str = "100", opened_hours: int = -24 * 250,
           covered_hours: int = -24 * 200, cutoff_hours: int = 0,
           sealed_hours: int = 0, policy: MM05ThresholdPolicy = POLICY):
    target = entry("target", 0, target_amount)
    feature = compute_mm05_activity(
        target, history, policy=WINDOW, decision_cutoff=NOW + timedelta(hours=cutoff_hours),
        account_opened_at=NOW + timedelta(hours=opened_hours),
        history_covered_from=NOW + timedelta(hours=covered_hours),
        history_sealed_through=NOW + timedelta(hours=sealed_hours),
        dataset_digest=DIGEST, history_epoch="synthetic-epoch",
    )
    return evaluate_mm05_activity(feature, policy=policy)


def test_dormant_activation_candidate_with_explainable_lineage() -> None:
    historical = (
        entry("old", -24 * 110, "100"),
        entry("burst1", -2, "200"),
        entry("burst2", -1, "300"),
    )
    result = assess(historical, target_amount="400")
    assert result.scenario_id == "MM-05"
    assert result.state is MM05State.REVIEW_CANDIDATE
    assert result.reason_codes == (
        MM05Reason.DORMANT_CANDIDATE.value,
        MM05Reason.DORMANT_ZERO_BASELINE.value,
        MM05Reason.ABSOLUTE_MATERIALITY.value,
    )
    assert result.feature.current_count == 3
    assert result.policy_version == POLICY.version
    assert result.threshold_fingerprint.startswith("sha256:")
    assert len(result.threshold_fingerprint) == 71
    assert result.source_fingerprint == result.feature.source_fingerprint
    assert result.knowledge_cutoff == NOW


def test_low_activity_surge_candidate_with_recent_prior_activity() -> None:
    history = (
        entry("baseline", -25, "10"),
        entry("burst1", -2, "200"),
        entry("burst2", -1, "200"),
    )
    result = assess(history, target_amount="200")
    assert result.feature.baseline_count == 1
    assert result.state is MM05State.REVIEW_CANDIDATE
    assert result.reason_codes[0] == MM05Reason.LOW_ACTIVITY_BASELINE.value


def test_payroll_business_cycle_and_gradual_growth_controls_do_not_flag() -> None:
    # Stable recurring pay cycles have established baselines, not sudden
    # unexplained low-activity origins. This is a synthetic structural control,
    # not bank-verified salary or calendar provenance.
    recurring = tuple(entry(f"cycle-{i}", -25 - i * 24, "100") for i in range(8))
    recurring += (entry("recent1", -2, "100"), entry("recent2", -1, "100"))
    result = assess(recurring)
    assert result.state is MM05State.NOT_FLAGGED
    assert result.reason_codes == (MM05Reason.NOT_LOW_ACTIVITY.value,)

    # Reopening account had settled debit movement just before the window,
    # while a single credit is not material enough for a count/value surge.
    reopening = (
        entry("debit", -26, "400", direction=ActivityDirection.DEBIT),
        entry("old", -25, "100"),
    )
    assert assess(reopening).state is MM05State.NOT_FLAGGED


def test_high_count_alone_and_high_value_alone_are_not_combined_surge() -> None:
    baseline = (entry("base", -25, "1000"),)
    count_only = baseline + (
        entry("c1", -3, "100"), entry("c2", -2, "100"), entry("c3", -1, "100"),
    )
    count_result = assess(count_only, target_amount="100")
    assert count_result.state is MM05State.NOT_FLAGGED
    assert count_result.reason_codes == (MM05Reason.VALUE_SURGE_NOT_MET.value,)
    value_only = (entry("base", -25, "100"), entry("v1", -1, "3000"))
    value_result = assess(
        value_only, target_amount="3000", policy=replace(POLICY, min_current_count=2),
    )
    assert value_result.state is MM05State.NOT_FLAGGED
    assert value_result.reason_codes == (MM05Reason.COUNT_SURGE_NOT_MET.value,)


def test_zero_baseline_and_missing_history_never_imply_infinite_risk() -> None:
    assert assess(()).state is MM05State.NOT_ASSESSED
    assert assess(()).reason_codes == (MM05Reason.INSUFFICIENT_BASELINE.value,)
    unavailable = assess(None)
    assert unavailable.state is MM05State.NOT_ASSESSED
    assert unavailable.reason_codes[0] == MM05Reason.FEATURE_UNAVAILABLE.value
    partial = assess((entry("old", -25),), covered_hours=-100)
    assert partial.state is MM05State.NOT_ASSESSED
    assert partial.reason_codes[0] == MM05Reason.FEATURE_UNAVAILABLE.value


def test_replay_order_late_arrival_and_cutoff_are_deterministic() -> None:
    history = (
        entry("base", -25, "10"),
        entry("first", -2, "200"),
        entry("second", -1, "200"),
        entry("too-late", -3, "5000", received_hours=1),
    )
    first = assess(history, target_amount="200")
    assert first == assess(tuple(reversed(history)), target_amount="200",
                           cutoff_hours=3, sealed_hours=3)
    assert first.feature.current_count == 3
    assert first.state is MM05State.REVIEW_CANDIDATE


def test_threshold_content_and_arithmetic_contract_are_bound() -> None:
    feature = assess((entry("base", -25, "100"),)).feature
    a = evaluate_mm05_activity(feature, policy=POLICY)
    changed = replace(POLICY, min_current_value=Decimal(301))
    b = evaluate_mm05_activity(feature, policy=changed)
    assert a.policy_version == b.policy_version
    assert a.threshold_fingerprint != b.threshold_fingerprint
    with pytest.raises(ValueError, match="arithmetic"):
        evaluate_mm05_activity(
            replace(feature, arithmetic_version="untrusted-arithmetic"),
            policy=POLICY,
        )


def test_exact_thresholds_and_wrong_window_fail_closed() -> None:
    history = (
        entry("base", -25, "100"),
        entry("first", -2, "100"),
        entry("second", -1, "100"),
    )
    exact = assess(history, target_amount="100")
    assert exact.state is MM05State.REVIEW_CANDIDATE  # ratios 3; current value 300
    stricter = replace(POLICY, min_current_value=Decimal("300.000001"))
    assert assess(history, target_amount="100", policy=stricter).state is MM05State.NOT_FLAGGED
    with pytest.raises(ValueError, match="version mismatch"):
        assess(history, policy=replace(POLICY, window_version="different"))


@pytest.mark.parametrize("bad", [Decimal("NaN"), Decimal("Infinity"), Decimal(0),
                                 Decimal("1e1000000"), Decimal("1e-1000000")])
def test_invalid_policy_decimal_denied(bad: Decimal) -> None:
    with pytest.raises(ValueError):
        replace(POLICY, min_count_ratio=bad)


def test_broken_feature_and_wrong_tenant_denied() -> None:
    feature = assess((entry("baseline", -25),)).feature
    with pytest.raises(ValueError, match="fingerprint"):
        evaluate_mm05_activity(replace(feature, source_fingerprint="notsha"), policy=POLICY)
    with pytest.raises(ValueError, match="count"):
        evaluate_mm05_activity(replace(feature, baseline_count=True), policy=POLICY)
    with pytest.raises(ValueError, match="cross-tenant"):
        assess((entry("foreign", -1, tenant="tenant-b"),))
    with pytest.raises(ValueError, match="typed MM-05"):
        evaluate_mm05_activity(feature, policy="not-a-policy")  # type: ignore[arg-type]
