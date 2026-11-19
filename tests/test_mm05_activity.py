"""Non-authoritative MM-05 computation; no alert or enforcement assertions."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from gasha.intelligence.mm05_activity import (
    AccountActivity,
    ActivityDirection,
    ActivityStatus,
    DormancyAssessment,
    ActivityWindowPolicy,
    compute_mm05_activity,
)

T = datetime(2026, 11, 19, 10, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def event(name="target", *, tenant="a", account="x", hours=0, available_hours=None,
          amount="100", currency="ETB", status=ActivityStatus.SETTLED,
          direction=ActivityDirection.CREDIT):
    time = T + timedelta(hours=hours)
    arrival = time if available_hours is None else T + timedelta(hours=available_hours)
    return AccountActivity(tenant, name, account, time, arrival, direction, status,
                           Decimal(amount), currency)


def compute(history=(), *, target=None, opened=-900, covered=-800, sealed=0, cutoff=0,
            policy=None, dataset=DIGEST, epoch="epoch-1"):
    return compute_mm05_activity(
        event() if target is None else target, history,
        policy=policy or ActivityWindowPolicy("v1", baseline_days=30,
                current_hours=24, direction=ActivityDirection.CREDIT),
        decision_cutoff=T + timedelta(hours=cutoff),
        account_opened_at=None if opened is None else T + timedelta(hours=opened),
        history_covered_from=None if covered is None else T + timedelta(hours=covered),
        history_sealed_through=None if sealed is None else T + timedelta(hours=sealed),
        dataset_digest=dataset, history_epoch=epoch,
    )


def test_computed_baseline_and_burst_prior_only_with_inclusive_window_boundary():
    history = (
        event("baseline", hours=-25, amount="10"),
        event("current-boundary", hours=-24, amount="40"),
        event("within", hours=-1, amount="50"),
        event("same-timestamp", hours=0, amount="999"),
        event("future", hours=1, amount="999"),
        event("late", hours=-3, available_hours=1, amount="999"),
        event("failed", hours=-2, status=ActivityStatus.FAILED),
        event("reverse", hours=-2, status=ActivityStatus.REVERSED),
        event("wrong-account", hours=-2, account="z"),
    )
    result = compute(history)
    assert result.available and result.unavailable_reason is None
    assert (result.baseline_count, result.current_count) == (1, 3)
    assert (result.baseline_value, result.current_value) == (Decimal(10), Decimal(190))
    assert result.count_ratio == 3
    assert result.value_ratio == 19
    assert result.last_baseline_activity_age_hours == 25
    assert compute(tuple(reversed(history))) == result


def test_history_incomplete_and_new_account_fail_as_unavailable_not_zero():
    for kwargs, reason in (
        ({"opened": -100}, "account_too_new"),
        ({"covered": -700}, "history_incomplete"),
        ({"sealed": -1}, "history_incomplete"),
        ({"covered": None}, "history_coverage_unverified"),
        ({"opened": None}, "history_coverage_unverified"),
    ):
        res = compute(**kwargs)
        assert not res.available and res.unavailable_reason == reason
        assert res.baseline_count is res.current_value is res.count_ratio is None
    assert compute(None).unavailable_reason == "history_store_unavailable"
    assert compute(None).source_fingerprint != compute(()).source_fingerprint


def test_complete_zero_baseline_has_undefined_ratios_without_division_inflation():
    res = compute()
    assert res.available and res.baseline_count == 0 and res.current_count == 1
    assert res.baseline_value == 0 and res.current_value == 100
    assert res.count_ratio is None and res.value_ratio is None
    assert res.last_baseline_activity_age_hours is None


def test_mixed_currencies_and_nonqualifying_target_unavailable():
    assert compute((event("old", hours=-25, currency="USD"),)).unavailable_reason == (
        "mixed_currency_no_approved_fx"
    )
    assert compute(target=event(status=ActivityStatus.REVERSED)).unavailable_reason == (
        "target_not_qualifying"
    )
    assert compute(target=event(direction=ActivityDirection.DEBIT)).unavailable_reason == (
        "target_not_qualifying"
    )


def test_tenant_collision_duplication_and_corrupt_runtime_objects_are_denied():
    with pytest.raises(ValueError, match="cross-tenant"):
        compute((event("another", tenant="b", hours=-1),))
    with pytest.raises(ValueError, match="duplicate"):
        compute((event("duplicate", hours=-2), event("duplicate", hours=-1)))
    with pytest.raises(ValueError, match="duplicate"):
        compute((event("target", hours=-1),))
    damaged = event("damaged", hours=-1)
    object.__setattr__(damaged, "tenant_id", ["a"])
    with pytest.raises(ValueError, match="reference"):
        compute((damaged,))


def test_point_in_time_late_arrival_not_leaked_and_fingerprint_differentiates():
    prior = event("prior", hours=-1)
    late = replace(prior, available_at=T + timedelta(seconds=1))
    a = compute((prior,))
    b = compute((late,))
    assert a.current_count == 2 and b.current_count == 1
    assert a.source_fingerprint != b.source_fingerprint
    assert compute((prior,), dataset="sha256:" + "b" * 64).source_fingerprint != a.source_fingerprint
    assert compute((prior,), epoch="epoch-2").source_fingerprint != a.source_fingerprint
    assert compute((prior,), cutoff=1).source_fingerprint != a.source_fingerprint


def test_timezones_strict_types_and_negative_clocks():
    local = T.astimezone(timezone(timedelta(hours=-5)))
    assert compute(target=event()) == compute(target=replace(event(), occurred_at=local))
    with pytest.raises(ValueError, match="unavailable"):
        compute(target=event(available_hours=1))
    with pytest.raises(ValueError, match="datetime"):
        compute_mm05_activity(
            event(), (), policy=ActivityWindowPolicy("v1", 30, 24, ActivityDirection.CREDIT),
            decision_cutoff="2026-11-19", account_opened_at=T - timedelta(days=50),
            history_covered_from=T - timedelta(days=40), history_sealed_through=T,
            dataset_digest=DIGEST, history_epoch="epoch-1",
        )
    with pytest.raises(ValueError, match="amount"):
        event(amount="NaN")
    with pytest.raises(ValueError, match="amount"):
        event(amount="0")
    with pytest.raises(ValueError, match="typed"):
        event(direction="credit")
    with pytest.raises(ValueError, match="range"):
        compute(policy=ActivityWindowPolicy("x", 1, 0, ActivityDirection.CREDIT))


def test_canonical_money_budget_rejects_amplification_before_fingerprint():
    # Short exponent notation must never amplify into million-byte output.
    for candidate in ("1e-1000000", "1e-100000000", "1e1000000",
                      "0.0000001", "9" * 65):
        with pytest.raises(ValueError, match="amount"):
            event(amount=candidate)
    assert compute((event("ok", hours=-1, amount="1.2300000000000000"),)).source_fingerprint == (
        compute((event("ok", hours=-1, amount="1.23"),)).source_fingerprint
    )
    assert compute((event("ok", hours=-1, amount="1E-6"),)).current_value == Decimal("100.000001")
    with pytest.raises(ValueError, match="amount"):
        compute((event("ok", hours=-1, amount="1.0000001"),))
    # Unavailable-history path must not accept a forged over-budget target.
    corrupted = event()
    object.__setattr__(corrupted, "amount", Decimal("1e-1000000"))
    with pytest.raises(ValueError, match="amount"):
        compute(None, target=corrupted)


def test_dormancy_beyond_baseline_partial_history_and_exact_threshold():
    policy = ActivityWindowPolicy("d90", 30, 24, ActivityDirection.CREDIT, dormancy_days=90)
    full = {"opened": -24 * 250, "covered": -24 * 200, "policy": policy}
    old = compute((event("old", hours=-24 * 100),), **full)
    assert old.available
    assert old.last_baseline_activity_age_hours is None
    assert old.last_pre_current_activity_age_hours == 24 * 100
    assert old.dormancy_assessment is DormancyAssessment.DORMANT_CANDIDATE
    recent = compute((event("recent", hours=-24 * 60),), **full)
    assert recent.last_pre_current_activity_age_hours == 24 * 60
    assert recent.dormancy_assessment is DormancyAssessment.RECENT_ACTIVITY
    edge = compute((event("edge", hours=-24 * 91),), **full)
    assert edge.dormancy_assessment is DormancyAssessment.DORMANT_CANDIDATE
    after = compute((event("after", hours=-24 * 91 + 1),), **full)
    assert after.dormancy_assessment is DormancyAssessment.RECENT_ACTIVITY
    quiet = compute((), **full)
    assert quiet.dormancy_assessment is DormancyAssessment.DORMANT_CANDIDATE
    assert quiet.last_pre_current_activity_age_hours is None
    partial = compute(())
    assert partial.available and partial.dormancy_assessment is (
        DormancyAssessment.HISTORY_INSUFFICIENT
    )
    assert compute(opened=-100).dormancy_assessment is DormancyAssessment.HISTORY_INSUFFICIENT
    assert compute((), policy=ActivityWindowPolicy("d30", 30, 24,
                     ActivityDirection.CREDIT, dormancy_days=30)).source_fingerprint != (
        compute((), policy=policy).source_fingerprint
    )


def test_dormancy_excludes_failed_reversals_and_uses_both_settled_directions():
    policy = ActivityWindowPolicy("d90", 30, 24, ActivityDirection.CREDIT, dormancy_days=90)
    args = {"opened": -24 * 250, "covered": -24 * 200, "policy": policy}
    events = (
        event("debit", hours=-24 * 2, direction=ActivityDirection.DEBIT),
        event("failed", hours=-24, status=ActivityStatus.FAILED),
        event("reversed", hours=-24, status=ActivityStatus.REVERSED),
    )
    result = compute(events, **args)
    assert result.dormancy_assessment is DormancyAssessment.RECENT_ACTIVITY
    assert result.last_pre_current_activity_age_hours == 48
    assert result.baseline_count == 0
    assert compute(tuple(reversed(events)), **args) == result


def test_bounded_maximum_4096_history_rows_and_excess_rejected():
    history = tuple(event(f"bulk-{i}", hours=-100 - i, account="another")
                    for i in range(4096))
    result = compute(history)
    assert result.available and result.baseline_count == 0
    assert len(result.source_fingerprint) == 71
    with pytest.raises(ValueError, match="bounded immutable"):
        compute(history + (event("bulk-extra", hours=-1, account="another"),))
