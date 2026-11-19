"""Non-authoritative MM-05 computation; no alert or enforcement assertions."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from gasha.intelligence.mm05_activity import (
    AccountActivity, ActivityDirection, ActivityStatus, ActivityWindowPolicy,
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
