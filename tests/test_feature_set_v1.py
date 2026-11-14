from datetime import UTC, datetime, timedelta, timezone
from dataclasses import FrozenInstanceError

import pytest

from gasha.intelligence.feature_set_v1 import FEATURE_VERSION, ObservedTransfer, compute_feature_set

T = datetime(2026, 11, 14, 12, tzinfo=UTC)


def event(
    event_id, *, tenant="synthetic-a", account="acct-a",
    beneficiary="ben-a", device="dev-a", time=T,
):
    return ObservedTransfer(tenant, event_id, account, beneficiary, device, time)


def test_point_in_time_and_inclusive_window():
    target = event("target")
    history = (
        event("one-hour", time=T - timedelta(hours=1)),
        event("within", account="acct-b", time=T - timedelta(seconds=1)),
        event("same", time=T),
        event("future", time=T + timedelta(seconds=1)),
        event("old", time=T - timedelta(days=2)),
    )
    result = compute_feature_set(target, history)
    assert result.version == FEATURE_VERSION
    assert result.account_transfers_1h == 1
    assert result.beneficiary_unique_senders_1h == 2
    assert result.distinct_accounts_on_device_1h == 2
    assert result.beneficiary_seen_before is True
    assert compute_feature_set(target, tuple(reversed(history))) == result


def test_missing_not_zero():
    result = compute_feature_set(event("target", beneficiary=None, device=None), ())
    assert result.beneficiary_unique_senders_1h is None
    assert result.beneficiary_seen_before is None
    assert result.distinct_accounts_on_device_1h is None
    assert result.missing == ("beneficiary_ref", "device_ref")


def test_history_outside_window_proves_prior_relationship_only():
    result = compute_feature_set(event("target"), (event("old", time=T - timedelta(days=7)),))
    assert result.account_transfers_1h == 0
    assert result.beneficiary_seen_before is True


def test_timezone_equivalence():
    local = T.astimezone(timezone(timedelta(hours=-5)))
    assert event("target", time=local).observed_at == T


@pytest.mark.parametrize("history", [
    (event("target"),),
    (event("other", tenant="synthetic-b"),),
])
def test_duplicate_or_cross_tenant_rejected(history):
    with pytest.raises(ValueError):
        compute_feature_set(event("target"), history)


def test_immutable_and_strict_types():
    with pytest.raises(ValueError):
        event("bad", tenant=True)
    with pytest.raises(ValueError):
        event("bad", time=T.replace(tzinfo=None))
    with pytest.raises(FrozenInstanceError):
        event("target").tenant_id = "other"
