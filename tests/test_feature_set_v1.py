from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from gasha.intelligence.feature_set_v1 import (
    FEATURE_VERSION,
    ObservedTransfer,
    compute_feature_set,
)

T = datetime(2026, 11, 14, 12, tzinfo=UTC)


def event(
    event_id,
    *,
    tenant="synthetic-a",
    account="acct-a",
    beneficiary="ben-a",
    device="dev-a",
    time=T,
    available=None,
):
    return ObservedTransfer(
        tenant, event_id, account, beneficiary, device, time,
        time if available is None else available,
    )


def compute(target, history, cutoff=T):
    return compute_feature_set(target, history, decision_as_of=cutoff)


def test_prior_only_and_inclusive_hour_boundary():
    target = event("target")
    history = (
        event("one-hour", time=T - timedelta(hours=1)),
        event("within", account="acct-b", time=T - timedelta(seconds=1)),
        event("same", time=T),
        event("future", time=T + timedelta(seconds=1)),
        event("old", time=T - timedelta(days=2)),
    )
    result = compute(target, history)
    assert result.version == FEATURE_VERSION
    assert result.account_transfers_1h == 1
    assert result.beneficiary_unique_senders_1h == 2
    assert result.distinct_accounts_on_device_1h == 2
    assert result.sender_beneficiary_seen_before is True
    assert compute(target, tuple(reversed(history))) == result
    assert len(result.source_fingerprint) == len(result.computation_fingerprint) == 64


def test_late_arrival_excluded_even_when_occurrence_is_old():
    target = event("target")
    old_late = event(
        "late", time=T - timedelta(minutes=15),
        available=T + timedelta(seconds=1),
    )
    assert compute(target, (old_late,)).account_transfers_1h == 0
    assert compute(target, (old_late,)).sender_beneficiary_seen_before is False


def test_exact_cutoff_is_included_but_after_cutoff_is_not():
    target = event("target", available=T + timedelta(minutes=1))
    past = T - timedelta(minutes=5)
    at_cutoff = event("prior", time=past, available=T + timedelta(minutes=1))
    late = event("late", time=past, available=T + timedelta(minutes=2))
    result = compute(target, (at_cutoff, late), T + timedelta(minutes=1))
    assert result.account_transfers_1h == 1
    assert result.beneficiary_unique_senders_1h == 1


def test_availability_changes_provenance_even_when_feature_values_match():
    target = event("target")
    first = event("one", time=T - timedelta(minutes=5))
    second = event("one", time=T - timedelta(minutes=5),
                   available=T - timedelta(minutes=1))
    a = compute(target, (first,))
    b = compute(target, (second,))
    assert a.account_transfers_1h == b.account_transfers_1h
    assert a.source_fingerprint != b.source_fingerprint
    assert a.computation_fingerprint != b.computation_fingerprint
    assert a.source_fingerprint == compute(target, (first,)).source_fingerprint


def test_target_account_counts_on_device_only_if_prior():
    target = event("target")
    other = event("other", account="acct-b", time=T - timedelta(minutes=5))
    own = event("own", time=T - timedelta(minutes=4))
    assert compute(target, (other,)).distinct_accounts_on_device_1h == 1
    assert compute(target, (other, own)).distinct_accounts_on_device_1h == 2


def test_missing_optional_telemetry_not_zero():
    result = compute(event("target", beneficiary=None, device=None), ())
    assert result.beneficiary_unique_senders_1h is None
    assert result.sender_beneficiary_seen_before is None
    assert result.distinct_accounts_on_device_1h is None
    assert result.missing == ("beneficiary_ref", "device_ref")


def test_old_relationship_only_not_one_hour_count():
    old = event("old", time=T - timedelta(days=7))
    result = compute(event("target"), (old,))
    assert result.account_transfers_1h == 0
    assert result.sender_beneficiary_seen_before is True


def test_timezone_equivalence_and_cutoff_identity():
    local = T.astimezone(timezone(timedelta(hours=-5)))
    assert event("target", time=local).occurred_at == T
    assert compute(event("target"), (), local) == compute(event("target"), (), T)


@pytest.mark.parametrize(
    "history",
    [
        (event("target"),),
        (event("other", tenant="synthetic-b"),),
        (event("duplicate", time=T - timedelta(seconds=1)),
         event("duplicate", time=T - timedelta(seconds=2))),
    ],
)
def test_duplicate_or_cross_tenant_rejected(history):
    with pytest.raises(ValueError):
        compute(event("target"), history)


def test_bad_temporal_order_and_unavailable_target_fail_closed():
    with pytest.raises(ValueError):
        event("bad", time=T, available=T - timedelta(seconds=1))
    with pytest.raises(ValueError):
        compute(event("target", available=T + timedelta(seconds=1)), ())
    with pytest.raises(ValueError):
        compute(event("target"), (), T - timedelta(seconds=1))


def test_immutable_and_concrete_clock_types():
    with pytest.raises(ValueError):
        event("bad", tenant=True)
    with pytest.raises(ValueError):
        event("bad", time=T.replace(tzinfo=None))
    with pytest.raises(ValueError):
        event("bad", available=T.replace(tzinfo=None))
    with pytest.raises(ValueError):
        compute(event("target"), (), "2026-11-14T12:00:00Z")
    with pytest.raises(FrozenInstanceError):
        event("target").tenant_id = "other"
