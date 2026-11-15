from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic, sleep
from uuid import uuid4

import pytest

from gasha.intelligence.feature_set_v1 import ObservedTransfer, compute_feature_set
from gasha.intelligence.redis_feature_history import FeatureHistoryUnavailable, RedisFeatureHistory

NOW = datetime(2026, 11, 15, tzinfo=UTC)
REDIS_URL = os.environ.get("GASHA_TEST_REDIS_URL")


@pytest.fixture
def redis_client():
    if not REDIS_URL:
        pytest.skip("GASHA_TEST_REDIS_URL not set")
    from redis import Redis

    with Redis.from_url(REDIS_URL, socket_timeout=2, socket_connect_timeout=2) as client:
        assert client.ping()
        yield client


def observation(event_id, *, time=NOW, availability=None, tenant="synthetic-a", account="a"):
    return ObservedTransfer(tenant, event_id, account, "beneficiary", "device", time, availability or time)


def test_watermark_preserves_point_in_time_replay_and_immutable_dedup(redis_client):
    history = RedisFeatureHistory(redis_client, tenant_id="synthetic-a", epoch=uuid4().hex)
    history.open_epoch(covered_from=NOW - timedelta(hours=1), ttl_seconds=10)
    target = observation("target")
    boundary = observation("boundary", time=NOW - timedelta(hours=1))
    exact = observation("exact", time=NOW - timedelta(minutes=1), availability=NOW, account="b")
    late = observation("late", time=NOW - timedelta(minutes=2), availability=NOW + timedelta(seconds=1))
    same = observation("same", time=NOW)
    with ThreadPoolExecutor(max_workers=4) as workers:
        added = list(workers.map(history.append, (boundary,) * 4))
    assert sum(added) == 1
    for event in (exact, late, same, target):
        assert history.append(event)
    history.seal(available_through=NOW)
    assert not history.append(boundary)
    with pytest.raises(FeatureHistoryUnavailable, match="immutable"):
        history.append(replace(boundary, account_ref="forged"))
    with pytest.raises(FeatureHistoryUnavailable, match="coverage"):
        history.append(observation("before-coverage", time=NOW - timedelta(hours=2)))
    with pytest.raises(FeatureHistoryUnavailable, match="coverage"):
        history.seal(available_through=NOW - timedelta(seconds=1))
    with pytest.raises(FeatureHistoryUnavailable, match="target conflicts"):
        history.compute(replace(target, account_ref="different"), decision_as_of=NOW)

    first = history.compute(target, decision_as_of=NOW)
    assert first == compute_feature_set(target, (boundary, exact, late, same), decision_as_of=NOW)
    later = NOW + timedelta(seconds=1)
    history.seal(available_through=later)
    assert history.compute(target, decision_as_of=NOW) == first
    assert history.compute(target, decision_as_of=later).account_transfers_1h == 2


def test_tenant_isolation_and_prior_relationship_coverage(redis_client):
    epoch = uuid4().hex
    a = RedisFeatureHistory(redis_client, tenant_id="synthetic-a", epoch=epoch)
    b = RedisFeatureHistory(redis_client, tenant_id="synthetic-b", epoch=epoch)
    for store in (a, b):
        store.open_epoch(covered_from=NOW - timedelta(days=1), ttl_seconds=10)
    first = observation("same-id", time=NOW - timedelta(hours=2))
    second = observation("same-id", time=NOW - timedelta(minutes=5), tenant="synthetic-b", account="b")
    assert a.append(first) and b.append(second)
    with pytest.raises(FeatureHistoryUnavailable, match="tenant"):
        a.append(second)
    for store in (a, b):
        store.seal(available_through=NOW)
    seen = a.compute(observation("target"), decision_as_of=NOW)
    unknown = b.compute(observation("target", tenant="synthetic-b"), decision_as_of=NOW)
    assert seen.sender_beneficiary_seen_before is True
    assert seen.beneficiary_unique_senders_1h == 0
    assert unknown.sender_beneficiary_seen_before is None
    assert unknown.beneficiary_unique_senders_1h == 1
    assert "sender_beneficiary_history_coverage" in unknown.missing


def test_incomplete_and_expired_history_do_not_fabricate_features(redis_client):
    epoch = uuid4().hex
    history = RedisFeatureHistory(redis_client, tenant_id="synthetic-a", epoch=epoch)
    target = observation("target")
    with pytest.raises(FeatureHistoryUnavailable):
        history.compute(target, decision_as_of=NOW)
    start = NOW - timedelta(minutes=59)
    history.open_epoch(covered_from=start, ttl_seconds=1)
    with pytest.raises(FeatureHistoryUnavailable):
        history.compute(target, decision_as_of=NOW)
    history.seal(available_through=NOW)
    with pytest.raises(FeatureHistoryUnavailable, match="one-hour"):
        history.compute(target, decision_as_of=NOW)
    with pytest.raises(FeatureHistoryUnavailable, match="immutable"):
        history.open_epoch(covered_from=start - timedelta(minutes=10), ttl_seconds=1)
    [key] = list(redis_client.scan_iter(match=history._key))
    before = redis_client.pttl(key)
    sleep(0.10)
    history.open_epoch(covered_from=start, ttl_seconds=1)
    assert 0 < redis_client.pttl(key) < before
    deadline = monotonic() + 3
    while redis_client.exists(key) and monotonic() < deadline:
        sleep(0.02)
    assert not redis_client.exists(key)
    with pytest.raises(FeatureHistoryUnavailable):
        history.compute(target, decision_as_of=NOW)


def test_store_failure_does_not_return_partial_features():
    class Unavailable:
        def eval(self, *_args):
            raise TimeoutError("synthetic connection failure")

    history = RedisFeatureHistory(Unavailable(), tenant_id="synthetic-a", epoch=uuid4().hex)
    with pytest.raises(FeatureHistoryUnavailable, match="store unavailable"):
        history.compute(observation("target"), decision_as_of=NOW)
    with pytest.raises(FeatureHistoryUnavailable, match="store unavailable"):
        history.append(observation("target"))


def test_corrupt_epoch_and_missing_expiry_are_rejected(redis_client):
    history = RedisFeatureHistory(redis_client, tenant_id="synthetic-a", epoch=uuid4().hex)
    history.open_epoch(covered_from=NOW - timedelta(hours=1), ttl_seconds=10)
    history.append(observation("previous", time=NOW - timedelta(seconds=1)))
    history.seal(available_through=NOW)
    assert history.compute(observation("target"), decision_as_of=NOW).account_transfers_1h == 1
    redis_client.hset(history._key, "event:previous", "not an observation")
    with pytest.raises(FeatureHistoryUnavailable, match="malformed"):
        history.compute(observation("target"), decision_as_of=NOW)
    redis_client.persist(history._key)
    with pytest.raises(FeatureHistoryUnavailable):
        history.compute(observation("target"), decision_as_of=NOW)
    with pytest.raises(FeatureHistoryUnavailable, match="epoch state"):
        history.append(observation("target"))


def test_revalidates_typed_observations_before_accessing_store_or_comparing_tenant():
    class CorruptTenant:
        def __ne__(self, _other):
            pytest.fail("untrusted tenant comparison")

    class UnusedStore:
        def eval(self, *_args):
            pytest.fail("invalid observation reached store")

    history = RedisFeatureHistory(UnusedStore(), tenant_id="synthetic-a", epoch=uuid4().hex)
    target = observation("target")
    object.__setattr__(target, "tenant_id", CorruptTenant())
    with pytest.raises(FeatureHistoryUnavailable, match="invalid feature observation"):
        history.append(target)
    with pytest.raises(FeatureHistoryUnavailable, match="invalid feature observation"):
        history.compute(target, decision_as_of=NOW)


def test_contradicted_seal_invalidates_entire_epoch_until_fresh_rebuild(redis_client):
    history = RedisFeatureHistory(redis_client, tenant_id="synthetic-a", epoch=uuid4().hex)
    boundary = NOW - timedelta(hours=1)
    history.open_epoch(covered_from=boundary, ttl_seconds=10)
    known = observation("known", time=NOW - timedelta(minutes=3))
    history.append(known)
    history.seal(available_through=NOW)
    target = observation("target")
    assert history.compute(target, decision_as_of=NOW).account_transfers_1h == 1
    contradiction = observation(
        "late-backfill", time=NOW - timedelta(minutes=4), availability=NOW,
    )
    with pytest.raises(FeatureHistoryUnavailable, match="contradicts sealed coverage"):
        history.append(contradiction)
    with pytest.raises(FeatureHistoryUnavailable, match="coverage loss"):
        history.compute(target, decision_as_of=NOW)
    for operation in (
        lambda: history.open_epoch(covered_from=boundary, ttl_seconds=10),
        lambda: history.append(known),
        lambda: history.seal(available_through=NOW + timedelta(minutes=1)),
    ):
        with pytest.raises(FeatureHistoryUnavailable, match="fresh epoch"):
            operation()
    rebuilt = RedisFeatureHistory(redis_client, tenant_id="synthetic-a", epoch=uuid4().hex)
    rebuilt.open_epoch(covered_from=boundary, ttl_seconds=10)
    rebuilt.append(known)
    rebuilt.append(contradiction)
    rebuilt.seal(available_through=NOW)
    assert rebuilt.compute(target, decision_as_of=NOW).account_transfers_1h == 2
