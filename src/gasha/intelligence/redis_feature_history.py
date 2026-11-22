"""Opt-in, bounded Redis history for synthetic online feature computation."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from json import dumps, loads
from typing import Protocol

from gasha.intelligence.feature_set_v1 import FeatureSetV1, ObservedTransfer, compute_feature_set

_MAX_EVENTS = 4096
_HEADER_FIELDS = 4
_MAX_TTL_SECONDS = 30 * 86400

# One key keeps each operation atomic and Redis Cluster slot local. Expiry is
# fixed for the entire epoch; individual rows cannot silently disappear.
_WRITE = f"""
local op, first, second, third, fourth = unpack(ARGV)
local key = KEYS[1]
local start = redis.call('HGET', key, 'covered_from')
if start then
    if redis.call('PTTL', key) <= 0 then return 'invalid' end
    local status = redis.call('HGET', key, 'status')
    if status == 'poisoned' then return 'poisoned' end
    if status ~= 'ready' then return 'invalid' end
end
if op == 'open' then
    if start then
        if start == first and redis.call('HGET', key, 'ttl_seconds') == second then
            return 'existing'
        end
        return 'conflict'
    end
    if redis.call('EXISTS', key) == 1 then return 'invalid' end
    redis.call('HSET', key, 'covered_from', first, 'sealed_through', '',
               'ttl_seconds', second, 'status', 'ready')
    redis.call('EXPIRE', key, tonumber(second))
    return 'created'
end
if not start then return 'missing' end
local sealed = redis.call('HGET', key, 'sealed_through')
if op == 'seal' then
    if first < start or first < sealed then return 'coverage' end
    redis.call('HSET', key, 'sealed_through', first)
    return 'sealed'
end
local prior = redis.call('HGET', key, first)
if prior then
    if prior == second then return 'existing' end
    return 'conflict'
end
if third < start then return 'coverage' end
if fourth <= sealed then
    redis.call('HSET', key, 'status', 'poisoned')
    return 'coverage_contradiction'
end
if redis.call('HLEN', key) >= {_MAX_EVENTS + _HEADER_FIELDS} then return 'capacity' end
redis.call('HSET', key, first, second)
return 'created'
"""
_READ = f"""
if redis.call('PTTL', KEYS[1]) <= 0 then return false end
if redis.call('HLEN', KEYS[1]) > {_MAX_EVENTS + _HEADER_FIELDS} then return false end
return redis.call('HGETALL', KEYS[1])
"""


class RedisScriptClient(Protocol):
    """Compatible with a synchronous, connection-bounded redis-py client."""

    def eval(self, script: str, numkeys: int, *keys_and_args: str) -> object: ...


class FeatureHistoryUnavailable(ValueError):
    """Coverage, integrity, capacity or availability is insufficient for features."""


def _text(value: object) -> str:
    if type(value) is bytes:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FeatureHistoryUnavailable("invalid feature history response encoding") from exc
    if type(value) is str:
        return value
    raise FeatureHistoryUnavailable("invalid feature history response")


def _instant(value: datetime) -> str:
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        raise ValueError("feature history requires an ordinary timezone-aware datetime")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if _instant(parsed) != value:
        raise ValueError("invalid feature history clock")
    return parsed


def _encode(event: ObservedTransfer) -> str:
    return dumps(
        asdict(event) | {
            "occurred_at": _instant(event.occurred_at),
            "available_at": _instant(event.available_at),
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )


class RedisFeatureHistory:
    """Explicit tenant/epoch store with producer-owned completeness watermark.

    A trusted producer starts an epoch and seals a cutoff only after all
    observations available by that cutoff have been appended. This adapter
    checks the declared boundary. Authenticating producer progress is the
    runtime composition's responsibility. Configure the owner to allocate a
    fresh epoch identifier on rebuild after expiration or loss.
    """

    def __init__(self, client: RedisScriptClient, *, tenant_id: str, epoch: str) -> None:
        if any(type(tag) is not str or not tag or len(tag) > 128 for tag in (tenant_id, epoch)):
            raise ValueError("tenant and history epoch are required")
        self._client = client
        self._tenant_id = tenant_id
        identity = dumps([tenant_id, epoch], ensure_ascii=True, separators=(",", ":"))
        self._key = "gasha:feature-history:v1:" + sha256(identity.encode()).hexdigest()

    @property
    def epoch_fingerprint(self) -> str:
        """Opaque binding to the process-configured tenant/epoch, not an attestation."""
        return sha256(self._key.encode("ascii")).hexdigest()

    def _eval(self, script: str, *args: str) -> object:
        try:
            return self._client.eval(script, 1, self._key, *args)
        except Exception as exc:
            raise FeatureHistoryUnavailable("feature history store unavailable") from exc

    def _write(self, operation: str, *args: str) -> str:
        result = _text(self._eval(_WRITE, operation, *args))
        accepted = {
            "open": {"created", "existing"},
            "append": {"created", "existing"},
            "seal": {"sealed"},
        }
        if result not in accepted[operation]:
            raise FeatureHistoryUnavailable({
                "missing": "feature history epoch missing or expired",
                "capacity": "feature history epoch exceeds capacity",
                "coverage": "operation conflicts with feature history coverage",
                "coverage_contradiction": "new observation contradicts sealed coverage",
                "poisoned": "sealed coverage was contradicted; rebuild with a fresh epoch",
                "conflict": "feature history identity conflicts with immutable state",
                "invalid": "invalid feature history epoch state",
            }.get(result, "invalid feature history write response"))
        return result

    def open_epoch(self, *, covered_from: datetime, ttl_seconds: int) -> None:
        """Initialize an explicit coverage start. A retry never refreshes expiry."""
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError("invalid feature history TTL")
        self._write("open", _instant(covered_from), str(ttl_seconds))

    def _event(self, event: ObservedTransfer) -> ObservedTransfer:
        if type(event) is not ObservedTransfer:
            raise FeatureHistoryUnavailable("invalid feature observation")
        try:
            snapshot = replace(event)
        except (AttributeError, TypeError, ValueError) as exc:
            raise FeatureHistoryUnavailable("invalid feature observation") from exc
        if snapshot.tenant_id != self._tenant_id:
            raise FeatureHistoryUnavailable("feature observation outside tenant scope")
        return snapshot

    def append(self, event: ObservedTransfer) -> bool:
        """Return whether an immutable event was inserted."""
        event = self._event(event)
        return self._write(
            "append", "event:" + event.event_id, _encode(event),
            _instant(event.occurred_at), _instant(event.available_at),
        ) == "created"

    def seal(self, *, available_through: datetime) -> None:
        """Make complete, explicitly sealed history available for decisions."""
        self._write("seal", _instant(available_through))

    def observations_for(
        self, target: ObservedTransfer, *, decision_as_of: datetime
    ) -> tuple[ObservedTransfer, ...]:
        """Read one validated, sealed Redis snapshot for the synthetic worker.

        The caller must be the configured server-side producer/worker. A client
        cannot assert epoch coverage or supply a completeness flag here.
        """
        target = self._event(target)
        cutoff = _parse_instant(_instant(decision_as_of))
        raw = self._eval(_READ)
        if type(raw) is not list or len(raw) % 2 or len(raw) > 2 * (_MAX_EVENTS + _HEADER_FIELDS):
            raise FeatureHistoryUnavailable("invalid feature history snapshot")
        try:
            rows = {_text(key): _text(value) for key, value in zip(raw[::2], raw[1::2], strict=True)}
            if len(rows) * 2 != len(raw):
                raise FeatureHistoryUnavailable("duplicate fields in feature history snapshot")
            if rows.pop("status") != "ready":
                raise FeatureHistoryUnavailable("feature history epoch unavailable after coverage loss")
            covered_from = _parse_instant(rows.pop("covered_from"))
            sealed = _parse_instant(rows.pop("sealed_through"))
            ttl = int(rows.pop("ttl_seconds"))
            if not 1 <= ttl <= _MAX_TTL_SECONDS:
                raise FeatureHistoryUnavailable("invalid feature history TTL")
            if covered_from > target.occurred_at - timedelta(hours=1) or sealed < cutoff:
                raise FeatureHistoryUnavailable("insufficient sealed one-hour history coverage")
            history = []
            for key, value in rows.items():
                data = loads(value)
                data["occurred_at"] = _parse_instant(data["occurred_at"])
                data["available_at"] = _parse_instant(data["available_at"])
                observation = self._event(ObservedTransfer(**data))
                if (
                    key != "event:" + observation.event_id
                    or observation.occurred_at < covered_from
                ):
                    raise FeatureHistoryUnavailable("stored feature observation identity mismatch")
                if observation.event_id == target.event_id:
                    if observation != target:
                        raise FeatureHistoryUnavailable("target conflicts with stored observation")
                else:
                    history.append(observation)
        except FeatureHistoryUnavailable:
            raise
        except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as exc:
            raise FeatureHistoryUnavailable("missing or malformed feature history snapshot") from exc
        return tuple(history)

    def compute(self, target: ObservedTransfer, *, decision_as_of: datetime) -> FeatureSetV1:
        """Reuse offline feature math, with unavailable first-seen on bounded history."""
        history = self.observations_for(target, decision_as_of=decision_as_of)
        return compute_feature_set(
            target, history, decision_as_of=decision_as_of,
            relationship_history_complete=False,
        )
