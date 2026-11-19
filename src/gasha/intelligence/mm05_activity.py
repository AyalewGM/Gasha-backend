"""Offline MM-05 point-in-time account activity features (#48/#145).

Caller-provided coverage/identity is not Bank attestation. This module is not
wired to a decision, Redis, case, readiness, or enforcement path.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from json import dumps
from re import fullmatch
from zoneinfo import ZoneInfo

VERSION = "mm05-activity-v1"
_MAX_AMOUNT = Decimal("1e18")
_MAX_ROWS = 4096


class ActivityStatus(StrEnum):
    SETTLED = "settled"
    REVERSED = "reversed"
    FAILED = "failed"


class ActivityDirection(StrEnum):
    DEBIT = "debit"
    CREDIT = "credit"


def _ref(name: str, value: object) -> str:
    if type(value) is not str or fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise ValueError(f"{name}: canonical opaque reference required")
    return value


def _clock(name: str, value: object) -> datetime:
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, ZoneInfo):
        raise ValueError(f"{name}: ordinary aware datetime required")
    if value.utcoffset() is None:
        raise ValueError(f"{name}: aware datetime required")
    return value.astimezone(UTC)


def _amount(value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or not 0 < value <= _MAX_AMOUNT:
        raise ValueError("finite positive Decimal amount required")
    return value


def _money_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


@dataclass(frozen=True, slots=True)
class AccountActivity:
    tenant_id: str
    event_id: str
    account_ref: str
    occurred_at: datetime
    available_at: datetime
    direction: ActivityDirection
    status: ActivityStatus
    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        for key in ("tenant_id", "event_id", "account_ref"):
            _ref(key, getattr(self, key))
        if type(self.direction) is not ActivityDirection or type(self.status) is not ActivityStatus:
            raise ValueError("typed direction/status required")
        if type(self.currency) is not str or fullmatch(r"[A-Z]{3}", self.currency) is None:
            raise ValueError("single ISO-style currency code required")
        _amount(self.amount)
        occurred = _clock("occurred_at", self.occurred_at)
        available = _clock("available_at", self.available_at)
        if available < occurred:
            raise ValueError("availability precedes occurrence")
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "available_at", available)


@dataclass(frozen=True, slots=True)
class ActivityWindowPolicy:
    version: str
    baseline_days: int
    current_hours: int
    direction: ActivityDirection

    def __post_init__(self) -> None:
        _ref("window version", self.version)
        if type(self.baseline_days) is not int or not 1 <= self.baseline_days <= 365:
            raise ValueError("baseline_days out of range")
        if type(self.current_hours) is not int or not 1 <= self.current_hours <= 168:
            raise ValueError("current_hours out of range")
        if type(self.direction) is not ActivityDirection:
            raise ValueError("typed direction required")


@dataclass(frozen=True, slots=True)
class ActivityFeature:
    version: str
    tenant_id: str
    event_id: str
    window_version: str
    decision_cutoff: datetime
    baseline_start: datetime
    current_start: datetime
    available: bool
    unavailable_reason: str | None
    baseline_count: int | None
    current_count: int | None
    baseline_value: Decimal | None
    current_value: Decimal | None
    baseline_active_days: int | None
    current_active_days: int | None
    last_baseline_activity_age_hours: Decimal | None
    count_ratio: Decimal | None
    value_ratio: Decimal | None
    source_fingerprint: str


def _unavailable(
    target: AccountActivity, policy: ActivityWindowPolicy, cutoff: datetime,
    baseline_start: datetime, current_start: datetime, reason: str, fingerprint: str,
) -> ActivityFeature:
    return ActivityFeature(
        VERSION, target.tenant_id, target.event_id, policy.version, cutoff,
        baseline_start, current_start, False, reason,
        None, None, None, None, None, None, None, None, None, fingerprint,
    )


def compute_mm05_activity(
    target: AccountActivity, history: tuple[AccountActivity, ...] | None, *,
    policy: ActivityWindowPolicy, decision_cutoff: datetime,
    account_opened_at: datetime | None, history_covered_from: datetime | None,
    history_sealed_through: datetime | None, dataset_digest: str, history_epoch: str,
) -> ActivityFeature:
    """Aggregate events strictly before the target plus the target itself.

    Baseline [baseline_start,current_start), current [current_start,target_time]
    include a boundary event only in its later window. History must be complete
    and sealed through cutoff; coverage is a caller claim, not authentication.
    Same-time other events are excluded because their order is not established.
    Reversed/failed and the opposite direction do not contribute. No FX is done.
    """
    if type(target) is not AccountActivity or type(policy) is not ActivityWindowPolicy:
        raise ValueError("typed activity target and policy required")
    target = replace(target)
    policy = replace(policy)
    cutoff = _clock("decision_cutoff", decision_cutoff)
    if not target.occurred_at <= target.available_at <= cutoff:
        raise ValueError("target is unavailable at the decision cutoff")
    if type(dataset_digest) is not str or fullmatch(r"sha256:[0-9a-f]{64}", dataset_digest) is None:
        raise ValueError("dataset digest required")
    _ref("history epoch", history_epoch)
    baseline_start = target.occurred_at - timedelta(
        days=policy.baseline_days, hours=policy.current_hours,
    )
    current_start = target.occurred_at - timedelta(hours=policy.current_hours)
    coverage = (
        _clock("account_opened_at", account_opened_at) if account_opened_at is not None else None,
        _clock("history_covered_from", history_covered_from)
        if history_covered_from is not None else None,
        _clock("history_sealed_through", history_sealed_through)
        if history_sealed_through is not None else None,
    )
    if history is not None and (type(history) is not tuple or len(history) > _MAX_ROWS):
        raise ValueError("bounded immutable activity history required")
    rows: list[AccountActivity] = []
    seen = {target.event_id}
    if history is not None:
        for entry in history:
            if type(entry) is not AccountActivity:
                raise ValueError("typed activity history required")
            item = replace(entry)
            if item.tenant_id != target.tenant_id:
                raise ValueError("cross-tenant activity history")
            if item.event_id in seen:
                raise ValueError("duplicate activity event")
            seen.add(item.event_id)
            rows.append(item)

    def identity(row: AccountActivity) -> tuple[str, ...]:
        return (
            row.tenant_id, row.event_id, row.account_ref,
            row.occurred_at.isoformat(), row.available_at.isoformat(),
            row.direction.value, row.status.value, _money_text(row.amount), row.currency,
        )

    # Do not bind to post-cutoff history, which may have arrived after a past
    # replay decision. The declared seal and coverage remain explicit inputs.
    eligible = [r for r in rows if r.occurred_at < target.occurred_at and r.available_at <= cutoff]
    packet = {
        "domain": VERSION, "dataset": dataset_digest, "epoch": history_epoch,
        "policy": (policy.version, policy.baseline_days, policy.current_hours, policy.direction.value),
        "target": identity(target), "cutoff": cutoff.isoformat(),
        "coverage": [c.isoformat() if c is not None else None for c in coverage],
        "eligible": sorted(identity(row) for row in eligible),
    }
    fingerprint = "sha256:" + sha256(
        dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    if history is None:
        return _unavailable(target, policy, cutoff, baseline_start, current_start,
                            "history_store_unavailable", fingerprint)
    opened, covered, sealed = coverage
    if opened is None or covered is None or sealed is None:
        return _unavailable(target, policy, cutoff, baseline_start, current_start,
                            "history_coverage_unverified", fingerprint)
    if opened > baseline_start:
        return _unavailable(target, policy, cutoff, baseline_start, current_start,
                            "account_too_new", fingerprint)
    if covered > baseline_start or sealed < cutoff or covered > sealed:
        return _unavailable(target, policy, cutoff, baseline_start, current_start,
                            "history_incomplete", fingerprint)
    account_rows = [
        row for row in eligible if row.account_ref == target.account_ref
        and row.direction is policy.direction and row.status is ActivityStatus.SETTLED
        and baseline_start <= row.occurred_at
    ]
    if target.direction is not policy.direction or target.status is not ActivityStatus.SETTLED:
        return _unavailable(target, policy, cutoff, baseline_start, current_start,
                            "target_not_qualifying", fingerprint)
    if any(row.currency != target.currency for row in account_rows):
        return _unavailable(target, policy, cutoff, baseline_start, current_start,
                            "mixed_currency_no_approved_fx", fingerprint)
    baseline = [row for row in account_rows if row.occurred_at < current_start]
    current = [row for row in account_rows if row.occurred_at >= current_start]
    current.append(target)
    last = max((row.occurred_at for row in baseline), default=None)
    baseline_value = sum((row.amount for row in baseline), Decimal(0))
    current_value = sum((row.amount for row in current), Decimal(0))
    return ActivityFeature(
        VERSION, target.tenant_id, target.event_id, policy.version, cutoff,
        baseline_start, current_start, True, None,
        len(baseline), len(current), baseline_value, current_value,
        len({row.occurred_at.date() for row in baseline}),
        len({row.occurred_at.date() for row in current}),
        (Decimal(str((target.occurred_at - last).total_seconds())) / Decimal(3600)
         if last is not None else None),
        Decimal(len(current)) / Decimal(len(baseline)) if baseline else None,
        current_value / baseline_value if baseline_value else None,
        fingerprint,
    )
