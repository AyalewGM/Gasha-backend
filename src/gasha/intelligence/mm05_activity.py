"""Offline MM-05 point-in-time account activity features (#48/#145).

Caller-provided coverage/identity is not Bank attestation. This module is not
wired to a decision, Redis, case, readiness, or enforcement path.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Context, Decimal, DivisionByZero, InvalidOperation, Overflow, ROUND_HALF_EVEN, localcontext
from enum import StrEnum
from hashlib import sha256
from json import dumps
from re import fullmatch
from zoneinfo import ZoneInfo

VERSION = "mm05-activity-v3"
_ARITHMETIC_VERSION = "exact-micro-units-ratio12-half-even-v1"
_RATIO_QUANTUM = Decimal("0.000000000001")
_RATIO_CONTEXT = Context(
    prec=64, rounding=ROUND_HALF_EVEN,
    traps=[DivisionByZero, InvalidOperation, Overflow],
)
_MAX_AMOUNT = Decimal("1e18")
_MAX_ROWS = 4096
_MAX_RAW_DECIMAL_DIGITS = 64
_MAX_SCALE = 6  # Provisional synthetic monetary contract; Bank currencies need approval.


class ActivityStatus(StrEnum):
    SETTLED = "settled"
    REVERSED = "reversed"
    FAILED = "failed"


class ActivityDirection(StrEnum):
    DEBIT = "debit"
    CREDIT = "credit"


class DormancyAssessment(StrEnum):
    DORMANT_CANDIDATE = "dormant_candidate"
    RECENT_ACTIVITY = "recent_activity"
    HISTORY_INSUFFICIENT = "history_insufficient"


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


def _money_text(value: Decimal) -> str:
    """Exact bounded money canonicalization: no context-dependent normalize/round.

    Up to six *significant fractional* places, 1e18 positive maximum, and
    at most 64 raw coefficient digits (including redundant trailing zeros).
    Validate exponent and coefficient before building any fixed-point string.
    """
    if type(value) is not Decimal or not value.is_finite():
        raise ValueError("finite positive Decimal amount required")
    parts = value.as_tuple()
    if parts.sign or len(parts.digits) > _MAX_RAW_DECIMAL_DIGITS or type(parts.exponent) is not int:
        raise ValueError("amount coefficient or exponent outside canonical budget")
    digits = "".join(str(digit) for digit in parts.digits).lstrip("0")
    if not digits:
        raise ValueError("positive amount required")
    exponent = parts.exponent
    while digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    if exponent < -_MAX_SCALE:
        raise ValueError("amount scale exceeds canonical budget")
    whole = len(digits) + exponent
    if whole > 19:
        raise ValueError("amount magnitude exceeds canonical budget")
    if exponent >= 0:
        text = digits + "0" * exponent
    elif whole > 0:
        text = digits[:whole] + "." + digits[whole:]
    else:
        text = "0." + "0" * (-whole) + digits
    if value > _MAX_AMOUNT:
        raise ValueError("amount magnitude exceeds permitted maximum")
    return text


def _micro_units(amount: Decimal) -> int:
    """Convert accepted money to exact integer millionths, independent of context."""
    text = _money_text(amount)
    whole, dot, fraction = text.partition(".")
    return int(whole) * 1_000_000 + (int(fraction.ljust(6, "0")) if dot else 0)


def _from_micro_units(value: int) -> Decimal:
    """Construct Decimal from an exact fixed-point string, without arithmetic."""
    whole, fraction = divmod(value, 1_000_000)
    return Decimal(f"{whole}.{fraction:06d}")


def _project_ratio(numerator: int, denominator: int) -> Decimal:
    """Versioned, 12-place half-even projection of an exact rational value."""
    if denominator <= 0:
        raise ValueError("positive ratio denominator required")
    with localcontext(_RATIO_CONTEXT):
        return (Decimal(numerator) / Decimal(denominator)).quantize(_RATIO_QUANTUM)


def _age_hours(older: datetime, newer: datetime) -> Decimal:
    """No float total_seconds() conversion: retain exact microsecond duration."""
    elapsed = newer - older
    microseconds = (
        (elapsed.days * 86_400 + elapsed.seconds) * 1_000_000
        + elapsed.microseconds
    )
    return _project_ratio(microseconds, 3_600_000_000)


def _amount(value: object) -> Decimal:
    if type(value) is not Decimal:
        raise ValueError("finite positive Decimal amount required")
    _money_text(value)
    return value


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
    dormancy_days: int = 90

    def __post_init__(self) -> None:
        _ref("window version", self.version)
        if type(self.baseline_days) is not int or not 1 <= self.baseline_days <= 365:
            raise ValueError("baseline_days out of range")
        if type(self.current_hours) is not int or not 1 <= self.current_hours <= 168:
            raise ValueError("current_hours out of range")
        if type(self.direction) is not ActivityDirection:
            raise ValueError("typed direction required")
        if type(self.dormancy_days) is not int or not 1 <= self.dormancy_days <= 365:
            raise ValueError("dormancy_days out of range")


@dataclass(frozen=True, slots=True)
class ActivityFeature:
    version: str
    arithmetic_version: str
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
    last_pre_current_activity_age_hours: Decimal | None
    dormancy_assessment: DormancyAssessment
    count_ratio: Decimal | None
    value_ratio: Decimal | None
    source_fingerprint: str


def _unavailable(
    target: AccountActivity, policy: ActivityWindowPolicy, cutoff: datetime,
    baseline_start: datetime, current_start: datetime, reason: str, fingerprint: str,
) -> ActivityFeature:
    return ActivityFeature(
        VERSION, _ARITHMETIC_VERSION, target.tenant_id, target.event_id, policy.version, cutoff,
        baseline_start, current_start, False, reason,
        None, None, None, None, None, None, None, None,
        DormancyAssessment.HISTORY_INSUFFICIENT, None, None, fingerprint,
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
    and sealed through the target receipt time; coverage is a caller claim,
    not authentication. Later decision_cutoff values never rewrite original evidence.
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
    # PO original-decision contract: later reconciliation cannot expand knowledge.
    cutoff = target.available_at
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

    # Original decision evidence uses only facts received by the target receipt
    # time, even when a caller later requests replay at a later decision time.
    eligible = [r for r in rows if r.occurred_at < target.occurred_at and r.available_at <= cutoff]
    # A seal extended after this decision is not new original-decision evidence.
    opened, covered, sealed = coverage
    effective_coverage = (
        opened, covered, min(sealed, cutoff) if sealed is not None else None,
    )
    packet = {
        "domain": VERSION, "arithmetic": _ARITHMETIC_VERSION,
        "dataset": dataset_digest, "epoch": history_epoch,
        "policy": (policy.version, policy.baseline_days, policy.current_hours,
                   policy.direction.value, policy.dormancy_days),
        "target": identity(target), "cutoff": cutoff.isoformat(),
        "history_present": history is not None,
        "coverage": [c.isoformat() if c is not None else None for c in effective_coverage],
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
    # Dormancy is about *all settled account movements* before the activation
    # window, not only baseline-window events in the configured direction.
    pre_current = [
        row.occurred_at for row in eligible
        if row.account_ref == target.account_ref
        and row.status is ActivityStatus.SETTLED
        and row.occurred_at < current_start
    ]
    last_pre_current = max(pre_current, default=None)
    dormancy_start = current_start - timedelta(days=policy.dormancy_days)
    opened, covered, _ = coverage
    if last_pre_current is not None and last_pre_current > dormancy_start:
        dormancy = DormancyAssessment.RECENT_ACTIVITY
    elif opened is not None and covered is not None and (
        opened <= dormancy_start and covered <= dormancy_start
    ):
        dormancy = DormancyAssessment.DORMANT_CANDIDATE
    else:
        dormancy = DormancyAssessment.HISTORY_INSUFFICIENT
    baseline_units = sum(_micro_units(row.amount) for row in baseline)
    current_units = sum(_micro_units(row.amount) for row in current)
    baseline_value = _from_micro_units(baseline_units)
    current_value = _from_micro_units(current_units)
    return ActivityFeature(
        VERSION, _ARITHMETIC_VERSION, target.tenant_id, target.event_id, policy.version, cutoff,
        baseline_start, current_start, True, None,
        len(baseline), len(current), baseline_value, current_value,
        len({row.occurred_at.date() for row in baseline}),
        len({row.occurred_at.date() for row in current}),
        _age_hours(last, target.occurred_at) if last is not None else None,
        _age_hours(last_pre_current, target.occurred_at)
        if last_pre_current is not None else None,
        dormancy,
        _project_ratio(len(current), len(baseline)) if baseline else None,
        _project_ratio(current_units, baseline_units) if baseline_units else None,
        fingerprint,
    )
