"""Synthetic-only deterministic MM-05 assessment over point-in-time activity features.

This is a review *candidate*, never an authenticated fraud decision or alert.
Feature lineage and coverage are caller assertions until the trusted history
issuer/ledger is implemented (#42/#43/#48). No API, Redis, case, or bank wiring.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from hashlib import sha256
from json import dumps
from re import fullmatch
from typing import cast

from gasha.intelligence.mm05_activity import VERSION as ACTIVITY_VERSION
from gasha.intelligence.mm05_activity import ActivityFeature, DormancyAssessment

VERSION = "mm05-offline-assessment-v2"
_SCENARIO_ID = "MM-05"
_MAX_RATIO = Decimal(1000000)


class MM05State(StrEnum):
    NOT_ASSESSED = "not_assessed"
    NOT_FLAGGED = "not_flagged"
    REVIEW_CANDIDATE = "review_candidate"


class MM05Reason(StrEnum):
    FEATURE_UNAVAILABLE = "feature_unavailable"
    INSUFFICIENT_BASELINE = "insufficient_baseline"
    DORMANT_ZERO_BASELINE = "dormant_zero_baseline"
    ABSOLUTE_MATERIALITY = "absolute_materiality"
    NOT_LOW_ACTIVITY = "not_low_activity"
    BELOW_CURRENT_MATERIALITY = "below_current_materiality"
    COUNT_SURGE_NOT_MET = "count_surge_not_met"
    VALUE_SURGE_NOT_MET = "value_surge_not_met"
    DORMANT_CANDIDATE = "dormant_candidate"
    LOW_ACTIVITY_BASELINE = "low_activity_baseline"
    COUNT_SURGE = "count_surge"
    VALUE_SURGE = "value_surge"


def _identifier(name: str, value: object) -> str:
    if type(value) is not str or fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise ValueError(f"{name} must be an opaque canonical identifier")
    return value


def _threshold(name: str, value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value <= 0 or value > _MAX_RATIO:
        raise ValueError(f"{name} must be a positive bounded Decimal")
    digits = value.as_tuple()
    # Reject exponent amplification or excessive precision before any formatting.
    if len(digits.digits) > 32 or not isinstance(digits.exponent, int):
        raise ValueError(f"{name} has excessive coefficient or exponent")
    if digits.exponent < -12 or digits.exponent > 6:
        raise ValueError(f"{name} has excessive scale or exponent")
    return value


@dataclass(frozen=True, slots=True)
class MM05ThresholdPolicy:
    """Provisional synthetic thresholds. Never represents a bank policy."""

    version: str
    window_version: str
    min_current_count: int
    min_current_value: Decimal
    min_count_ratio: Decimal
    min_value_ratio: Decimal
    max_low_baseline_count: int
    max_low_baseline_active_days: int

    def __post_init__(self) -> None:
        _identifier("threshold version", self.version)
        _identifier("window version", self.window_version)
        for name, low, high in (
            ("min_current_count", 2, 4097),
            ("max_low_baseline_count", 1, 4096),
            ("max_low_baseline_active_days", 1, 365),
        ):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} outside synthetic integer bounds")
        for name in ("min_current_value", "min_count_ratio", "min_value_ratio"):
            _threshold(name, getattr(self, name))


def _canonical_decimal(value: Decimal) -> str:
    """Canonical base-10 numeric identity, independent of ambient Decimal context.

    Numerically equivalent 300, 300.0 and 3e2 serialize identically.
    _threshold bounds coefficient and exponent before text expansion.
    """
    _threshold("snapshot decimal", value)
    parts = value.as_tuple()
    digits = "".join(str(digit) for digit in parts.digits)
    exponent = cast(int, parts.exponent)
    point = len(digits) + exponent
    if point <= 0:
        text = "0." + "0" * (-point) + digits
    elif point >= len(digits):
        text = digits + "0" * (point - len(digits))
    else:
        text = digits[:point] + "." + digits[point:]
    return text.rstrip("0").rstrip(".") if "." in text else text


def _snapshot_str(name: str, value: object) -> str:
    if type(value) is not str or len(value) > 128:
        raise ValueError(f"{name} must be a bounded canonical string")
    return value


def _snapshot_int(name: str, value: object) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    return value


@dataclass(frozen=True, slots=True)
class MM05ThresholdSnapshot:
    """Immutable, JSON-reconstructible synthetic threshold values.

    All monetary and ratio fields use canonical plain-decimal strings.
    This is evidence for offline replay, not an authorized policy issuer.
    """

    version: str
    window_version: str
    min_current_count: int
    min_current_value: str
    min_count_ratio: str
    min_value_ratio: str
    max_low_baseline_count: int
    max_low_baseline_active_days: int

    def __post_init__(self) -> None:
        # Revalidate even when loading an untrusted serialized snapshot.
        policy = self.to_policy()
        for name in ("min_current_value", "min_count_ratio", "min_value_ratio"):
            if getattr(self, name) != _canonical_decimal(getattr(policy, name)):
                raise ValueError(f"{name} is not canonical")

    @classmethod
    def from_policy(cls, policy: MM05ThresholdPolicy) -> MM05ThresholdSnapshot:
        if type(policy) is not MM05ThresholdPolicy:
            raise ValueError("typed synthetic threshold policy required")
        return cls(
            version=policy.version,
            window_version=policy.window_version,
            min_current_count=policy.min_current_count,
            min_current_value=_canonical_decimal(policy.min_current_value),
            min_count_ratio=_canonical_decimal(policy.min_count_ratio),
            min_value_ratio=_canonical_decimal(policy.min_value_ratio),
            max_low_baseline_count=policy.max_low_baseline_count,
            max_low_baseline_active_days=policy.max_low_baseline_active_days,
        )

    def to_policy(self) -> MM05ThresholdPolicy:
        for name in ("min_current_value", "min_count_ratio", "min_value_ratio"):
            text = _snapshot_str(name, getattr(self, name))
            try:
                _threshold(name, Decimal(text))
            except (InvalidOperation, ValueError) as exc:
                raise ValueError(f"{name} is not a bounded canonical decimal") from exc
        return MM05ThresholdPolicy(
            version=self.version,
            window_version=self.window_version,
            min_current_count=self.min_current_count,
            min_current_value=Decimal(self.min_current_value),
            min_count_ratio=Decimal(self.min_count_ratio),
            min_value_ratio=Decimal(self.min_value_ratio),
            max_low_baseline_count=self.max_low_baseline_count,
            max_low_baseline_active_days=self.max_low_baseline_active_days,
        )

    def to_payload(self) -> dict[str, str | int]:
        """Exact JSON object for durable offline serialization."""
        return {
            "version": self.version,
            "window_version": self.window_version,
            "min_current_count": self.min_current_count,
            "min_current_value": self.min_current_value,
            "min_count_ratio": self.min_count_ratio,
            "min_value_ratio": self.min_value_ratio,
            "max_low_baseline_count": self.max_low_baseline_count,
            "max_low_baseline_active_days": self.max_low_baseline_active_days,
        }

    @classmethod
    def from_payload(cls, payload: object) -> MM05ThresholdSnapshot:
        """Fail closed on absent, extra or wrong-typed serialized fields."""
        if not isinstance(payload, Mapping):
            raise TypeError("threshold snapshot object required")
        if set(payload) != {
        "version",
        "window_version",
        "min_current_count",
        "min_current_value",
        "min_count_ratio",
        "min_value_ratio",
        "max_low_baseline_count",
        "max_low_baseline_active_days",
    }:
            raise ValueError("threshold snapshot fields must match exactly")
        return cls(
            version=_snapshot_str("version", payload["version"]),
            window_version=_snapshot_str("window_version", payload["window_version"]),
            min_current_count=_snapshot_int("min_current_count", payload["min_current_count"]),
            min_current_value=_snapshot_str("min_current_value", payload["min_current_value"]),
            min_count_ratio=_snapshot_str("min_count_ratio", payload["min_count_ratio"]),
            min_value_ratio=_snapshot_str("min_value_ratio", payload["min_value_ratio"]),
            max_low_baseline_count=_snapshot_int(
                "max_low_baseline_count", payload["max_low_baseline_count"],
            ),
            max_low_baseline_active_days=_snapshot_int(
                "max_low_baseline_active_days", payload["max_low_baseline_active_days"],
            ),
        )


@dataclass(frozen=True, slots=True)
class MM05Assessment:
    scenario_id: str
    version: str
    tenant_id: str
    event_id: str
    policy_version: str
    threshold_snapshot: MM05ThresholdSnapshot
    threshold_fingerprint: str
    feature_version: str
    arithmetic_version: str
    window_version: str
    source_fingerprint: str
    knowledge_cutoff: datetime
    state: MM05State
    reason_codes: tuple[str, ...]
    feature: ActivityFeature


def _policy_fingerprint(snapshot: MM05ThresholdSnapshot) -> str:
    """Hash the exact retained snapshot, not an external policy version."""
    payload = (VERSION, snapshot.to_payload())
    encoded = dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(encoded).hexdigest()


def evaluate_mm05_activity(
    feature: ActivityFeature, *, policy: MM05ThresholdPolicy,
) -> MM05Assessment:
    """Assess a synthetic feature, without invoking decisions or interventions.

    Both *count* and *value* surges are required to avoid mistaking isolated
    high-value or high-frequency activity for the MM-05 combined hypothesis.
    Zero-baseline ratios are undefined: they are never promoted to infinity.
    Dormancy is an optional qualifying branch, not proof of illicit behavior.
    """
    if type(feature) is not ActivityFeature or type(policy) is not MM05ThresholdPolicy:
        raise ValueError("typed MM-05 feature and policy required")
    snapshot = MM05ThresholdSnapshot.from_policy(policy)
    policy = snapshot.to_policy()  # Decisions and digest use the very same retained values.
    if feature.version != ACTIVITY_VERSION or feature.window_version != policy.window_version:
        raise ValueError("MM-05 feature/policy version mismatch")
    if feature.arithmetic_version != "exact-micro-units-ratio12-half-even-v1":
        raise ValueError("unsupported MM-05 arithmetic contract")
    _identifier("tenant", feature.tenant_id)
    _identifier("event", feature.event_id)
    if type(feature.source_fingerprint) is not str or fullmatch(
        r"sha256:[0-9a-f]{64}", feature.source_fingerprint,
    ) is None:
        raise ValueError("canonical feature fingerprint required")
    if type(feature.available) is not bool:
        raise ValueError("typed availability required")
    if feature.available:
        if feature.unavailable_reason is not None:
            raise ValueError("available feature cannot contain unavailable_reason")
    elif not feature.unavailable_reason:
        raise ValueError("unavailable feature requires explicit reason")

    state = MM05State.NOT_ASSESSED
    reasons: tuple[str, ...] = ()
    if not feature.available:
        reasons = (MM05Reason.FEATURE_UNAVAILABLE.value, feature.unavailable_reason or "")
    else:
        quantities = (
            feature.baseline_count, feature.current_count,
            feature.baseline_active_days, feature.current_active_days,
        )
        amounts = (feature.baseline_value, feature.current_value)
        if any(type(n) is not int or n < 0 or n > 4097 for n in quantities):
            raise ValueError("available feature has invalid count or active days")
        if any(type(n) is not Decimal or not n.is_finite() or n < 0 for n in amounts):
            raise ValueError("available feature has invalid monetary value")
        if type(feature.dormancy_assessment) is not DormancyAssessment:
            raise ValueError("typed dormancy assessment required")
        baseline_count = cast(int, feature.baseline_count)
        current_count = cast(int, feature.current_count)
        baseline_days = cast(int, feature.baseline_active_days)
        current_value = cast(Decimal, feature.current_value)
        dormant = feature.dormancy_assessment is DormancyAssessment.DORMANT_CANDIDATE
        low_baseline = (
            baseline_count <= policy.max_low_baseline_count
            and baseline_days <= policy.max_low_baseline_active_days
        )
        if not (low_baseline or dormant):
            state = MM05State.NOT_FLAGGED
            reasons = (MM05Reason.NOT_LOW_ACTIVITY.value,)
        elif (
            current_count < policy.min_current_count
            or current_value < policy.min_current_value
        ):
            # A quiet account with just one event is never a surge by inference.
            reasons = (MM05Reason.INSUFFICIENT_BASELINE.value,) if baseline_count == 0 else (
                MM05Reason.BELOW_CURRENT_MATERIALITY.value,
            )
            state = (
                MM05State.NOT_ASSESSED if baseline_count == 0 else MM05State.NOT_FLAGGED
            )
        elif feature.count_ratio is None or feature.value_ratio is None:
            if baseline_count == 0 and dormant:
                # No ratio/division is invented. A complete, dormant account
                # with multiple material events can still be reviewed on an
                # explicitly different absolute-activation basis.
                state = MM05State.REVIEW_CANDIDATE
                reasons = (
                    MM05Reason.DORMANT_CANDIDATE.value,
                    MM05Reason.DORMANT_ZERO_BASELINE.value,
                    MM05Reason.ABSOLUTE_MATERIALITY.value,
                )
            else:
                reasons = (MM05Reason.INSUFFICIENT_BASELINE.value,)
        elif any(
            type(ratio) is not Decimal or not ratio.is_finite() or ratio < 0
            for ratio in (feature.count_ratio, feature.value_ratio)
        ):
            raise ValueError("available feature has invalid ratio")
        elif feature.count_ratio < policy.min_count_ratio:
            state = MM05State.NOT_FLAGGED
            reasons = (MM05Reason.COUNT_SURGE_NOT_MET.value,)
        elif feature.value_ratio < policy.min_value_ratio:
            state = MM05State.NOT_FLAGGED
            reasons = (MM05Reason.VALUE_SURGE_NOT_MET.value,)
        else:
            state = MM05State.REVIEW_CANDIDATE
            reasons = (
                MM05Reason.DORMANT_CANDIDATE.value if dormant
                else MM05Reason.LOW_ACTIVITY_BASELINE.value,
                MM05Reason.COUNT_SURGE.value,
                MM05Reason.VALUE_SURGE.value,
            )

    return MM05Assessment(
        scenario_id=_SCENARIO_ID,
        version=VERSION,
        tenant_id=feature.tenant_id,
        event_id=feature.event_id,
        policy_version=policy.version,
        threshold_snapshot=snapshot,
        threshold_fingerprint=_policy_fingerprint(snapshot),
        feature_version=feature.version,
        arithmetic_version=feature.arithmetic_version,
        window_version=feature.window_version,
        source_fingerprint=feature.source_fingerprint,
        knowledge_cutoff=feature.decision_cutoff,
        state=state,
        reason_codes=reasons,
        feature=feature,
    )
