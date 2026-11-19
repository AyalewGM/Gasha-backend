"""Synthetic-only deterministic MM-05 assessment over point-in-time activity features.

This is a review *candidate*, never an authenticated fraud decision or alert.
Feature lineage and coverage are caller assertions until the trusted history
issuer/ledger is implemented (#42/#43/#48). No API, Redis, case, or bank wiring.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from re import fullmatch

from gasha.intelligence.mm05_activity import (
    VERSION as ACTIVITY_VERSION,
    ActivityFeature,
    DormancyAssessment,
)

VERSION = "mm05-offline-assessment-v1"
_SCENARIO_ID = "MM-05"
_MAX_RATIO = Decimal("1000000")


class MM05State(StrEnum):
    NOT_ASSESSED = "not_assessed"
    NOT_FLAGGED = "not_flagged"
    REVIEW_CANDIDATE = "review_candidate"


class MM05Reason(StrEnum):
    FEATURE_UNAVAILABLE = "feature_unavailable"
    INSUFFICIENT_BASELINE = "insufficient_baseline"
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


@dataclass(frozen=True, slots=True)
class MM05Assessment:
    scenario_id: str
    version: str
    tenant_id: str
    event_id: str
    policy_version: str
    feature_version: str
    arithmetic_version: str
    window_version: str
    source_fingerprint: str
    knowledge_cutoff: datetime
    state: MM05State
    reason_codes: tuple[str, ...]
    feature: ActivityFeature


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
    if feature.version != ACTIVITY_VERSION or feature.window_version != policy.window_version:
        raise ValueError("MM-05 feature/policy version mismatch")
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
        if feature.count_ratio is None or feature.value_ratio is None:
            reasons = (MM05Reason.INSUFFICIENT_BASELINE.value,)
        elif any(
            type(ratio) is not Decimal or not ratio.is_finite() or ratio < 0
            for ratio in (feature.count_ratio, feature.value_ratio)
        ):
            raise ValueError("available feature has invalid ratio")
        else:
            low_baseline = (
                feature.baseline_count <= policy.max_low_baseline_count
                and feature.baseline_active_days <= policy.max_low_baseline_active_days
            )
            dormant = feature.dormancy_assessment is DormancyAssessment.DORMANT_CANDIDATE
            if not (low_baseline or dormant):
                reasons = (MM05Reason.NOT_LOW_ACTIVITY.value,)
            elif (
                feature.current_count < policy.min_current_count
                or feature.current_value < policy.min_current_value
            ):
                reasons = (MM05Reason.BELOW_CURRENT_MATERIALITY.value,)
            elif feature.count_ratio < policy.min_count_ratio:
                reasons = (MM05Reason.COUNT_SURGE_NOT_MET.value,)
            elif feature.value_ratio < policy.min_value_ratio:
                reasons = (MM05Reason.VALUE_SURGE_NOT_MET.value,)
            else:
                state = MM05State.REVIEW_CANDIDATE
                reasons = (
                    MM05Reason.DORMANT_CANDIDATE.value if dormant
                    else MM05Reason.LOW_ACTIVITY_BASELINE.value,
                    MM05Reason.COUNT_SURGE.value,
                    MM05Reason.VALUE_SURGE.value,
                )
            if state is not MM05State.REVIEW_CANDIDATE:
                state = MM05State.NOT_FLAGGED

    return MM05Assessment(
        scenario_id=_SCENARIO_ID,
        version=VERSION,
        tenant_id=feature.tenant_id,
        event_id=feature.event_id,
        policy_version=policy.version,
        feature_version=feature.version,
        arithmetic_version=feature.arithmetic_version,
        window_version=feature.window_version,
        source_fingerprint=feature.source_fingerprint,
        knowledge_cutoff=feature.decision_cutoff,
        state=state,
        reason_codes=reasons,
        feature=feature,
    )
