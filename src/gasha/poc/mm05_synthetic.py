"""Inactive MM-05 low-activity-to-surge hypothesis, never a Bank decision.

Requires the separate #48 scenario evidence-presence contract. Every value,
threshold and context assertion here is synthetic/unverified: no protected
API, fraud scoring, alert, readiness, case or payment intervention uses it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum

from gasha.poc.scenario_observations import (
    FieldState,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
    inspect_scenario_coverage,
)

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_MAX_VALUE = Decimal("1e18")


class MM05Context(StrEnum):
    """UNKNOWN must never be treated as a negative exception finding."""

    UNKNOWN = "unknown"
    REPORTED = "reported"
    REPORTED_ABSENT = "reported_absent"


class MM05AccountState(StrEnum):
    ACTIVE = "active"
    DORMANT = "dormant"
    FROZEN = "frozen"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class MM05Status(StrEnum):
    BLOCKED_REQUIRED_FIELDS = "blocked_required_fields"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_METRICS = "blocked_metrics"
    BLOCKED_WINDOW = "blocked_window"
    BLOCKED_ACCOUNT_STATE = "blocked_account_state"
    BASELINE_NOT_DORMANT = "baseline_not_dormant"
    NO_ACTIVITY_SURGE = "no_activity_surge"
    CONTEXT_EXCLUSION_REPORTED = "context_exclusion_reported"
    CONTEXT_REVIEW_REQUIRED = "context_review_required"
    SYNTHETIC_CHANGE_HYPOTHESIS = "synthetic_change_hypothesis"


def _token(name: str, value: object) -> str:
    if not isinstance(value, str) or type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical synthetic token required")
    return value


def _utc(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: aware datetime required")
    return value.astimezone(UTC)


def _whole(name: str, value: object, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or type(value) is not int or value < minimum or value > 1_000_000:
        raise ScenarioContractError(f"{name}: bounded integer required")
    return value


def _money(name: str, value: object, *, positive: bool = False) -> Decimal:
    if not isinstance(value, Decimal) or type(value) is not Decimal:
        raise ScenarioContractError(f"{name}: strict Decimal required")
    if not value.is_finite() or value < 0 or (positive and value == 0) or value > _MAX_VALUE:
        raise ScenarioContractError(f"{name}: finite nonnegative Decimal required")
    return value


@dataclass(frozen=True, slots=True)
class MM05SyntheticPolicy:
    """Explicit caller-proposed thresholds, NEVER server/Bank-approved policy."""

    version: str
    configuration_version: str
    min_prior_days: int
    max_current_hours: int
    max_gap_hours: int
    max_prior_count: int
    max_prior_value: Decimal
    min_current_count: int
    min_current_value: Decimal
    min_count_increase: int
    min_value_increase: Decimal

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("configuration version", self.configuration_version)
        for name, minimum in (
            ("min_prior_days", 1), ("max_current_hours", 1),
            ("max_gap_hours", 0), ("max_prior_count", 0),
            ("min_current_count", 1), ("min_count_increase", 1),
        ):
            _whole(name, getattr(self, name), minimum=minimum)
        _money("max_prior_value", self.max_prior_value)
        _money("min_current_value", self.min_current_value, positive=True)
        _money("min_value_increase", self.min_value_increase, positive=True)
        if self.min_prior_days > 36_500 or self.max_current_hours > 8_760:
            raise ScenarioContractError("synthetic time bounds exceed configured safety limit")
        if self.max_gap_hours > 8_760:
            raise ScenarioContractError("synthetic gap exceeds safety limit")


@dataclass(frozen=True, slots=True)
class MM05SyntheticMetrics:
    """Aggregated, synthetic-only account windows; not authenticated Bank data."""

    observation_digest: str
    policy_version: str
    account_ref: str
    currency: str
    account_state: MM05AccountState
    prior_start: datetime
    prior_end: datetime
    current_start: datetime
    current_end: datetime
    available_at: datetime
    prior_count: int
    prior_value: Decimal
    current_count: int
    current_value: Decimal
    reactivation_reason: MM05Context = MM05Context.UNKNOWN
    scheduled_bulk_activity: MM05Context = MM05Context.UNKNOWN

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or _DIGEST.fullmatch(
            self.observation_digest
        ) is None:
            raise ScenarioContractError("metrics observation digest invalid")
        _token("metrics policy version", self.policy_version)
        _token("account reference", self.account_ref)
        if type(self.currency) is not str or _CURRENCY.fullmatch(self.currency) is None:
            raise ScenarioContractError("one canonical aggregate currency required")
        if type(self.account_state) is not MM05AccountState:
            raise ScenarioContractError("typed account lifecycle state required")
        for key in ("reactivation_reason", "scheduled_bulk_activity"):
            if type(getattr(self, key)) is not MM05Context:
                raise ScenarioContractError("typed three-state optional context required")
        for name in ("prior_count", "current_count"):
            _whole(name, getattr(self, name))
        for name in ("prior_value", "current_value"):
            _money(name, getattr(self, name))
        if (self.prior_count == 0 and self.prior_value != 0) or (
            self.current_count == 0 and self.current_value != 0
        ):
            raise ScenarioContractError("nonzero aggregate value with zero transactions")
        for name in (
            "prior_start", "prior_end", "current_start", "current_end", "available_at",
        ):
            object.__setattr__(self, name, _utc(name, getattr(self, name)))
        if not (
            self.prior_start < self.prior_end <= self.current_start
            < self.current_end <= self.available_at
        ):
            raise ScenarioContractError("invalid disjoint window/availability chronology")


@dataclass(frozen=True, slots=True)
class MM05SyntheticResult:
    status: MM05Status
    observation_digest: str
    configuration_version: str
    policy_version: str | None
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        """Never export account references, counts, currency amounts or PII."""
        return {
            "scenario_id": "MM-05", "use_case": "UC-02",
            "status": self.status.value, "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "configuration_version": self.configuration_version,
            "policy_version": self.policy_version,
            "source": "synthetic_caller_asserted",
            "heuristic_evaluated": self.heuristic_evaluated,
            "bank_verified": False, "fraud_determined": False,
            "readiness_authorized": False, "enforcement_activated": False,
        }


def evaluate_mm05_synthetic(
    observation: ScenarioObservation, *,
    policy: MM05SyntheticPolicy | None,
    metrics: MM05SyntheticMetrics | None,
    expected_installation: str, expected_tenant: str,
    expected_dataset_digest: str,
) -> MM05SyntheticResult:
    """Evaluate an *untrusted hypothesis* after fail-closed #48 coverage.

    Missing inputs and unknown exception context never turn into a risk score
    or a 'safe' inference. Bank mapping, baseline windows, and policy approvals
    MUST be independently established before operational detector integration.
    """
    coverage = inspect_scenario_coverage(
        observation, expected_installation=expected_installation,
        expected_tenant=expected_tenant, expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.MM_05:
        raise ScenarioContractError("MM-05 observation required")
    if policy is not None:
        if type(policy) is not MM05SyntheticPolicy:
            raise ScenarioContractError("exact policy type required")
        policy = replace(policy)
    if metrics is not None:
        if type(metrics) is not MM05SyntheticMetrics:
            raise ScenarioContractError("exact metrics type required")
        metrics = replace(metrics)

    def result(
        status: MM05Status, *reasons: str, evaluated: bool = False,
    ) -> MM05SyntheticResult:
        return MM05SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(MM05Status.BLOCKED_REQUIRED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(MM05Status.BLOCKED_POLICY, "threshold_policy_unavailable")
    if metrics is None:
        return result(MM05Status.BLOCKED_METRICS, "aggregate_values_unavailable")
    if (
        metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
        or policy.configuration_version != observation.configuration_version
    ):
        raise ScenarioContractError("metrics/observation/policy version mismatch")
    if not (
        metrics.current_start <= observation.occurred_at <= metrics.current_end
        and metrics.available_at <= observation.decision_cutoff
    ):
        raise ScenarioContractError("post-cutoff or wrong-event aggregate window")
    if (
        metrics.prior_end - metrics.prior_start < timedelta(days=policy.min_prior_days)
        or metrics.current_end - metrics.current_start > timedelta(hours=policy.max_current_hours)
        or metrics.current_start - metrics.prior_end > timedelta(hours=policy.max_gap_hours)
    ):
        return result(MM05Status.BLOCKED_WINDOW, "unqualified_comparison_window")
    available_optional = {
        field.name for field in observation.fields
        if field.state is FieldState.OBSERVED
    }
    for field_name, context in (
        ("reactivation_reason", metrics.reactivation_reason),
        ("scheduled_bulk_activity", metrics.scheduled_bulk_activity),
    ):
        if context is not MM05Context.UNKNOWN and field_name not in available_optional:
            raise ScenarioContractError("known context without observed optional evidence")
    if metrics.account_state not in (MM05AccountState.ACTIVE, MM05AccountState.DORMANT):
        return result(MM05Status.BLOCKED_ACCOUNT_STATE, "lifecycle_not_evaluable")
    if (
        metrics.prior_count > policy.max_prior_count
        or metrics.prior_value > policy.max_prior_value
    ):
        return result(MM05Status.BASELINE_NOT_DORMANT, "prior_activity_exceeds_policy")
    if not (
        metrics.current_count >= policy.min_current_count
        and metrics.current_value >= policy.min_current_value
        and metrics.current_count - metrics.prior_count >= policy.min_count_increase
        and metrics.current_value - metrics.prior_value >= policy.min_value_increase
    ):
        return result(MM05Status.NO_ACTIVITY_SURGE, "insufficient_count_or_value_shift",
                      evaluated=True)
    context_states = (metrics.reactivation_reason, metrics.scheduled_bulk_activity)
    if MM05Context.REPORTED in context_states:
        return result(MM05Status.CONTEXT_EXCLUSION_REPORTED,
                      "caller_reported_exception_not_verified", evaluated=True)
    if MM05Context.UNKNOWN in context_states:
        return result(MM05Status.CONTEXT_REVIEW_REQUIRED,
                      "optional_exception_context_unknown", evaluated=True)
    return result(MM05Status.SYNTHETIC_CHANGE_HYPOTHESIS,
                  "low_prior_activity_and_current_surge", evaluated=True)
