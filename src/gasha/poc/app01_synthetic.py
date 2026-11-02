"""Inactive APP-01 first-beneficiary/large-payment synthetic hypothesis (#48).

All values, window-completeness claims and thresholds are caller assertions.
Never wire this into a Bank API, alert, readiness gate, or enforcement path.
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
_MAX_AMOUNT = Decimal("1e18")


class APP01Context(StrEnum):
    UNKNOWN = "unknown"
    REPORTED = "reported"
    REPORTED_ABSENT = "reported_absent"


class APP01History(StrEnum):
    UNKNOWN = "unknown"
    INCOMPLETE = "incomplete"
    COMPLETE = "complete"


class APP01PaymentState(StrEnum):
    ATTEMPTED = "attempted"
    POSTED = "posted"
    REJECTED = "rejected"
    REVERSED = "reversed"
    UNKNOWN = "unknown"


class APP01Status(StrEnum):
    BLOCKED_REQUIRED_FIELDS = "blocked_required_fields"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_METRICS = "blocked_metrics"
    BLOCKED_HISTORY = "blocked_history"
    BLOCKED_CURRENCY = "blocked_currency"
    BLOCKED_PAYMENT_STATE = "blocked_payment_state"
    BENEFICIARY_NOT_NEW = "beneficiary_not_new_in_covered_history"
    AMOUNT_NOT_UNUSUAL = "amount_not_unusual"
    CONTEXT_REVIEW_REQUIRED = "context_review_required"
    CONTEXT_EXCEPTION_REPORTED = "context_exception_reported"
    SYNTHETIC_HYPOTHESIS = "synthetic_first_beneficiary_large_amount_hypothesis"


def _token(name: str, value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical opaque token required")
    return value


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: timezone-aware datetime required")
    return value.astimezone(UTC)


def _count(name: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 1_000_000:
        raise ScenarioContractError(f"{name}: bounded integer required")
    return value


def _amount(name: str, value: object, *, positive: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ScenarioContractError(f"{name}: finite strict Decimal required")
    if value < 0 or (positive and value == 0) or value > _MAX_AMOUNT:
        raise ScenarioContractError(f"{name}: amount outside bounds")
    return value


@dataclass(frozen=True, slots=True)
class APP01SyntheticPolicy:
    """Explicit proposed thresholds, never an approved Bank policy."""

    version: str
    configuration_version: str
    min_history_days: int
    min_baseline_samples: int
    min_payment_amount: Decimal
    min_baseline_multiple: Decimal

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("configuration version", self.configuration_version)
        if not 1 <= _count("min_history_days", self.min_history_days) <= 36_500:
            raise ScenarioContractError("history days exceed synthetic safety bound")
        _count("min_baseline_samples", self.min_baseline_samples, minimum=1)
        _amount("min_payment_amount", self.min_payment_amount, positive=True)
        _amount("min_baseline_multiple", self.min_baseline_multiple, positive=True)
        if self.min_baseline_multiple <= 1:
            raise ScenarioContractError("large-payment multiple must exceed one")


@dataclass(frozen=True, slots=True)
class APP01SyntheticMetrics:
    """Untrusted aggregate and first-seen claims, never raw beneficiary details."""

    observation_digest: str
    policy_version: str
    beneficiary_ref: str
    payment_currency: str
    baseline_currency: str
    payment_state: APP01PaymentState
    payment_amount: Decimal
    history_state: APP01History
    history_start: datetime
    history_end: datetime
    beneficiary_first_seen_at: datetime
    prior_beneficiary_payments: int
    baseline_typical_amount: Decimal
    baseline_sample_count: int
    baseline_as_of: datetime
    available_at: datetime
    recurring_payment: APP01Context = APP01Context.UNKNOWN

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or _DIGEST.fullmatch(
            self.observation_digest
        ) is None:
            raise ScenarioContractError("metrics observation digest invalid")
        _token("metrics policy version", self.policy_version)
        _token("beneficiary reference", self.beneficiary_ref)
        for name in ("payment_currency", "baseline_currency"):
            value = getattr(self, name)
            if type(value) is not str or _CURRENCY.fullmatch(value) is None:
                raise ScenarioContractError(f"{name}: ISO-style currency code required")
        if type(self.payment_state) is not APP01PaymentState:
            raise ScenarioContractError("typed payment state required")
        if type(self.history_state) is not APP01History:
            raise ScenarioContractError("typed history completeness required")
        if type(self.recurring_payment) is not APP01Context:
            raise ScenarioContractError("typed optional recurring context required")
        _amount("payment_amount", self.payment_amount, positive=True)
        _amount("baseline_typical_amount", self.baseline_typical_amount, positive=True)
        _count("prior_beneficiary_payments", self.prior_beneficiary_payments)
        _count("baseline_sample_count", self.baseline_sample_count)
        for name in (
            "history_start", "history_end", "beneficiary_first_seen_at",
            "baseline_as_of", "available_at",
        ):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        if not (
            self.history_start <= self.beneficiary_first_seen_at
            <= self.history_end <= self.available_at
            and self.history_start < self.history_end
            and self.baseline_as_of <= self.available_at
        ):
            raise ScenarioContractError("invalid history/baseline availability chronology")


@dataclass(frozen=True, slots=True)
class APP01SyntheticResult:
    status: APP01Status
    observation_digest: str
    configuration_version: str
    policy_version: str | None
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        """No customer, beneficiary, transaction, amount or FX details in the report."""
        return {
            "scenario_id": "APP-01", "use_case": "UC-03",
            "status": self.status.value, "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "configuration_version": self.configuration_version,
            "policy_version": self.policy_version,
            "source": "synthetic_caller_asserted",
            "heuristic_evaluated": self.heuristic_evaluated,
            "bank_verified": False, "fraud_determined": False,
            "readiness_authorized": False, "enforcement_activated": False,
        }


def evaluate_app01_synthetic(
    observation: ScenarioObservation, *,
    policy: APP01SyntheticPolicy | None,
    metrics: APP01SyntheticMetrics | None,
    expected_installation: str,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> APP01SyntheticResult:
    """Evaluate only an offline synthetic candidate with point-in-time shape guards."""
    coverage = inspect_scenario_coverage(
        observation, expected_installation=expected_installation,
        expected_tenant=expected_tenant, expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.APP_01:
        raise ScenarioContractError("APP-01 observation required")
    if policy is not None:
        if type(policy) is not APP01SyntheticPolicy:
            raise ScenarioContractError("exact policy type required")
        policy = replace(policy)
    if metrics is not None:
        if type(metrics) is not APP01SyntheticMetrics:
            raise ScenarioContractError("exact metrics type required")
        metrics = replace(metrics)

    def result(
        status: APP01Status, *reasons: str, evaluated: bool = False,
    ) -> APP01SyntheticResult:
        return APP01SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(APP01Status.BLOCKED_REQUIRED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(APP01Status.BLOCKED_POLICY, "threshold_policy_unavailable")
    if metrics is None:
        return result(APP01Status.BLOCKED_METRICS, "payment_or_history_unavailable")
    if (
        metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
        or policy.configuration_version != observation.configuration_version
    ):
        raise ScenarioContractError("policy/metrics/observation version mismatch")
    if not (
        metrics.history_end == observation.occurred_at
        and metrics.beneficiary_first_seen_at <= observation.occurred_at
        and metrics.baseline_as_of <= observation.occurred_at
        and metrics.available_at <= observation.decision_cutoff
    ):
        raise ScenarioContractError("wrong-event or post-cutoff history/baseline")
    if (
        metrics.history_end - metrics.history_start
        < timedelta(days=policy.min_history_days)
        or metrics.history_state is not APP01History.COMPLETE
    ):
        return result(APP01Status.BLOCKED_HISTORY, "beneficiary_history_not_complete")
    if metrics.payment_currency != metrics.baseline_currency:
        return result(APP01Status.BLOCKED_CURRENCY, "trusted_point_in_time_fx_unavailable")
    if metrics.payment_state not in (
        APP01PaymentState.ATTEMPTED, APP01PaymentState.POSTED,
    ):
        return result(APP01Status.BLOCKED_PAYMENT_STATE, "payment_not_eligible")
    if metrics.baseline_sample_count < policy.min_baseline_samples:
        return result(APP01Status.BLOCKED_METRICS, "customer_baseline_insufficient")
    available_optional = {
        field.name for field in observation.fields if field.state is FieldState.OBSERVED
    }
    if (
        metrics.recurring_payment is not APP01Context.UNKNOWN
        and "expected_recurring_payment" not in available_optional
    ):
        raise ScenarioContractError("known context without observed optional evidence")
    if metrics.prior_beneficiary_payments != 0:
        return result(APP01Status.BENEFICIARY_NOT_NEW, "prior_transfer_in_covered_history")
    if not (
        metrics.payment_amount >= policy.min_payment_amount
        and metrics.payment_amount
        >= metrics.baseline_typical_amount * policy.min_baseline_multiple
    ):
        return result(APP01Status.AMOUNT_NOT_UNUSUAL, "below_one_or_more_proposed_thresholds",
                      evaluated=True)
    if metrics.recurring_payment is APP01Context.REPORTED:
        return result(APP01Status.CONTEXT_EXCEPTION_REPORTED,
                      "caller_reported_recurring_not_verified", evaluated=True)
    if metrics.recurring_payment is APP01Context.UNKNOWN:
        return result(APP01Status.CONTEXT_REVIEW_REQUIRED,
                      "recurring_payment_context_unknown", evaluated=True)
    return result(APP01Status.SYNTHETIC_HYPOTHESIS,
                  "first_transfer_in_covered_history_and_unusual_amount", evaluated=True)
