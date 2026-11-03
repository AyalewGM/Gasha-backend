"""Inactive APP-02 change-then-unusual-payment synthetic hypothesis (Issues #41/#48).

Every fact, policy and source reference is caller asserted. This code must not be
imported by the protected API, worker, readiness gate or payment adapters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from json import dumps
from uuid import UUID

from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
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


def _token(name: str, value: object) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical opaque token required")


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: timezone-aware datetime required")
    return value.astimezone(UTC)


def _count(name: str, value: object, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ScenarioContractError(f"{name}: strict bounded integer required")
    return value


def _amount(name: str, value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ScenarioContractError(f"{name}: finite Decimal required")
    if not 0 < value <= _MAX_AMOUNT:
        raise ScenarioContractError(f"{name}: positive bounded amount required")
    return value


class APP02ChangeKind(StrEnum):
    DEVICE = "device_change"
    CREDENTIAL = "credential_change"
    PROFILE = "security_profile_change"


class APP02PaymentStatus(StrEnum):
    ATTEMPTED = "attempted"
    POSTED = "posted"
    FAILED = "failed"
    REVERSED = "reversed"
    UNKNOWN = "unknown"


class APP02MaintenanceContext(StrEnum):
    UNKNOWN = "unknown_unassessed"
    REPORTED_ABSENT = "reported_absent"
    REPORTED_APPROVED = "reported_approved_maintenance_or_reset"


class APP02Status(StrEnum):
    BLOCKED_FIELDS = "blocked_required_change_payment_fields"
    BLOCKED_POLICY = "blocked_proposed_policy"
    BLOCKED_METRICS = "blocked_change_payment_metrics"
    BLOCKED_HISTORY = "blocked_point_in_time_amount_baseline"
    BLOCKED_PAYMENT = "blocked_payment_state"
    BLOCKED_CURRENCY = "blocked_currency_comparison"
    BLOCKED_CHRONOLOGY = "blocked_future_change"
    OUTSIDE_WINDOW = "change_outside_proposed_window"
    AMOUNT_ORDINARY = "amount_not_unusual"
    MAINTENANCE_EXCEPTION = "reported_approved_maintenance_context"
    CONTEXT_UNASSESSED = "maintenance_context_unassessed"
    SYNTHETIC_HYPOTHESIS = "synthetic_change_then_unusual_payment_hypothesis"


@dataclass(frozen=True, slots=True)
class APP02SyntheticPolicy:
    """Proposed thresholds; not Bank approved."""

    version: str
    configuration_version: str
    max_change_to_payment_seconds: int
    min_baseline_days: int
    min_baseline_samples: int
    min_payment_amount: Decimal
    min_baseline_multiple: Decimal
    payment_currency: str

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("configuration version", self.configuration_version)
        _count("change window", self.max_change_to_payment_seconds, minimum=1,
               maximum=86_400)
        _count("baseline days", self.min_baseline_days, minimum=1, maximum=36_500)
        _count("baseline samples", self.min_baseline_samples, minimum=1)
        _amount("minimum payment", self.min_payment_amount)
        _amount("baseline multiple", self.min_baseline_multiple)
        if self.min_baseline_multiple <= 1:
            raise ScenarioContractError("unusual-payment multiple must exceed one")
        if type(self.payment_currency) is not str or _CURRENCY.fullmatch(
            self.payment_currency
        ) is None:
            raise ScenarioContractError("canonical proposed floor currency required")


@dataclass(frozen=True, slots=True)
class APP02SyntheticMetrics:
    """Untrusted synthetic source/version, event, baseline and payment assertions."""

    observation_digest: str
    policy_version: str
    payment_event_id: UUID
    change_ref: str
    change_kind: APP02ChangeKind
    change_at: datetime
    change_source_ref: str
    change_source_version: str
    payment_at: datetime
    payment_status: APP02PaymentStatus
    payment_amount: Decimal
    payment_currency: str
    baseline_typical_amount: Decimal
    baseline_currency: str
    baseline_samples: int
    baseline_start: datetime
    baseline_end: datetime
    baseline_complete: bool
    available_at: datetime
    maintenance_context: APP02MaintenanceContext = APP02MaintenanceContext.UNKNOWN
    maintenance_source_ref: str | None = None
    maintenance_source_version: str | None = None
    maintenance_observed_at: datetime | None = None
    maintenance_available_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or _DIGEST.fullmatch(
            self.observation_digest
        ) is None:
            raise ScenarioContractError("valid observation digest required")
        _token("metrics policy", self.policy_version)
        if type(self.payment_event_id) is not UUID:
            raise ScenarioContractError("typed payment event id required")
        for name in ("change_ref", "change_source_ref", "change_source_version"):
            _token(name, getattr(self, name))
        if type(self.change_kind) is not APP02ChangeKind:
            raise ScenarioContractError("typed change kind required")
        if type(self.payment_status) is not APP02PaymentStatus:
            raise ScenarioContractError("typed payment status required")
        if type(self.maintenance_context) is not APP02MaintenanceContext:
            raise ScenarioContractError("typed maintenance context required")
        if type(self.baseline_complete) is not bool:
            raise ScenarioContractError("strict baseline completeness required")
        for name in ("payment_currency", "baseline_currency"):
            value = getattr(self, name)
            if type(value) is not str or _CURRENCY.fullmatch(value) is None:
                raise ScenarioContractError(f"{name}: canonical currency required")
        _amount("payment amount", self.payment_amount)
        _amount("baseline typical amount", self.baseline_typical_amount)
        _count("baseline samples", self.baseline_samples)
        for name in (
            "change_at", "payment_at", "baseline_start", "baseline_end", "available_at",
        ):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        if not (
            self.baseline_start < self.baseline_end <= self.payment_at <= self.available_at
        ):
            raise ScenarioContractError("invalid baseline/payment chronology")
        context = (
            self.maintenance_source_ref, self.maintenance_source_version,
            self.maintenance_observed_at, self.maintenance_available_at,
        )
        if self.maintenance_context is APP02MaintenanceContext.UNKNOWN:
            if any(value is not None for value in context):
                raise ScenarioContractError("unknown maintenance cannot assert source")
        else:
            _token("maintenance source", self.maintenance_source_ref)
            _token("maintenance source version", self.maintenance_source_version)
            observed = _instant("maintenance observed", self.maintenance_observed_at)
            available = _instant("maintenance available", self.maintenance_available_at)
            if not observed <= available <= self.payment_at:
                raise ScenarioContractError("maintenance not available at payment time")
            object.__setattr__(self, "maintenance_observed_at", observed)
            object.__setattr__(self, "maintenance_available_at", available)


def _effective_digest(
    observation_digest: str,
    policy: APP02SyntheticPolicy | None,
    metrics: APP02SyntheticMetrics | None,
) -> str:
    """Domain-separated effective-input identity, NOT attestation or approval."""

    def serialize(value: object) -> object:
        if isinstance(value, datetime):
            return _instant("digest clock", value).isoformat()
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, Decimal):
            return str(value.normalize())
        if isinstance(value, StrEnum):
            return value.value
        return value

    def record(value: APP02SyntheticPolicy | APP02SyntheticMetrics | None) -> object:
        if value is None:
            return None
        return {field.name: serialize(getattr(value, field.name)) for field in fields(value)}

    payload = {
        "domain": "gasha.app02.synthetic.effective-input.v1",
        "observation_digest": observation_digest,
        "policy": record(policy), "metrics": record(metrics),
    }
    canonical = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class APP02SyntheticResult:
    status: APP02Status
    observation_digest: str
    effective_input_digest: str
    policy_version: str | None
    configuration_version: str
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        """Do not disclose change/customer/transaction refs or raw financial amounts."""
        return {
            "scenario_id": "APP-02", "use_case": "UC-03",
            "status": self.status.value, "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "effective_input_digest": self.effective_input_digest,
            "policy_version": self.policy_version,
            "configuration_version": self.configuration_version,
            "source": "synthetic_caller_asserted",
            "heuristic_evaluated": self.heuristic_evaluated,
            "bank_verified": False, "social_engineering_determined": False,
            "fraud_determined": False, "readiness_authorized": False,
            "enforcement_activated": False,
        }


def evaluate_app02_synthetic(
    observation: ScenarioObservation, *,
    policy: APP02SyntheticPolicy | None,
    metrics: APP02SyntheticMetrics | None,
    expected_installation: str,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> APP02SyntheticResult:
    """Evaluate only offline caller-asserted data; no operational wiring."""
    coverage = inspect_scenario_coverage(
        observation, expected_installation=expected_installation,
        expected_tenant=expected_tenant, expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.APP_02:
        raise ScenarioContractError("APP-02 observation required")
    if policy is not None:
        if type(policy) is not APP02SyntheticPolicy:
            raise ScenarioContractError("typed proposed policy required")
        policy = replace(policy)
    if metrics is not None:
        if type(metrics) is not APP02SyntheticMetrics:
            raise ScenarioContractError("typed metrics required")
        metrics = replace(metrics)

    def result(
        status: APP02Status, *reasons: str, evaluated: bool = False,
    ) -> APP02SyntheticResult:
        return APP02SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            effective_input_digest=_effective_digest(
                coverage.observation_digest, policy, metrics,
            ),
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(APP02Status.BLOCKED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(APP02Status.BLOCKED_POLICY, "proposed_policy_missing")
    if metrics is None:
        return result(APP02Status.BLOCKED_METRICS, "change_payment_baseline_unavailable")
    if (
        metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
        or policy.configuration_version != observation.configuration_version
        or metrics.payment_event_id != observation.event_id
        or metrics.payment_at != observation.occurred_at
    ):
        raise ScenarioContractError("observation/event/policy identity mismatch")
    if metrics.available_at > observation.decision_cutoff:
        raise ScenarioContractError("post-cutoff metrics cannot inform payment")
    available = {field.name: field for field in observation.fields
                 if field.state is FieldState.OBSERVED}
    for name in SCENARIO_FIELDS[ScenarioId.APP_02].required:
        evidence = available.get(name)
        if evidence is None or evidence.available_at is None or (
            evidence.available_at > metrics.available_at
        ):
            return result(APP02Status.BLOCKED_FIELDS,
                          f"required_evidence_after_metrics_snapshot:{name}")
    change_evidence = available["authorized_change_event"]
    change_clock = available["change_occurred_at"]
    payment_evidence = available["payment_event"]
    if (
        change_evidence.observed_at != metrics.change_at
        or change_clock.observed_at != metrics.change_at
        or change_evidence.source_ref != metrics.change_source_ref
        or change_evidence.source_version != metrics.change_source_version
        or change_clock.source_ref != metrics.change_source_ref
        or change_clock.source_version != metrics.change_source_version
        or payment_evidence.observed_at != metrics.payment_at
    ):
        raise ScenarioContractError("change or payment source/time evidence mismatch")
    if metrics.maintenance_context is not APP02MaintenanceContext.UNKNOWN:
        maintenance = available.get("approved_maintenance_reset")
        if (
            maintenance is None or maintenance.available_at is None
            or maintenance.source_ref != metrics.maintenance_source_ref
            or maintenance.source_version != metrics.maintenance_source_version
            or maintenance.observed_at != metrics.maintenance_observed_at
            or maintenance.available_at != metrics.maintenance_available_at
            or maintenance.available_at > metrics.available_at
        ):
            raise ScenarioContractError("maintenance claim not bound to optional source")
    if metrics.change_at > metrics.payment_at:
        return result(APP02Status.BLOCKED_CHRONOLOGY,
                      "change_after_payment_cannot_be_historical_feature")
    if (
        not metrics.baseline_complete
        or metrics.baseline_end > metrics.change_at
        or metrics.baseline_end - metrics.baseline_start < timedelta(
            days=policy.min_baseline_days
        )
        or metrics.baseline_samples < policy.min_baseline_samples
    ):
        return result(APP02Status.BLOCKED_HISTORY, "point_in_time_baseline_insufficient")
    if metrics.payment_currency != metrics.baseline_currency or (
        metrics.payment_currency != policy.payment_currency
    ):
        return result(APP02Status.BLOCKED_CURRENCY,
                      "trusted_point_in_time_fx_conversion_unavailable")
    if metrics.payment_status not in (
        APP02PaymentStatus.ATTEMPTED, APP02PaymentStatus.POSTED,
    ):
        return result(APP02Status.BLOCKED_PAYMENT, "payment_not_eligible")
    if metrics.payment_at - metrics.change_at > timedelta(
        seconds=policy.max_change_to_payment_seconds
    ):
        return result(APP02Status.OUTSIDE_WINDOW, "change_before_proposed_window",
                      evaluated=True)
    if not (
        metrics.payment_amount >= policy.min_payment_amount
        and metrics.payment_amount >= (
            metrics.baseline_typical_amount * policy.min_baseline_multiple
        )
    ):
        return result(APP02Status.AMOUNT_ORDINARY, "below_one_or_more_proposed_thresholds",
                      evaluated=True)
    if metrics.maintenance_context is APP02MaintenanceContext.REPORTED_APPROVED:
        return result(APP02Status.MAINTENANCE_EXCEPTION,
                      "caller_reported_approved_context_not_bank_verified", evaluated=True)
    if metrics.maintenance_context is APP02MaintenanceContext.UNKNOWN:
        return result(APP02Status.CONTEXT_UNASSESSED,
                      "maintenance_or_reset_context_unavailable", evaluated=True)
    return result(APP02Status.SYNTHETIC_HYPOTHESIS,
                  "reported_change_precedes_unusual_payment_within_proposed_window",
                  "maintenance_absence_caller_asserted", evaluated=True)
