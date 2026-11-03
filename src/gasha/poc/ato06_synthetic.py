"""Inactive ATO-06 beneficiary-addition to rapid-transfer synthetic hypothesis (#48).

Inputs and thresholds are caller assertions, not Bank provenance or fraud findings.
No API, worker, case, readiness, scoring or enforcement integration is permitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields as dataclass_fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from hashlib import sha256
from json import dumps

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


class ATO06BeneficiaryStatus(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class ATO06TransferStatus(StrEnum):
    ATTEMPTED = "attempted"
    EXECUTED = "executed"
    SETTLED = "settled"
    REVERSED = "reversed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ATO06MaintenanceContext(StrEnum):
    UNKNOWN = "unknown_unavailable"
    REPORTED_ABSENT = "reported_absent"
    PLANNED_SETUP = "planned_beneficiary_setup"
    APPROVED_PAYEE_MIGRATION = "approved_payee_migration_import"
    PAYROLL_VENDOR_ENROLLMENT = "payroll_vendor_enrollment"
    BANK_ADMIN_CORRECTION = "bank_admin_correction"


class ATO06RetryContext(StrEnum):
    UNKNOWN = "unknown_unavailable"
    REPORTED_NOT_RETRY = "reported_not_technical_retry"
    TECHNICAL_RETRY = "reported_technical_retry"


class ATO06Status(StrEnum):
    BLOCKED_REQUIRED_FIELDS = "blocked_required_fields"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_METRICS = "blocked_metrics"
    BLOCKED_HISTORY = "blocked_beneficiary_history"
    BLOCKED_STATUS = "blocked_beneficiary_or_transfer_status"
    BLOCKED_SETTLEMENT = "blocked_execution_or_settlement_evidence"
    BLOCKED_CURRENCY = "blocked_transfer_currency_unit_mismatch"
    BLOCKED_ATTEMPT_LINEAGE = "blocked_attempt_deduplication"
    CONTEXTUAL_EXCLUSION = "reported_legitimate_context_or_technical_retry"
    OUTSIDE_WINDOW = "outside_proposed_addition_transfer_window"
    ADDITION_NOT_UNUSUAL = "beneficiary_addition_not_unusual_in_covered_window"
    AMOUNT_BELOW_FLOOR = "amount_below_proposed_floor"
    SYNTHETIC_HYPOTHESIS = "synthetic_unusual_beneficiary_addition_rapid_transfer_hypothesis"


def _token(name: str, value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical opaque token required")
    return value


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: timezone-aware datetime required")
    return value.astimezone(UTC)


def _count(name: str, value: object, *, maximum: int = 1_000_000) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ScenarioContractError(f"{name}: bounded strict integer required")
    return value


def _amount(name: str, value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ScenarioContractError(f"{name}: finite strict Decimal required")
    if value <= 0 or value > _MAX_AMOUNT:
        raise ScenarioContractError(f"{name}: positive bounded amount required")
    return value


@dataclass(frozen=True, slots=True)
class ATO06SyntheticPolicy:
    """Proposed policy; never a Bank-approved threshold or control."""

    version: str
    configuration_version: str
    max_addition_to_transfer_seconds: int
    min_history_days: int
    max_prior_beneficiary_additions: int
    min_transfer_amount: Decimal
    min_transfer_currency: str

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("policy configuration", self.configuration_version)
        if not 1 <= _count("transfer window", self.max_addition_to_transfer_seconds) <= 86_400:
            raise ScenarioContractError("invalid proposed transfer window")
        if not 1 <= _count("history days", self.min_history_days) <= 36_500:
            raise ScenarioContractError("invalid proposed history period")
        _count("prior additions maximum", self.max_prior_beneficiary_additions)
        _amount("minimum transfer amount", self.min_transfer_amount)
        if type(self.min_transfer_currency) is not str or _CURRENCY.fullmatch(
            self.min_transfer_currency
        ) is None:
            raise ScenarioContractError("canonical proposed floor currency required")


@dataclass(frozen=True, slots=True)
class ATO06SyntheticMetrics:
    """Untrusted, pseudonymous lifecycle, baseline and transfer claims."""

    observation_digest: str
    policy_version: str
    beneficiary_ref: str
    beneficiary_created_at: datetime
    beneficiary_activated_at: datetime
    beneficiary_status: ATO06BeneficiaryStatus
    history_start: datetime
    history_end: datetime
    history_complete: bool
    prior_beneficiary_additions: int
    transfer_attempted_at: datetime
    transfer_status: ATO06TransferStatus
    transfer_amount: Decimal
    transfer_currency: str
    available_at: datetime
    attempt_deduplicated: bool
    maintenance_context: ATO06MaintenanceContext
    retry_context: ATO06RetryContext = ATO06RetryContext.UNKNOWN
    maintenance_source_ref: str | None = None
    maintenance_source_version: str | None = None
    maintenance_observed_at: datetime | None = None
    maintenance_available_at: datetime | None = None
    transfer_executed_at: datetime | None = None
    transfer_settled_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or _DIGEST.fullmatch(
            self.observation_digest
        ) is None:
            raise ScenarioContractError("invalid observation digest")
        _token("metrics policy version", self.policy_version)
        _token("beneficiary reference", self.beneficiary_ref)
        if type(self.beneficiary_status) is not ATO06BeneficiaryStatus:
            raise ScenarioContractError("typed beneficiary status required")
        if type(self.transfer_status) is not ATO06TransferStatus:
            raise ScenarioContractError("typed transfer status required")
        if type(self.history_complete) is not bool:
            raise ScenarioContractError("strict history completeness boolean required")
        if type(self.transfer_currency) is not str or _CURRENCY.fullmatch(
            self.transfer_currency
        ) is None:
            raise ScenarioContractError("canonical transfer currency required")
        _count("prior beneficiary additions", self.prior_beneficiary_additions)
        _amount("transfer amount", self.transfer_amount)
        if type(self.attempt_deduplicated) is not bool:
            raise ScenarioContractError("strict attempt deduplication boolean required")
        if type(self.maintenance_context) is not ATO06MaintenanceContext:
            raise ScenarioContractError("typed maintenance context required")
        if type(self.retry_context) is not ATO06RetryContext:
            raise ScenarioContractError("typed retry context required")
        context_fields = (
            self.maintenance_source_ref, self.maintenance_source_version,
            self.maintenance_observed_at, self.maintenance_available_at,
        )
        if self.maintenance_context is ATO06MaintenanceContext.UNKNOWN:
            if any(value is not None for value in context_fields):
                raise ScenarioContractError("unknown context cannot claim observed evidence")
        else:
            _token("maintenance source", self.maintenance_source_ref)
            _token("maintenance version", self.maintenance_source_version)
            observed = _instant("maintenance observed", self.maintenance_observed_at)
            available = _instant("maintenance available", self.maintenance_available_at)
            if observed > available:
                raise ScenarioContractError("maintenance observed after availability")
            object.__setattr__(self, "maintenance_observed_at", observed)
            object.__setattr__(self, "maintenance_available_at", available)
        for name in (
            "beneficiary_created_at", "beneficiary_activated_at", "history_start",
            "history_end", "transfer_attempted_at", "available_at",
        ):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        for name in ("transfer_executed_at", "transfer_settled_at"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _instant(name, value))
        if not (
            self.history_start < self.history_end <= self.beneficiary_created_at
            <= self.beneficiary_activated_at <= self.transfer_attempted_at
            <= self.available_at
        ):
            raise ScenarioContractError("invalid beneficiary/history/attempt chronology")
        if self.maintenance_available_at is not None and (
            self.maintenance_available_at > self.transfer_attempted_at
            or self.maintenance_available_at > self.available_at
        ):
            raise ScenarioContractError("maintenance context unavailable at attempted transfer")
        executed, settled = self.transfer_executed_at, self.transfer_settled_at
        if executed is not None and not (
            self.transfer_attempted_at <= executed <= self.available_at
        ):
            raise ScenarioContractError("invalid execution chronology")
        if settled is not None and (
            executed is None or not executed <= settled <= self.available_at
        ):
            raise ScenarioContractError("invalid settlement chronology")
        if self.transfer_status is ATO06TransferStatus.EXECUTED and executed is None:
            raise ScenarioContractError("executed transfer requires execution timestamp")
        if self.transfer_status is ATO06TransferStatus.SETTLED and settled is None:
            raise ScenarioContractError("settled transfer requires settlement timestamp")
        if self.transfer_status is ATO06TransferStatus.ATTEMPTED and (
            executed is not None or settled is not None
        ):
            raise ScenarioContractError("attempted transfer must not claim later execution")
        if self.transfer_status is ATO06TransferStatus.EXECUTED and settled is not None:
            raise ScenarioContractError("executed transfer must not claim settlement")


def _evaluation_fingerprint(
    observation_digest: str,
    policy: ATO06SyntheticPolicy | None,
    metrics: ATO06SyntheticMetrics | None,
) -> str:
    """Canonical effective-input identity; NOT a signed approval or Bank attestation."""

    def value(item: object) -> object:
        if isinstance(item, datetime):
            return _instant("fingerprint instant", item).isoformat()
        if isinstance(item, Decimal):
            return str(item.normalize())
        if isinstance(item, StrEnum):
            return item.value
        return item

    def record(item: ATO06SyntheticPolicy | ATO06SyntheticMetrics | None) -> object:
        if item is None:
            return None
        return {field.name: value(getattr(item, field.name))
                for field in dataclass_fields(item)}

    payload = {
        "domain": "gasha.ato06.synthetic.effective-input.v1",
        "observation_digest": observation_digest,
        "policy": record(policy),
        "metrics": record(metrics),
    }
    canonical = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class ATO06SyntheticResult:
    status: ATO06Status
    observation_digest: str
    effective_input_digest: str
    configuration_version: str
    policy_version: str | None
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": "ATO-06",
            "use_case": "UC-01",
            "status": self.status.value,
            "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "effective_input_digest": self.effective_input_digest,
            "configuration_version": self.configuration_version,
            "policy_version": self.policy_version,
            "source": "synthetic_caller_asserted",
            "heuristic_evaluated": self.heuristic_evaluated,
            "bank_verified": False,
            "fraud_determined": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
        }


def evaluate_ato06_synthetic(
    observation: ScenarioObservation, *,
    policy: ATO06SyntheticPolicy | None,
    metrics: ATO06SyntheticMetrics | None,
    expected_installation: str,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> ATO06SyntheticResult:
    """Strict point-in-time shape validation; no Bank action or scoring."""
    coverage = inspect_scenario_coverage(
        observation, expected_installation=expected_installation,
        expected_tenant=expected_tenant, expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.ATO_06:
        raise ScenarioContractError("ATO-06 observation required")
    if policy is not None:
        if type(policy) is not ATO06SyntheticPolicy:
            raise ScenarioContractError("typed policy required")
        policy = replace(policy)
    if metrics is not None:
        if type(metrics) is not ATO06SyntheticMetrics:
            raise ScenarioContractError("typed metrics required")
        metrics = replace(metrics)

    def result(status: ATO06Status, *reasons: str, evaluated: bool = False) -> ATO06SyntheticResult:
        return ATO06SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            effective_input_digest=_evaluation_fingerprint(
                coverage.observation_digest, policy, metrics,
            ),
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(ATO06Status.BLOCKED_REQUIRED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(ATO06Status.BLOCKED_POLICY, "proposed_policy_missing")
    if metrics is None:
        return result(ATO06Status.BLOCKED_METRICS, "beneficiary_transfer_metrics_missing")
    if (
        metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
        or policy.configuration_version != observation.configuration_version
    ):
        raise ScenarioContractError("policy/metrics/observation version mismatch")
    if metrics.maintenance_context is not ATO06MaintenanceContext.UNKNOWN and (
        metrics.maintenance_source_ref != observation.source_system
        or metrics.maintenance_source_version != observation.source_schema_version
        or metrics.maintenance_available_at is None
        or metrics.maintenance_available_at > observation.decision_cutoff
    ):
        raise ScenarioContractError("maintenance source/version/cutoff mismatch")
    if metrics.transfer_attempted_at != observation.occurred_at:
        raise ScenarioContractError("transfer attempt not bound to observed event")
    if metrics.available_at > observation.decision_cutoff:
        raise ScenarioContractError("post-cutoff metrics unavailable at decision time")
    optional = {
        field.name: field for field in observation.fields
        if field.state is FieldState.OBSERVED
    }
    creation = optional.get("beneficiary_created_at")
    if creation is None or creation.available_at is None or (
        creation.available_at > metrics.available_at
    ):
        return result(ATO06Status.BLOCKED_REQUIRED_FIELDS,
                      "beneficiary_addition_evidence_unavailable")
    for name, event_time in (
        ("transfer_executed_at", metrics.transfer_executed_at),
        ("transfer_settled_at", metrics.transfer_settled_at),
    ):
        if event_time is None:
            continue
        evidence = optional.get(name)
        if evidence is None:
            raise ScenarioContractError(f"{name} claimed without observed evidence")
        if (
            evidence.observed_at is None
            or evidence.available_at is None
            or evidence.observed_at < event_time
            or evidence.available_at < event_time
            or evidence.available_at > metrics.available_at
        ):
            raise ScenarioContractError(f"{name} impossible evidence availability")
    if metrics.transfer_status is ATO06TransferStatus.EXECUTED and (
        "transfer_executed_at" not in optional
    ):
        return result(ATO06Status.BLOCKED_SETTLEMENT, "execution_evidence_unavailable")
    if metrics.transfer_status is ATO06TransferStatus.SETTLED and (
        "transfer_executed_at" not in optional or "transfer_settled_at" not in optional
    ):
        return result(ATO06Status.BLOCKED_SETTLEMENT, "settlement_evidence_unavailable")
    if metrics.beneficiary_status is not ATO06BeneficiaryStatus.ACTIVE or (
        metrics.transfer_status not in (
            ATO06TransferStatus.ATTEMPTED,
            ATO06TransferStatus.EXECUTED,
            ATO06TransferStatus.SETTLED,
        )
    ):
        return result(ATO06Status.BLOCKED_STATUS, "unresolved_lifecycle_or_transfer_status")
    if not metrics.history_complete or (
        metrics.history_end != metrics.beneficiary_created_at
        or metrics.history_end - metrics.history_start < timedelta(
            days=policy.min_history_days
        )
    ):
        return result(ATO06Status.BLOCKED_HISTORY, "beneficiary_baseline_not_complete")
    if metrics.transfer_currency != policy.min_transfer_currency:
        return result(ATO06Status.BLOCKED_CURRENCY,
                      "proposed_amount_floor_currency_mismatch")
    if not metrics.attempt_deduplicated:
        return result(ATO06Status.BLOCKED_ATTEMPT_LINEAGE,
                      "attempt_uniqueness_unverified")
    if metrics.maintenance_context not in (
        ATO06MaintenanceContext.UNKNOWN, ATO06MaintenanceContext.REPORTED_ABSENT,
    ):
        return result(ATO06Status.CONTEXTUAL_EXCLUSION,
                      "reported_applicable_legitimate_maintenance_context",
                      evaluated=True)
    if metrics.retry_context is ATO06RetryContext.TECHNICAL_RETRY:
        return result(ATO06Status.CONTEXTUAL_EXCLUSION,
                      "reported_technical_retry", evaluated=True)
    if metrics.prior_beneficiary_additions > policy.max_prior_beneficiary_additions:
        return result(ATO06Status.ADDITION_NOT_UNUSUAL,
                      "addition_not_rare_in_proposed_baseline", evaluated=True)
    if metrics.transfer_attempted_at - metrics.beneficiary_created_at > timedelta(
        seconds=policy.max_addition_to_transfer_seconds
    ):
        return result(ATO06Status.OUTSIDE_WINDOW, "attempt_outside_proposed_window",
                      evaluated=True)
    if metrics.transfer_amount < policy.min_transfer_amount:
        return result(ATO06Status.AMOUNT_BELOW_FLOOR, "below_proposed_transfer_floor",
                      evaluated=True)
    return result(
        ATO06Status.SYNTHETIC_HYPOTHESIS,
        "low_addition_frequency_in_claimed_precreation_baseline",
        "addition_to_attempt_within_proposed_window",
        *(
            ("maintenance_context_unknown_unassessed",)
            if metrics.maintenance_context is ATO06MaintenanceContext.UNKNOWN else ()
        ),
        *(
            ("retry_context_unknown_unassessed",)
            if metrics.retry_context is ATO06RetryContext.UNKNOWN else ()
        ),
        evaluated=True,
    )
