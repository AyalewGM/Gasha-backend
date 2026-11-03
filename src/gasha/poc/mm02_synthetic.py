"""Inactive UC-02/MM-02 multi-sender beneficiary hypothesis (#41/#48).

Caller-asserted synthetic evidence only. Never imported by protected APIs, decision,
worker, readiness or payment paths. A candidate is not a fraud determination.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
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


def _token(name: str, value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical synthetic reference required")
    return value


def _digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: lowercase digest required")
    return value


def _utc(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: aware timestamp required")
    return value.astimezone(UTC)


class MM02TransferStatus(StrEnum):
    POSTED = "posted"
    SETTLED = "settled"
    PENDING = "pending"
    FAILED = "failed"
    REVERSED = "reversed"


class MM02Institution(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class MM02Context(StrEnum):
    UNKNOWN = "unknown"
    REPORTED = "reported"
    REPORTED_ABSENT = "reported_absent"


class MM02Status(StrEnum):
    BLOCKED_REQUIRED_FIELDS = "blocked_required_fields"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_METRICS = "blocked_metrics"
    BLOCKED_WINDOW = "blocked_window"
    BLOCKED_INSTITUTION = "blocked_institution"
    BLOCKED_TARGET_STATUS = "blocked_target_status"
    BELOW_UNIQUE_SENDER_THRESHOLD = "below_unique_sender_threshold"
    CONTEXT_EXCLUSION_REPORTED = "context_exclusion_reported"
    CONTEXT_REVIEW_REQUIRED = "context_review_required"
    SYNTHETIC_FAN_IN_HYPOTHESIS = "synthetic_fan_in_hypothesis"


@dataclass(frozen=True, slots=True)
class MM02SyntheticPolicy:
    version: str
    configuration_version: str
    window_seconds: int
    min_unique_senders: int

    def __post_init__(self) -> None:
        _token("policy_version", self.version)
        _token("configuration_version", self.configuration_version)
        if type(self.window_seconds) is not int or not 1 <= self.window_seconds <= 86_400:
            raise ScenarioContractError("bounded window seconds required")
        if (type(self.min_unique_senders) is not int
                or not 2 <= self.min_unique_senders <= 10_000):
            raise ScenarioContractError("bounded unique-sender threshold required")


@dataclass(frozen=True, slots=True)
class MM02Transfer:
    """Pseudonymous synthetic source observation, NOT a signed bank ledger entry."""

    event_ref: str
    sender_ref: str
    beneficiary_ref: str
    status: MM02TransferStatus
    occurred_at: datetime
    available_at: datetime
    source_ref: str
    source_version: str
    evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("event_ref", "sender_ref", "beneficiary_ref",
                     "source_ref", "source_version"):
            _token(name, getattr(self, name))
        if type(self.status) is not MM02TransferStatus:
            raise ScenarioContractError("typed transfer status required")
        _digest("transfer evidence", self.evidence_digest)
        occurred = _utc("occurred_at", self.occurred_at)
        available = _utc("available_at", self.available_at)
        if occurred > available:
            raise ScenarioContractError("transfer available before occurrence")
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "available_at", available)


@dataclass(frozen=True, slots=True)
class MM02SyntheticMetrics:
    """Explicitly unverified completeness, source and exception assertions."""

    observation_digest: str
    policy_version: str
    installation_ref: str
    tenant_ref: str
    dataset_digest: str
    beneficiary_ref: str
    window_start: datetime
    window_end: datetime
    available_at: datetime
    window_complete: bool
    deduplicated_event_set: bool
    external_institution: MM02Institution
    transfers: tuple[MM02Transfer, ...]
    sender_baseline: MM02Context = MM02Context.UNKNOWN
    payroll_merchant_exclusion: MM02Context = MM02Context.UNKNOWN

    def __post_init__(self) -> None:
        _digest("observation_digest", self.observation_digest)
        _digest("dataset_digest", self.dataset_digest)
        for name in ("policy_version", "installation_ref", "tenant_ref", "beneficiary_ref"):
            _token(name, getattr(self, name))
        if type(self.window_complete) is not bool or type(self.deduplicated_event_set) is not bool:
            raise ScenarioContractError("strict completeness and deduplication booleans required")
        if type(self.external_institution) is not MM02Institution:
            raise ScenarioContractError("typed external-institution indicator required")
        if (type(self.sender_baseline) is not MM02Context
                or type(self.payroll_merchant_exclusion) is not MM02Context):
            raise ScenarioContractError("typed optional context required")
        for name in ("window_start", "window_end", "available_at"):
            object.__setattr__(self, name, _utc(name, getattr(self, name)))
        if not self.window_start < self.window_end <= self.available_at:
            raise ScenarioContractError("invalid window/availability chronology")
        if type(self.transfers) is not tuple or any(
            type(row) is not MM02Transfer for row in self.transfers
        ):
            raise ScenarioContractError("immutable typed transfer tuple required")
        if len(self.transfers) > 20_000:
            raise ScenarioContractError("synthetic observation count out of bounds")


@dataclass(frozen=True, slots=True)
class MM02SyntheticResult:
    status: MM02Status
    observation_digest: str
    policy_version: str | None
    configuration_version: str
    reasons: tuple[str, ...]
    contributing_events: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": "MM-02", "use_case": "UC-02", "status": self.status.value,
            "reasons": list(self.reasons), "contributing_event_refs": list(self.contributing_events),
            "observation_digest": self.observation_digest,
            "policy_version": self.policy_version,
            "configuration_version": self.configuration_version,
            "source": "synthetic_caller_asserted", "bank_verified": False,
            "fraud_determined": False, "funds_traced": False,
            "readiness_authorized": False, "enforcement_activated": False,
        }


def evaluate_mm02_synthetic(
    observation: ScenarioObservation, *, policy: MM02SyntheticPolicy | None,
    metrics: MM02SyntheticMetrics | None, expected_installation: str,
    expected_tenant: str, expected_dataset_digest: str,
) -> MM02SyntheticResult:
    """Evaluate only synthetic fan-in; never output a risk score or Bank approval."""
    coverage = inspect_scenario_coverage(
        observation, expected_installation=expected_installation,
        expected_tenant=expected_tenant, expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.MM_02:
        raise ScenarioContractError("MM-02 observation required")
    try:
        if policy is not None:
            if type(policy) is not MM02SyntheticPolicy:
                raise ScenarioContractError("exact policy type required")
            policy = replace(policy)
        if metrics is not None:
            if type(metrics) is not MM02SyntheticMetrics:
                raise ScenarioContractError("exact metrics type required")
            metrics = replace(
                metrics, transfers=tuple(replace(transfer) for transfer in metrics.transfers)
            )
    except AttributeError:
        raise ScenarioContractError("missing required synthetic fan-in attribute") from None

    def result(status: MM02Status, *reasons: str,
               events: tuple[str, ...] = ()) -> MM02SyntheticResult:
        return MM02SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            policy_version=policy.version if policy else None,
            configuration_version=observation.configuration_version,
            reasons=tuple(reasons), contributing_events=events,
        )

    if coverage.missing_required:
        return result(MM02Status.BLOCKED_REQUIRED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(MM02Status.BLOCKED_POLICY, "threshold_policy_unavailable")
    if metrics is None:
        return result(MM02Status.BLOCKED_METRICS, "transfer_window_unavailable")
    if (
        metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
        or metrics.installation_ref != expected_installation
        or metrics.tenant_ref != expected_tenant
        or metrics.dataset_digest != expected_dataset_digest
        or policy.configuration_version != observation.configuration_version
    ):
        raise ScenarioContractError("scope/policy/snapshot mismatch")
    if (
        metrics.available_at > observation.decision_cutoff
        or not metrics.window_start <= observation.occurred_at <= metrics.window_end
        or metrics.window_end - metrics.window_start != timedelta(seconds=policy.window_seconds)
    ):
        raise ScenarioContractError("wrong-event, post-cutoff or incorrect window")

    observed = {f.name for f in observation.fields if f.state is FieldState.OBSERVED}
    for key, context in (
        ("sender_baseline", metrics.sender_baseline),
        ("payroll_merchant_exclusion", metrics.payroll_merchant_exclusion),
    ):
        if context is not MM02Context.UNKNOWN and key not in observed:
            raise ScenarioContractError("optional context claimed without observed evidence")

    # Validate all source-event facts before any short-circuit status. Duplicate retries
    # may repeat an identical event; contradictory reuse of an event ID fails closed.
    distinct: dict[str, MM02Transfer] = {}
    for transfer in metrics.transfers:
        if transfer.available_at > observation.decision_cutoff:
            raise ScenarioContractError("late transfer evidence")
        prior = distinct.get(transfer.event_ref)
        if prior is not None and prior != transfer:
            raise ScenarioContractError("conflicting duplicate transaction ID")
        distinct[transfer.event_ref] = transfer
    target = distinct.get(str(observation.event_id))
    if target is None or target.occurred_at != observation.occurred_at:
        raise ScenarioContractError("target event not linked to observed transaction")
    if target.beneficiary_ref != metrics.beneficiary_ref:
        raise ScenarioContractError("target beneficiary mismatch")
    if not metrics.window_complete or not metrics.deduplicated_event_set:
        return result(MM02Status.BLOCKED_WINDOW, "window_or_dedup_claim_unavailable")
    if metrics.external_institution is MM02Institution.UNKNOWN:
        return result(MM02Status.BLOCKED_INSTITUTION, "institution_indicator_unknown")
    if target.status not in (MM02TransferStatus.POSTED, MM02TransferStatus.SETTLED):
        return result(MM02Status.BLOCKED_TARGET_STATUS, "target_not_confirmed")
    in_window = tuple(sorted(
        (
            transfer for transfer in distinct.values()
            if metrics.window_start <= transfer.occurred_at <= metrics.window_end
            and transfer.beneficiary_ref == metrics.beneficiary_ref
            and transfer.status in (MM02TransferStatus.POSTED, MM02TransferStatus.SETTLED)
        ),
        key=lambda row: (row.occurred_at, row.event_ref),
    ))
    senders = {row.sender_ref for row in in_window}
    if len(senders) < policy.min_unique_senders:
        return result(MM02Status.BELOW_UNIQUE_SENDER_THRESHOLD,
                      "insufficient_distinct_confirmed_senders")
    contexts = (metrics.sender_baseline, metrics.payroll_merchant_exclusion)
    if MM02Context.REPORTED in contexts:
        return result(MM02Status.CONTEXT_EXCLUSION_REPORTED,
                      "caller_reported_legitimate_fan_in")
    if MM02Context.UNKNOWN in contexts:
        return result(MM02Status.CONTEXT_REVIEW_REQUIRED,
                      "baseline_or_payroll_context_unavailable")
    return result(
        MM02Status.SYNTHETIC_FAN_IN_HYPOTHESIS, "distinct_confirmed_senders_in_window",
        events=tuple(row.event_ref for row in in_window),
    )
