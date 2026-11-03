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
    SCENARIO_FIELDS,
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
class MM02FieldClaim:
    """Snapshot-scoped *synthetic* semantic value claim, never Bank provenance."""

    name: str
    source_ref: str
    source_version: str
    evidence_digest: str
    value_digest: str
    snapshot_digest: str
    installation_ref: str
    tenant_ref: str
    dataset_digest: str
    mapping_version: str
    observed_at: datetime
    available_at: datetime

    def __post_init__(self) -> None:
        for name in ("name", "source_ref", "source_version", "installation_ref",
                     "tenant_ref", "mapping_version"):
            _token(name, getattr(self, name))
        for name in ("evidence_digest", "value_digest", "snapshot_digest",
                     "dataset_digest"):
            _digest(name, getattr(self, name))
        for name in ("observed_at", "available_at"):
            object.__setattr__(self, name, _utc(name, getattr(self, name)))
        if self.observed_at > self.available_at:
            raise ScenarioContractError("field claim observed after availability")


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
    field_claims: tuple[MM02FieldClaim, ...] = ()

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
        if type(self.field_claims) is not tuple or any(
            type(claim) is not MM02FieldClaim for claim in self.field_claims
        ):
            raise ScenarioContractError("immutable typed semantic claims required")


def _facts(metrics: MM02SyntheticMetrics) -> list[dict[str, str]]:
    """Canonical, sorted unique event facts; contradictory retries fail closed."""
    unique: dict[str, dict[str, str]] = {}
    for transfer in metrics.transfers:
        fact = {
            "event_ref": transfer.event_ref, "sender_ref": transfer.sender_ref,
            "beneficiary_ref": transfer.beneficiary_ref, "status": transfer.status.value,
            "occurred_at": transfer.occurred_at.astimezone(UTC).isoformat(),
            "available_at": transfer.available_at.astimezone(UTC).isoformat(),
            "source_ref": transfer.source_ref, "source_version": transfer.source_version,
            "evidence_digest": transfer.evidence_digest,
        }
        prior = unique.get(transfer.event_ref)
        if prior is not None and prior != fact:
            raise ScenarioContractError("conflicting duplicate transaction ID")
        unique[transfer.event_ref] = fact
    return [unique[name] for name in sorted(unique)]


def mm02_field_value_digest(name: str, metrics: MM02SyntheticMetrics) -> str:
    """Bind a field's actual semantic values, not only its presence."""
    facts = _facts(metrics)
    values: dict[str, object] = {
        "sender_pseudonym": [
            (f["event_ref"], f["sender_ref"]) for f in facts
        ],
        "beneficiary_pseudonym": {
            "target": metrics.beneficiary_ref,
            "rows": [(f["event_ref"], f["beneficiary_ref"]) for f in facts],
        },
        "transfer_status": [(f["event_ref"], f["status"]) for f in facts],
        "observation_window": {
            "start": metrics.window_start.astimezone(UTC).isoformat(),
            "end": metrics.window_end.astimezone(UTC).isoformat(),
            "available_at": metrics.available_at.astimezone(UTC).isoformat(),
            "rows": [(f["event_ref"], f["occurred_at"], f["available_at"]) for f in facts],
        },
        "window_completeness": metrics.window_complete,
        "deduplicated_event_set": {
            "complete": metrics.deduplicated_event_set, "facts": facts,
        },
        "external_institution_indicator": metrics.external_institution.value,
        "sender_baseline": metrics.sender_baseline.value,
        "payroll_merchant_exclusion": metrics.payroll_merchant_exclusion.value,
    }
    if name not in values:
        raise ScenarioContractError("unknown MM-02 semantic field")
    wire = dumps(
        {"domain": "mm02-synthetic-semantic-v1", "name": name, "value": values[name]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return "sha256:" + sha256(wire.encode("ascii")).hexdigest()


def _validate_claims(
    observation: ScenarioObservation, metrics: MM02SyntheticMetrics,
    snapshot_digest: str,
) -> None:
    """Reject absent, late, spliced or stale caller claims before classification."""
    needed = set(SCENARIO_FIELDS[ScenarioId.MM_02].required)
    for name, context in (
        ("sender_baseline", metrics.sender_baseline),
        ("payroll_merchant_exclusion", metrics.payroll_merchant_exclusion),
    ):
        if context is not MM02Context.UNKNOWN:
            needed.add(name)
    if len(metrics.field_claims) != len(needed) or {
        claim.name for claim in metrics.field_claims
    } != needed:
        raise ScenarioContractError("missing, duplicate or extra semantic field claim")
    sources = {
        field.name: field for field in observation.fields
        if field.state is FieldState.OBSERVED
    }
    for claim in metrics.field_claims:
        source = sources.get(claim.name)
        if source is None:
            raise ScenarioContractError("optional context claimed without observed evidence")
        if (
            claim.source_ref != source.source_ref
            or claim.source_version != source.source_version
            or claim.evidence_digest != source.evidence_digest
            or claim.snapshot_digest != snapshot_digest
            or claim.installation_ref != observation.installation_ref
            or claim.tenant_ref != observation.tenant_ref
            or claim.dataset_digest != observation.dataset_digest
            or claim.mapping_version != observation.mapping_version
            or claim.observed_at != source.observed_at
            or claim.available_at != source.available_at
            or claim.available_at > metrics.available_at
            or claim.value_digest != mm02_field_value_digest(claim.name, metrics)
        ):
            raise ScenarioContractError("inconsistent or late synthetic semantic claim")
    # Source/version/digest on each transfer must refer to the observed
    # transaction-status dataset, not to an arbitrary caller-provided tuple.
    transfer_source = sources["transfer_status"]
    for transfer in metrics.transfers:
        if (
            transfer.source_ref != transfer_source.source_ref
            or transfer.source_version != transfer_source.source_version
            or transfer.evidence_digest != transfer_source.evidence_digest
            or transfer.available_at > metrics.available_at
        ):
            raise ScenarioContractError("late transfer evidence or source mismatch")


def _effective_digest(
    policy: MM02SyntheticPolicy, metrics: MM02SyntheticMetrics,
    snapshot_digest: str,
) -> str:
    """Canonical effective-input identity; opaque hash is NOT authentication."""
    wire = dumps({
        "domain": "mm02-effective-input-v1",
        "snapshot_digest": snapshot_digest,
        "policy": {
            "version": policy.version, "configuration_version": policy.configuration_version,
            "window_seconds": policy.window_seconds,
            "min_unique_senders": policy.min_unique_senders,
        },
        "scope": {
            "installation": metrics.installation_ref, "tenant": metrics.tenant_ref,
            "dataset": metrics.dataset_digest,
        },
        "window": {
            "start": metrics.window_start.astimezone(UTC).isoformat(),
            "end": metrics.window_end.astimezone(UTC).isoformat(),
            "available_at": metrics.available_at.astimezone(UTC).isoformat(),
            "beneficiary": metrics.beneficiary_ref,
            "complete": metrics.window_complete, "dedup": metrics.deduplicated_event_set,
            "institution": metrics.external_institution.value,
            "baseline": metrics.sender_baseline.value,
            "payroll_merchant": metrics.payroll_merchant_exclusion.value,
        },
        "facts": _facts(metrics),
        "claims": [
            {"name": c.name, "source_ref": c.source_ref, "source_version": c.source_version,
             "evidence_digest": c.evidence_digest, "value_digest": c.value_digest,
             "snapshot_digest": c.snapshot_digest,
             "installation_ref": c.installation_ref, "tenant_ref": c.tenant_ref,
             "dataset_digest": c.dataset_digest, "mapping_version": c.mapping_version,
             "observed_at": c.observed_at.astimezone(UTC).isoformat(),
             "available_at": c.available_at.astimezone(UTC).isoformat()}
            for c in sorted(metrics.field_claims, key=lambda item: item.name)
        ],
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(wire.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class MM02SyntheticResult:
    status: MM02Status
    observation_digest: str
    policy_version: str | None
    configuration_version: str
    reasons: tuple[str, ...]
    contributing_events: tuple[str, ...] = ()
    effective_input_digest: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": "MM-02", "use_case": "UC-02", "status": self.status.value,
            "reasons": list(self.reasons), "contributing_event_refs": list(self.contributing_events),
            "observation_digest": self.observation_digest,
            "effective_input_digest": self.effective_input_digest,
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
            # Validate caller-held container and members BEFORE converting/copying.
            if type(metrics.transfers) is not tuple or any(
                type(item) is not MM02Transfer for item in metrics.transfers
            ):
                raise ScenarioContractError("immutable typed transfer tuple required")
            if type(metrics.field_claims) is not tuple or any(
                type(item) is not MM02FieldClaim for item in metrics.field_claims
            ):
                raise ScenarioContractError("immutable typed semantic claims required")
            metrics = replace(
                metrics, transfers=tuple(replace(item) for item in metrics.transfers),
                field_claims=tuple(replace(item) for item in metrics.field_claims),
            )
    except (AttributeError, TypeError):
        raise ScenarioContractError("malformed or missing synthetic fan-in attribute") from None

    effective_input_digest: str | None = None

    def result(status: MM02Status, *reasons: str,
               events: tuple[str, ...] = ()) -> MM02SyntheticResult:
        return MM02SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            policy_version=policy.version if policy else None,
            configuration_version=observation.configuration_version,
            reasons=tuple(reasons), contributing_events=events,
            effective_input_digest=effective_input_digest,
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

    _validate_claims(observation, metrics, coverage.observation_digest)
    effective_input_digest = _effective_digest(policy, metrics, coverage.observation_digest)

    # Validate all source-event facts before any short-circuit status. Duplicate retries
    # may repeat an identical event; contradictory reuse of an event ID fails closed.
    distinct: dict[str, MM02Transfer] = {}
    for transfer in metrics.transfers:
        if transfer.available_at > metrics.available_at:
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
