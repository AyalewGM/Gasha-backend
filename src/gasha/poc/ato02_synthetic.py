"""Inactive ATO-02 synthetic hypothesis: new device and abnormal session activity (#48).

All history, session, reset and policy facts are *caller assertions*, not Bank
evidence. This module is not imported into protected API, worker or prevention.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields, replace
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


def _token(name: str, value: object) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical opaque token required")


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: aware datetime required")
    return value.astimezone(UTC)


def _count(name: str, value: object, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ScenarioContractError(f"{name}: strict bounded integer required")
    return value


class ATO02AuthOutcome(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    CHALLENGED = "challenged"
    UNKNOWN = "unknown"


class ATO02ResetContext(StrEnum):
    UNKNOWN = "unknown_unassessed"
    APPROVED_RESET = "reported_approved_device_reset"
    APPROVED_REENROLMENT = "reported_approved_device_reenrolment"


class ATO02Status(StrEnum):
    BLOCKED_FIELDS = "blocked_required_device_session_fields"
    BLOCKED_POLICY = "blocked_proposed_policy"
    BLOCKED_METRICS = "blocked_device_session_metrics"
    BLOCKED_HISTORY = "blocked_device_history"
    BLOCKED_AUTH = "blocked_authentication_outcome"
    BLOCKED_ANOMALY = "blocked_session_anomaly_evidence"
    LEGITIMATE_RESET = "reported_approved_device_reset_or_reenrolment"
    KNOWN_DEVICE = "known_device_in_claimed_history"
    ORDINARY_SESSION = "session_not_abnormal"
    NOT_RECENT = "first_seen_outside_proposed_window"
    SYNTHETIC_HYPOTHESIS = "synthetic_new_device_abnormal_session_hypothesis"


@dataclass(frozen=True, slots=True)
class ATO02SyntheticPolicy:
    """Explicitly proposed, not approved thresholds."""

    version: str
    configuration_version: str
    minimum_history_days: int
    maximum_new_device_age_seconds: int

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("policy configuration", self.configuration_version)
        if not 1 <= _count("minimum history days", self.minimum_history_days) <= 36_500:
            raise ScenarioContractError("invalid history duration")
        if not 0 <= _count("maximum device age", self.maximum_new_device_age_seconds) <= 86_400:
            raise ScenarioContractError("invalid proposed first-seen age")


@dataclass(frozen=True, slots=True)
class ATO02SyntheticMetrics:
    """Untrusted historical device/login and session anomaly assertions."""

    observation_digest: str
    policy_version: str
    device_ref: str
    first_seen_at: datetime
    history_start: datetime
    history_end: datetime
    history_complete: bool
    prior_device_sessions: int
    authentication_at: datetime
    authentication_outcome: ATO02AuthOutcome
    session_anomalous: bool | None
    available_at: datetime
    reset_context: ATO02ResetContext = ATO02ResetContext.UNKNOWN
    reset_source_ref: str | None = None
    reset_source_version: str | None = None
    reset_observed_at: datetime | None = None
    reset_available_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or not _DIGEST.fullmatch(
            self.observation_digest
        ):
            raise ScenarioContractError("invalid observation digest")
        _token("metrics policy version", self.policy_version)
        _token("device pseudonym", self.device_ref)
        if type(self.history_complete) is not bool:
            raise ScenarioContractError("strict history completeness required")
        _count("prior device sessions", self.prior_device_sessions)
        if type(self.authentication_outcome) is not ATO02AuthOutcome:
            raise ScenarioContractError("typed authentication outcome required")
        if self.session_anomalous is not None and type(self.session_anomalous) is not bool:
            raise ScenarioContractError("typed session anomaly claim required")
        if type(self.reset_context) is not ATO02ResetContext:
            raise ScenarioContractError("typed reset context required")
        for name in (
            "first_seen_at", "history_start", "history_end",
            "authentication_at", "available_at",
        ):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        if not (
            self.history_start < self.history_end <= self.authentication_at
            <= self.available_at
            and self.first_seen_at <= self.authentication_at
        ):
            raise ScenarioContractError("invalid device/session history chronology")
        contextual = (
            self.reset_source_ref, self.reset_source_version,
            self.reset_observed_at, self.reset_available_at,
        )
        if self.reset_context is ATO02ResetContext.UNKNOWN:
            if any(item is not None for item in contextual):
                raise ScenarioContractError("unknown reset cannot assert evidence")
        else:
            _token("reset source", self.reset_source_ref)
            _token("reset version", self.reset_source_version)
            observed = _instant("reset observed", self.reset_observed_at)
            available = _instant("reset available", self.reset_available_at)
            if not observed <= available <= self.authentication_at:
                raise ScenarioContractError("reset not available before authentication")
            object.__setattr__(self, "reset_observed_at", observed)
            object.__setattr__(self, "reset_available_at", available)


def _effective_digest(
    observation_digest: str, policy: ATO02SyntheticPolicy | None,
    metrics: ATO02SyntheticMetrics | None,
) -> str:
    """Domain-separated effective-input identity, NOT an attestation/signature."""

    def encode(value: object) -> object:
        if isinstance(value, datetime):
            return _instant("digest datetime", value).isoformat()
        if isinstance(value, StrEnum):
            return value.value
        return value

    def record(value: ATO02SyntheticPolicy | ATO02SyntheticMetrics | None) -> object:
        if value is None:
            return None
        return {field.name: encode(getattr(value, field.name)) for field in fields(value)}

    payload = {
        "domain": "gasha.ato02.synthetic.effective-input.v1",
        "observation_digest": observation_digest,
        "policy": record(policy), "metrics": record(metrics),
    }
    serialized = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(serialized.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class ATO02SyntheticResult:
    status: ATO02Status
    observation_digest: str
    effective_input_digest: str
    policy_version: str | None
    configuration_version: str
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        """No device, principal, transaction, customer identifier or raw amount."""
        return {
            "scenario_id": "ATO-02",
            "use_case": "UC-01",
            "status": self.status.value,
            "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "effective_input_digest": self.effective_input_digest,
            "policy_version": self.policy_version,
            "configuration_version": self.configuration_version,
            "source": "synthetic_caller_asserted",
            "heuristic_evaluated": self.heuristic_evaluated,
            "bank_verified": False,
            "account_takeover_determined": False,
            "fraud_determined": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
        }


def evaluate_ato02_synthetic(
    observation: ScenarioObservation, *,
    policy: ATO02SyntheticPolicy | None,
    metrics: ATO02SyntheticMetrics | None,
    expected_installation: str,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> ATO02SyntheticResult:
    """Point-in-time shape checks; only an offline scenario hypothesis."""
    coverage = inspect_scenario_coverage(
        observation,
        expected_installation=expected_installation,
        expected_tenant=expected_tenant,
        expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.ATO_02:
        raise ScenarioContractError("ATO-02 observation required")
    if policy is not None:
        if type(policy) is not ATO02SyntheticPolicy:
            raise ScenarioContractError("typed proposed policy required")
        policy = replace(policy)
    if metrics is not None:
        if type(metrics) is not ATO02SyntheticMetrics:
            raise ScenarioContractError("typed session metrics required")
        metrics = replace(metrics)

    def result(
        status: ATO02Status, *reasons: str, evaluated: bool = False,
    ) -> ATO02SyntheticResult:
        return ATO02SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            effective_input_digest=_effective_digest(
                coverage.observation_digest, policy, metrics,
            ),
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(ATO02Status.BLOCKED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(ATO02Status.BLOCKED_POLICY, "proposed_policy_unavailable")
    if metrics is None:
        return result(ATO02Status.BLOCKED_METRICS, "device_history_or_session_unavailable")
    if (
        metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
        or policy.configuration_version != observation.configuration_version
    ):
        raise ScenarioContractError("policy/observation/metrics version mismatch")
    if metrics.authentication_at != observation.occurred_at:
        raise ScenarioContractError("authentication not bound to observed event")
    if metrics.available_at > observation.decision_cutoff:
        raise ScenarioContractError("post-cutoff device/session history")
    # A decision-cutoff check alone cannot prove that required source facts
    # existed when these metrics were assembled. Reject post-snapshot arrivals
    # before any negative, reset exclusion or synthetic positive is reported.
    for field in observation.fields:
        if (
            field.name in SCENARIO_FIELDS[ScenarioId.ATO_02].required
            and field.state is FieldState.OBSERVED
            and field.available_at is not None
            and field.available_at > metrics.available_at
        ):
            return result(
                ATO02Status.BLOCKED_FIELDS,
                f"required_evidence_after_metrics_snapshot:{field.name}",
            )
    if metrics.reset_context is not ATO02ResetContext.UNKNOWN:
        reset = next(
            (field for field in observation.fields if field.name == "approved_device_reset"
             and field.state is FieldState.OBSERVED), None,
        )
        if (
            reset is None or reset.available_at is None
            or metrics.reset_source_ref != reset.source_ref
            or metrics.reset_source_version != reset.source_version
            or metrics.reset_observed_at != reset.observed_at
            or metrics.reset_available_at != reset.available_at
        ):
            raise ScenarioContractError("reset claim not bound to observed optional evidence")
    if (
        not metrics.history_complete
        or metrics.history_end != metrics.authentication_at
        or metrics.history_end - metrics.history_start < timedelta(
            days=policy.minimum_history_days
        )
    ):
        return result(ATO02Status.BLOCKED_HISTORY, "continuous_device_lookback_unproven")
    if metrics.authentication_outcome is not ATO02AuthOutcome.SUCCESS:
        if metrics.authentication_outcome is ATO02AuthOutcome.FAILED:
            return result(ATO02Status.BLOCKED_AUTH, "authentication_not_successful")
        return result(ATO02Status.BLOCKED_AUTH, "authentication_status_unresolved")
    if metrics.session_anomalous is None:
        return result(ATO02Status.BLOCKED_ANOMALY, "session_anomaly_unavailable")
    if metrics.prior_device_sessions > 0:
        return result(ATO02Status.KNOWN_DEVICE, "prior_device_activity_in_declared_history",
                      evaluated=True)
    if not metrics.session_anomalous:
        return result(ATO02Status.ORDINARY_SESSION, "no_session_anomaly_claimed",
                      evaluated=True)
    if observation.occurred_at - metrics.first_seen_at > timedelta(
        seconds=policy.maximum_new_device_age_seconds
    ):
        return result(ATO02Status.NOT_RECENT, "device_first_seen_outside_proposed_window",
                      evaluated=True)
    # A claimed approved reset can exclude only an otherwise qualifying
    # new-device/abnormal-session candidate, never conceal missing facts.
    if metrics.reset_context is not ATO02ResetContext.UNKNOWN:
        return result(ATO02Status.LEGITIMATE_RESET, "reported_approved_device_context",
                      evaluated=True)
    return result(
        ATO02Status.SYNTHETIC_HYPOTHESIS,
        "zero_prior_sessions_in_claimed_continuous_lookback",
        "first_seen_within_proposed_window",
        "session_anomaly_caller_asserted",
        "approved_reset_context_unknown_unassessed",
        evaluated=True,
    )
