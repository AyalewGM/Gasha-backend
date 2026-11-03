"""Inactive APP-05 rapid repeated OR escalating payment-attempt hypothesis (#48).

Caller-supplied sequence, policy, completeness and retry context are untrusted.
Never use this module for a Bank decision, action, alert or readiness gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from uuid import UUID

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


class APP05AttemptState(StrEnum):
    ATTEMPTED = "attempted"
    APPROVED = "approved"
    DECLINED = "declined"
    ABANDONED = "abandoned"
    REVERSED = "reversed"
    TECHNICAL_FAILURE = "technical_failure"
    UNKNOWN = "unknown"


class APP05RetryContext(StrEnum):
    UNKNOWN = "unknown"
    REPORTED = "reported"
    REPORTED_ABSENT = "reported_absent"


class APP05Status(StrEnum):
    BLOCKED_REQUIRED_FIELDS = "blocked_required_fields"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_SEQUENCE = "blocked_sequence"
    BLOCKED_CURRENCY = "blocked_currency"
    BLOCKED_STATUS = "blocked_attempt_status"
    INSUFFICIENT_ATTEMPTS = "insufficient_attempts"
    OUTSIDE_WINDOW = "outside_rapid_window"
    AMOUNTS_NOT_ESCALATING = "amounts_not_escalating"
    RETRY_CONTEXT_REVIEW = "technical_retry_context_review_required"
    TECHNICAL_RETRY_REPORTED = "technical_retry_reported"
    SYNTHETIC_HYPOTHESIS = "synthetic_rapid_escalating_attempts_hypothesis"


def _token(name: str, value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: opaque canonical token required")
    return value


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: timezone-aware datetime required")
    return value.astimezone(UTC)


def _count(name: str, value: object, *, minimum: int = 0, maximum: int = 1000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ScenarioContractError(f"{name}: bounded strict integer required")
    return value


def _money(name: str, value: object, *, positive: bool = False) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ScenarioContractError(f"{name}: finite strict Decimal required")
    if value < 0 or (positive and value == 0) or value > _MAX_AMOUNT:
        raise ScenarioContractError(f"{name}: amount outside bounds")
    return value


@dataclass(frozen=True, slots=True)
class APP05SyntheticPolicy:
    """Explicit caller-proposed thresholds; not an approved Bank policy."""

    version: str
    configuration_version: str
    min_attempts: int
    max_window_seconds: int
    min_step_increase: Decimal
    min_total_multiple: Decimal

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("configuration version", self.configuration_version)
        _count("min_attempts", self.min_attempts, minimum=2)
        _count("max_window_seconds", self.max_window_seconds, minimum=1, maximum=86_400)
        _money("min_step_increase", self.min_step_increase, positive=True)
        _money("min_total_multiple", self.min_total_multiple, positive=True)
        if self.min_total_multiple <= 1:
            raise ScenarioContractError("escalation multiple must exceed one")


@dataclass(frozen=True, slots=True)
class APP05Attempt:
    """Pseudonymous synthetic attempt; retries are never inferred from amount alone."""

    event_id: UUID
    occurred_at: datetime
    available_at: datetime
    amount: Decimal
    currency: str
    state: APP05AttemptState
    # Caller assertion only: Bank source/decline reason still require attestation.
    claimed_customer_initiated: bool | None = None

    def __post_init__(self) -> None:
        if type(self.event_id) is not UUID:
            raise ScenarioContractError("attempt event ID must be UUID")
        if type(self.state) is not APP05AttemptState:
            raise ScenarioContractError("typed attempt state required")
        if self.claimed_customer_initiated is not None and (
            type(self.claimed_customer_initiated) is not bool
        ):
            raise ScenarioContractError("typed customer-initiation claim required")
        if type(self.currency) is not str or _CURRENCY.fullmatch(self.currency) is None:
            raise ScenarioContractError("canonical currency required")
        _money("attempt amount", self.amount, positive=True)
        occurred = _instant("attempt occurred_at", self.occurred_at)
        available = _instant("attempt available_at", self.available_at)
        if available < occurred:
            raise ScenarioContractError("attempt available before occurrence")
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "available_at", available)


@dataclass(frozen=True, slots=True)
class APP05SyntheticSequence:
    """Untrusted, claimed-complete correlated sequence, not a Bank event stream."""

    observation_digest: str
    policy_version: str
    correlation_ref: str
    sequence_complete: bool
    attempts: tuple[APP05Attempt, ...]
    technical_retry: APP05RetryContext = APP05RetryContext.UNKNOWN

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or _DIGEST.fullmatch(
            self.observation_digest
        ) is None:
            raise ScenarioContractError("sequence observation digest invalid")
        _token("sequence policy version", self.policy_version)
        _token("correlation reference", self.correlation_ref)
        if type(self.sequence_complete) is not bool:
            raise ScenarioContractError("strict completeness boolean required")
        if type(self.technical_retry) is not APP05RetryContext:
            raise ScenarioContractError("typed retry context required")
        if type(self.attempts) is not tuple or len(self.attempts) > 1000:
            raise ScenarioContractError("bounded immutable attempt tuple required")
        if any(type(item) is not APP05Attempt for item in self.attempts):
            raise ScenarioContractError("untyped attempt in sequence")
        if len({item.event_id for item in self.attempts}) != len(self.attempts):
            raise ScenarioContractError("duplicate attempt event identifier")


@dataclass(frozen=True, slots=True)
class APP05SyntheticResult:
    status: APP05Status
    observation_digest: str
    configuration_version: str
    policy_version: str | None
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        """Exclude event IDs, correlation, amount, account and Bank PII."""
        return {
            "scenario_id": "APP-05",
            "use_case": "UC-03",
            "status": self.status.value,
            "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "configuration_version": self.configuration_version,
            "policy_version": self.policy_version,
            "source": "synthetic_caller_asserted",
            "heuristic_evaluated": self.heuristic_evaluated,
            "bank_verified": False,
            "fraud_determined": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
        }


def evaluate_app05_synthetic(
    observation: ScenarioObservation, *,
    policy: APP05SyntheticPolicy | None,
    sequence: APP05SyntheticSequence | None,
    expected_installation: str,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> APP05SyntheticResult:
    """Evaluate a bounded offline shape/sequence hypothesis, never a fraud verdict."""
    coverage = inspect_scenario_coverage(
        observation, expected_installation=expected_installation,
        expected_tenant=expected_tenant, expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.APP_05:
        raise ScenarioContractError("APP-05 observation required")
    if policy is not None:
        if type(policy) is not APP05SyntheticPolicy:
            raise ScenarioContractError("exact policy type required")
        policy = replace(policy)
    if sequence is not None:
        if type(sequence) is not APP05SyntheticSequence:
            raise ScenarioContractError("exact sequence type required")
        # Frozen dataclasses can be mutated via object.__setattr__ or deserializers.
        # Revalidate every nested attempt at the consumption boundary.
        if type(sequence.attempts) is not tuple:
            raise ScenarioContractError("immutable attempt tuple required")
        if any(type(item) is not APP05Attempt for item in sequence.attempts):
            raise ScenarioContractError("untyped attempt")
        sequence = replace(sequence, attempts=tuple(replace(item) for item in sequence.attempts))

    def result(
        status: APP05Status, *reasons: str, evaluated: bool = False,
    ) -> APP05SyntheticResult:
        return APP05SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(APP05Status.BLOCKED_REQUIRED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(APP05Status.BLOCKED_POLICY, "threshold_policy_unavailable")
    if sequence is None:
        return result(APP05Status.BLOCKED_SEQUENCE, "attempt_sequence_unavailable")
    if (
        sequence.observation_digest != coverage.observation_digest
        or sequence.policy_version != policy.version
        or policy.configuration_version != observation.configuration_version
    ):
        raise ScenarioContractError("policy/sequence/observation version mismatch")
    if not sequence.sequence_complete:
        return result(APP05Status.BLOCKED_SEQUENCE, "correlated_attempt_history_incomplete")
    if not sequence.attempts:
        return result(APP05Status.BLOCKED_SEQUENCE, "no_correlated_attempts")
    ordered = tuple(sorted(sequence.attempts, key=lambda item: (item.occurred_at, item.event_id)))
    if any(
        attempt.available_at > observation.decision_cutoff
        or attempt.occurred_at > observation.decision_cutoff
        for attempt in ordered
    ) or (
        ordered[-1].occurred_at != observation.occurred_at
        or ordered[-1].event_id != observation.event_id
    ):
        raise ScenarioContractError("future/post-cutoff or wrong-event attempt sequence")
    if any(
        left.occurred_at == right.occurred_at
        for left, right in pairwise(ordered)
    ):
        return result(APP05Status.BLOCKED_SEQUENCE, "same_instant_order_ambiguous")
    observed_optional = {
        field.name for field in observation.fields if field.state is FieldState.OBSERVED
    }
    if (
        sequence.technical_retry is not APP05RetryContext.UNKNOWN
        and "technical_retry_indicator" not in observed_optional
    ):
        raise ScenarioContractError("known retry context without observed optional evidence")
    if len({attempt.currency for attempt in ordered}) != 1:
        return result(APP05Status.BLOCKED_CURRENCY, "trusted_point_in_time_fx_unavailable")
    # This is a claimed customer-initiated sequence, not a Bank-attested intent.
    # In particular, a declined customer attempt can be followed by a retry;
    # infrastructure failures, reversals and ambiguous statuses cannot qualify.
    eligible = (
        APP05AttemptState.ATTEMPTED,
        APP05AttemptState.APPROVED,
        APP05AttemptState.DECLINED,
    )
    if any(
        attempt.state not in eligible
        or attempt.claimed_customer_initiated is not True
        for attempt in ordered
    ):
        return result(APP05Status.BLOCKED_STATUS, "unresolved_or_non_customer_attempt")
    if len(ordered) < policy.min_attempts:
        return result(APP05Status.INSUFFICIENT_ATTEMPTS, "below_proposed_attempt_count")
    if ordered[-1].occurred_at - ordered[0].occurred_at > timedelta(
        seconds=policy.max_window_seconds
    ):
        return result(APP05Status.OUTSIDE_WINDOW, "attempt_span_exceeds_proposed_window",
                      evaluated=True)

    # APP-05 is *repeated OR rapidly escalating*. Every escalation is also a
    # repeated-attempt pattern, but there is only one scenario result.
    escalating = (
        all(
            current.amount > previous.amount
            and current.amount - previous.amount >= policy.min_step_increase
            for previous, current in pairwise(ordered)
        )
        and ordered[-1].amount >= ordered[0].amount * policy.min_total_multiple
    )
    pattern_reasons = (
        ("rapid_escalating_attempts", "rapid_repeated_attempts")
        if escalating else ("rapid_repeated_attempts",)
    )
    if sequence.technical_retry is APP05RetryContext.REPORTED:
        return result(APP05Status.TECHNICAL_RETRY_REPORTED,
                      "caller_reported_retry_not_verified", *pattern_reasons,
                      evaluated=True)
    if sequence.technical_retry is APP05RetryContext.UNKNOWN:
        return result(APP05Status.RETRY_CONTEXT_REVIEW,
                      "technical_failure_retry_context_unknown", *pattern_reasons,
                      evaluated=True)
    return result(APP05Status.SYNTHETIC_HYPOTHESIS, *pattern_reasons, evaluated=True)
