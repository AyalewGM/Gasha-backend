"""Versioned channel-enforcement contract for bank executors.

Gasha decides; the bank's integration layer (channel gateway, payment
switch, core banking workflow) enforces. ``EnforcementInstruction`` is the
typed, versioned artifact a channel executor consumes — it is derived
deterministically from a ``FraudDecision`` so an executor can map a stored
or streamed decision at any time without contacting Gasha again.

Shadow envelopes never produce an executable instruction: their effective
action is ``NO_ACTION_SHADOW`` and they map to ``OBSERVE`` while still
carrying the hypothetical decision for offline evidence.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from gasha.decision.mode import DecisionEnvelope
from gasha.domain.models import (
    DecisionAction,
    FraudDecision,
    RiskScore,
)

ENFORCEMENT_SCHEMA_VERSION = "gasha-enforcement-1"


class EnforcementRejected(ValueError):
    """A decision cannot be mapped into an enforcement instruction."""


class EnforcementKind(StrEnum):
    """What a channel executor must do with the transaction."""

    PROCEED = "proceed"  # release/complete the transaction
    PROCEED_WITH_MONITORING = "proceed_with_monitoring"
    STEP_UP = "step_up"  # require additional authentication, then re-decide
    ROUTE_TO_REVIEW = "route_to_review"  # hold completion pending analyst review
    HOLD = "hold"  # suspend; do not complete until released
    DENY = "deny"  # reject the transaction
    OBSERVE = "observe"  # no enforcement — shadow/evaluation record only


_ACTION_TO_KIND: dict[DecisionAction, EnforcementKind] = {
    DecisionAction.ALLOW: EnforcementKind.PROCEED,
    DecisionAction.MONITOR: EnforcementKind.PROCEED_WITH_MONITORING,
    DecisionAction.CHALLENGE: EnforcementKind.STEP_UP,
    DecisionAction.REVIEW: EnforcementKind.ROUTE_TO_REVIEW,
    DecisionAction.HOLD: EnforcementKind.HOLD,
    DecisionAction.BLOCK: EnforcementKind.DENY,
    DecisionAction.NO_ACTION_SHADOW: EnforcementKind.OBSERVE,
}


class EnforcementInstruction(BaseModel):
    """Executable instruction derived from one decision or envelope.

    ``step_up_methods`` is a hint list a channel may satisfy with its own
    mechanism (otp, biometric, manual callback); an empty tuple lets the
    channel choose. ``hold_disposition`` tells the executor what releases a
    held transaction. All policy/model provenance is carried so an executor
    can prove which artifact produced the instruction it enforced.
    """

    schema_version: str = Field(default=ENFORCEMENT_SCHEMA_VERSION, min_length=1)
    kind: EnforcementKind
    action: DecisionAction
    hypothetical_action: DecisionAction | None = None
    tenant_id: str
    event_id: UUID
    correlation_id: str
    risk_score: RiskScore
    reason_codes: list[str]
    step_up_methods: tuple[str, ...] = ()
    hold_disposition: str | None = None
    configuration_version: str
    policy_version: str
    rule_version: str
    model_version: str | None = None
    decided_at: datetime


def enforcement_instruction(decision: FraudDecision) -> EnforcementInstruction:
    """Maps a decision to its channel-executable instruction.

    Unknown or unmapped actions are rejected — an executor must never guess
    at an enforcement meaning. ``NO_ACTION_SHADOW`` decisions map to
    ``OBSERVE``; they describe a shadow record, not something to enforce.
    """
    if type(decision) is not FraudDecision:
        raise EnforcementRejected("typed fraud decision required")
    try:
        kind = _ACTION_TO_KIND[decision.action]
    except KeyError:
        raise EnforcementRejected(
            f"no enforcement mapping for action {decision.action!r}"
        ) from None
    return EnforcementInstruction(
        kind=kind,
        action=decision.action,
        tenant_id=decision.tenant_id,
        event_id=decision.event_id,
        correlation_id=decision.correlation_id,
        risk_score=decision.risk_score,
        reason_codes=list(decision.reason_codes),
        hold_disposition=(
            "pending_release" if kind is EnforcementKind.HOLD else None
        ),
        configuration_version=decision.configuration_version,
        policy_version=decision.policy_version,
        rule_version=decision.rule_version,
        model_version=decision.model_version,
        decided_at=decision.decided_at,
    )


def envelope_instruction(envelope: DecisionEnvelope) -> EnforcementInstruction:
    """Maps a decision envelope to an instruction on its *effective* action.

    Shadow envelopes always produce ``OBSERVE`` — they are evidence of what
    the engine would have done, never an instruction to enforce. The
    hypothetical action is preserved for offline comparison.
    """
    if type(envelope) is not DecisionEnvelope:
        raise EnforcementRejected("typed decision envelope required")
    decision = envelope.decision
    effective = envelope.effective_action
    try:
        kind = _ACTION_TO_KIND[effective]
    except KeyError:
        raise EnforcementRejected(
            f"no enforcement mapping for action {effective!r}"
        ) from None
    return EnforcementInstruction(
        kind=kind,
        action=effective,
        hypothetical_action=(
            decision.action if decision.action is not effective else None
        ),
        tenant_id=decision.tenant_id,
        event_id=decision.event_id,
        correlation_id=decision.correlation_id,
        risk_score=decision.risk_score,
        reason_codes=list(decision.reason_codes),
        hold_disposition=(
            "pending_release" if kind is EnforcementKind.HOLD else None
        ),
        configuration_version=decision.configuration_version,
        policy_version=decision.policy_version,
        rule_version=decision.rule_version,
        model_version=decision.model_version,
        decided_at=decision.decided_at,
    )
