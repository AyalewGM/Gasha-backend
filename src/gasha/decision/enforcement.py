"""Default-off, versioned diagnostic boundary for channel actions.

Gasha's decision is a *recommendation*, not a Bank order or proof of an
executed intervention. Only a trusted, Bank-controlled issuer may eventually
create executable channel instructions. That issuer is deliberately absent
from this offline component until identity, tenant/channel capability,
stage authorization, revocation and request/acknowledgment persistence are
implemented and independently verified under #42/#49.

The public functions below cannot create executable HOLD, DENY or STEP_UP
orders. In particular, a raw hypothetical FraudDecision never supplies a
mode/authorization boundary, even when obtained from a shadow envelope.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from gasha.decision.mode import DecisionEnvelope
from gasha.domain.models import (
    DecisionAction,
    FraudDecision,
    OperatingMode,
    RiskScore,
)

ENFORCEMENT_SCHEMA_VERSION = "gasha-enforcement-1"


class EnforcementRejected(ValueError):
    """An untrusted decision cannot issue or be mistaken for a Bank action."""


class EnforcementKind(StrEnum):
    """Potential channel action names; no public executable issuer exists."""

    PROCEED = "proceed"
    PROCEED_WITH_MONITORING = "proceed_with_monitoring"
    STEP_UP = "step_up"
    ROUTE_TO_REVIEW = "route_to_review"
    HOLD = "hold"
    DENY = "deny"
    OBSERVE = "observe"


class EnforcementInstruction(BaseModel):
    """A non-executable observation, never an authenticated Bank request.

    The original recommendation is retained in ``hypothetical_action``.
    The executable flag has only the literal false value. A future Bank
    request/acknowledgment contract must have separate verified authority and
    persistence; this object must never be consumed as that request.
    """

    schema_version: str = Field(default=ENFORCEMENT_SCHEMA_VERSION, min_length=1)
    kind: EnforcementKind
    action: DecisionAction
    hypothetical_action: DecisionAction | None = None
    executable: Literal[False] = False
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

    @model_validator(mode="after")
    def advisory_only(self) -> EnforcementInstruction:
        if (
            self.kind is not EnforcementKind.OBSERVE
            or self.action is not DecisionAction.NO_ACTION_SHADOW
            or self.hypothetical_action is None
            or self.hold_disposition is not None
            or self.step_up_methods
        ):
            raise ValueError("only non-executable shadow observations are supported")
        return self


def enforcement_instruction(decision: FraudDecision) -> EnforcementInstruction:
    """Reject the legacy raw-decision-to-executable bypass, without fallback.

    A decision never carries an authenticated operating mode, active Bank
    capability or installation scope. Use ``envelope_instruction`` for
    non-executable shadow evidence, not for payment enforcement.
    """
    if type(decision) is not FraudDecision:
        raise EnforcementRejected("typed fraud decision required")
    raise EnforcementRejected("raw decisions are hypothetical, not Bank instructions")


def envelope_instruction(envelope: DecisionEnvelope) -> EnforcementInstruction:
    """Project a verified *shape* of shadow envelope into observation only.

    Even an ENFORCING enum is not Bank authorization: without a trusted
    issuer, it fails closed. No externally asserted policy-reference, model
    manifest, mode or readiness boolean can enable payment instructions.
    """
    if type(envelope) is not DecisionEnvelope:
        raise EnforcementRejected("typed decision envelope required")
    try:
        decision = envelope.decision
        mode = envelope.operating_mode
        effective = envelope.effective_action
    except AttributeError as exc:
        raise EnforcementRejected("malformed decision envelope") from exc
    if (
        type(decision) is not FraudDecision
        or type(mode) is not OperatingMode
        or type(effective) is not DecisionAction
    ):
        raise EnforcementRejected("invalid envelope fields")
    if mode is not OperatingMode.SHADOW:
        raise EnforcementRejected("Bank-authorized executable issuer unavailable")
    if effective is not DecisionAction.NO_ACTION_SHADOW:
        raise EnforcementRejected("shadow envelope cannot carry an effective action")
    if type(decision.action) is not DecisionAction or decision.action is DecisionAction.NO_ACTION_SHADOW:
        raise EnforcementRejected("invalid hypothetical decision action")
    return EnforcementInstruction(
        kind=EnforcementKind.OBSERVE,
        action=DecisionAction.NO_ACTION_SHADOW,
        hypothetical_action=decision.action,
        executable=False,
        tenant_id=decision.tenant_id,
        event_id=decision.event_id,
        correlation_id=decision.correlation_id,
        risk_score=decision.risk_score,
        reason_codes=list(decision.reason_codes),
        configuration_version=decision.configuration_version,
        policy_version=decision.policy_version,
        rule_version=decision.rule_version,
        model_version=decision.model_version,
        decided_at=decision.decided_at,
    )
