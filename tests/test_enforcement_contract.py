"""Channel-enforcement contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.decision.enforcement import (
    ENFORCEMENT_SCHEMA_VERSION,
    EnforcementKind,
    EnforcementRejected,
    enforcement_instruction,
    envelope_instruction,
)
from gasha.decision.mode import ModeAwareDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
    OperatingMode,
)

POLICY = DecisionPolicy(
    configuration_version="cfg-v1",
    policy_version="rules-v1",
    rule_version="rules-v1",
    challenge_threshold=0.60,
)


def tx() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=UUID(int=1),
        occurred_at=datetime(2026, 1, 1, 9, tzinfo=UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(500),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-1",
    )


def decide(score: float) -> FraudDecision:
    return DecisionService(POLICY).decide(tx(), IntelligenceSnapshot(transaction_risk=score))


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.10, EnforcementKind.PROCEED),
        (0.55, EnforcementKind.PROCEED_WITH_MONITORING),
        (0.65, EnforcementKind.STEP_UP),
        (0.75, EnforcementKind.ROUTE_TO_REVIEW),
        (0.90, EnforcementKind.HOLD),
        (0.98, EnforcementKind.DENY),
    ],
)
def test_action_to_enforcement_mapping(score: float, expected: EnforcementKind) -> None:
    instruction = enforcement_instruction(decide(score))
    assert instruction.kind is expected
    assert instruction.schema_version == ENFORCEMENT_SCHEMA_VERSION
    assert instruction.hypothetical_action is None


def test_instruction_carries_provenance_for_the_executor() -> None:
    instruction = enforcement_instruction(decide(0.98))
    assert instruction.action is DecisionAction.BLOCK
    assert instruction.tenant_id == "tenant-a"
    assert instruction.policy_version == "rules-v1"
    assert instruction.reason_codes
    assert instruction.hold_disposition is None


def test_hold_disposition_tells_executor_how_to_release() -> None:
    instruction = enforcement_instruction(decide(0.90))
    assert instruction.kind is EnforcementKind.HOLD
    assert instruction.hold_disposition == "pending_release"


def test_instruction_rejects_wrong_type() -> None:
    with pytest.raises(EnforcementRejected):
        enforcement_instruction(object())  # type: ignore[arg-type]


def test_shadow_envelope_never_produces_enforcement() -> None:
    envelope = ModeAwareDecisionService(
        POLICY, operating_mode=OperatingMode.SHADOW
    ).decide(tx(), IntelligenceSnapshot(transaction_risk=0.98))
    instruction = envelope_instruction(envelope)
    assert instruction.kind is EnforcementKind.OBSERVE
    assert instruction.action is DecisionAction.NO_ACTION_SHADOW
    # The hypothetical BLOCK is preserved as evidence, not as an instruction.
    assert instruction.hypothetical_action is DecisionAction.BLOCK


def test_enforcing_envelope_maps_normally() -> None:
    envelope = ModeAwareDecisionService(
        POLICY, operating_mode=OperatingMode.ENFORCING
    ).decide(tx(), IntelligenceSnapshot(transaction_risk=0.98))
    instruction = envelope_instruction(envelope)
    assert instruction.kind is EnforcementKind.DENY
    assert instruction.hypothetical_action is None


def test_envelope_instruction_rejects_wrong_type() -> None:
    with pytest.raises(EnforcementRejected):
        envelope_instruction(object())  # type: ignore[arg-type]
