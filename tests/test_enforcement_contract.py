"""Fail-closed channel-action projection tests (#146 / #42 / #49)."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest
from pydantic import ValidationError

from gasha.decision.enforcement import (
    ENFORCEMENT_SCHEMA_VERSION,
    EnforcementInstruction,
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
    policy_version="policy-v1",
    rule_version="rules-v1",
    challenge_threshold=0.60,
    challenge_supported_channels=("mobile",),
    challenge_policy_ref="synthetic-lineage-v1",
)


def tx(tenant_id: str = "tenant-a") -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant_id,
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


def decide(score: float, tenant_id: str = "tenant-a") -> FraudDecision:
    return DecisionService(POLICY).decide(
        tx(tenant_id), IntelligenceSnapshot(transaction_risk=score)
    )


def envelope(score: float, mode: OperatingMode = OperatingMode.SHADOW, *, tenant_id: str = "tenant-a"):
    return ModeAwareDecisionService(POLICY, operating_mode=mode).decide(
        tx(tenant_id), IntelligenceSnapshot(transaction_risk=score)
    )


@pytest.mark.parametrize("score", [0.10, 0.55, 0.65, 0.75, 0.90, 0.98])
def test_raw_decision_never_issues_channel_order(score: float) -> None:
    with pytest.raises(EnforcementRejected, match="hypothetical"):
        enforcement_instruction(decide(score))


@pytest.mark.parametrize(
    ("score", "hypothetical"),
    [
        (0.10, DecisionAction.ALLOW),
        (0.55, DecisionAction.MONITOR),
        (0.65, DecisionAction.CHALLENGE),
        (0.75, DecisionAction.REVIEW),
        (0.90, DecisionAction.HOLD),
        (0.98, DecisionAction.BLOCK),
    ],
)
def test_shadow_only_observes_all_hypothetical_actions(
    score: float, hypothetical: DecisionAction
) -> None:
    original = envelope(score)
    report = envelope_instruction(original)
    assert report.schema_version == ENFORCEMENT_SCHEMA_VERSION
    assert report.kind is EnforcementKind.OBSERVE
    assert report.action is DecisionAction.NO_ACTION_SHADOW
    assert report.hypothetical_action is hypothetical
    assert report.executable is False
    assert report.hold_disposition is None
    assert report.step_up_methods == ()
    assert report.event_id == original.decision.event_id
    assert report.correlation_id == original.decision.correlation_id
    assert report.policy_version == original.decision.policy_version
    assert report.risk_score == original.decision.risk_score
    assert report.reason_codes == original.decision.reason_codes


@pytest.mark.parametrize("score", [0.10, 0.65, 0.90, 0.98])
def test_enforcing_mode_alone_never_grants_bank_authority(score: float) -> None:
    with pytest.raises(EnforcementRejected, match="issuer unavailable"):
        envelope_instruction(envelope(score, OperatingMode.ENFORCING))


@pytest.mark.parametrize("score", [0.65, 0.90, 0.98])
def test_alternate_shadow_raw_entrypoint_is_blocked(score: float) -> None:
    shadow = envelope(score)
    with pytest.raises(EnforcementRejected):
        enforcement_instruction(shadow.decision)
    assert envelope_instruction(shadow).kind is EnforcementKind.OBSERVE


@pytest.mark.parametrize("score", [0.65, 0.90, 0.98])
def test_forged_shadow_effective_action_cannot_enable_execution(score: float) -> None:
    shadow = envelope(score)
    forged = shadow.model_copy(update={"effective_action": shadow.decision.action})
    with pytest.raises(EnforcementRejected, match="shadow envelope"):
        envelope_instruction(forged)


@pytest.mark.parametrize("bad_mode", ["shadow", "enforcing", None, True])
def test_postconstruction_mode_corruption_rejects(bad_mode: object) -> None:
    forged = envelope(0.98).model_copy(update={"operating_mode": bad_mode})
    with pytest.raises(EnforcementRejected):
        envelope_instruction(forged)


def test_postconstruction_decision_corruption_rejects() -> None:
    forged = envelope(0.98).model_copy(update={"decision": object()})
    with pytest.raises(EnforcementRejected):
        envelope_instruction(forged)


@pytest.mark.parametrize("kind", [EnforcementKind.STEP_UP, EnforcementKind.HOLD, EnforcementKind.DENY])
def test_advisory_model_rejects_executable_kind(kind: EnforcementKind) -> None:
    data = envelope_instruction(envelope(0.98)).model_dump()
    data["kind"] = kind
    with pytest.raises(ValidationError, match="non-executable"):
        EnforcementInstruction.model_validate(data)


def test_advisory_model_rejects_spoofed_executable_flag() -> None:
    data = envelope_instruction(envelope(0.98)).model_dump()
    data["executable"] = True
    with pytest.raises(ValidationError):
        EnforcementInstruction.model_validate(data)


def test_advisory_model_rejects_hold_or_stepup_hints() -> None:
    original = envelope_instruction(envelope(0.98)).model_dump()
    with pytest.raises(ValidationError, match="non-executable"):
        EnforcementInstruction.model_validate({**original, "hold_disposition": "pending_release"})
    with pytest.raises(ValidationError, match="non-executable"):
        EnforcementInstruction.model_validate({**original, "step_up_methods": ["otp"]})


def test_projection_is_tenant_bound_but_never_a_bank_order() -> None:
    first = envelope_instruction(envelope(0.98, tenant_id="tenant-a"))
    second = envelope_instruction(envelope(0.98, tenant_id="tenant-b"))
    assert first.tenant_id == "tenant-a"
    assert second.tenant_id == "tenant-b"
    assert first.event_id == second.event_id
    assert first.executable is False and second.executable is False
    assert first.kind is EnforcementKind.OBSERVE and second.kind is EnforcementKind.OBSERVE


def test_wrong_types_reject_without_instructions() -> None:
    with pytest.raises(EnforcementRejected):
        enforcement_instruction(object())  # type: ignore[arg-type]
    with pytest.raises(EnforcementRejected):
        envelope_instruction(object())  # type: ignore[arg-type]
