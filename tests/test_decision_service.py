from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)


def policy(**overrides: object) -> DecisionPolicy:
    values: dict[str, object] = {
        "configuration_version": "tenant-config-7",
        "policy_version": "policy-3",
        "rule_version": "rules-2",
    }
    values.update(overrides)
    return DecisionPolicy(**values)


def transaction(
    *,
    beneficiary_type: BeneficiaryType = BeneficiaryType.EXTERNAL,
    destination_institution_id: str | None = "external-bank",
) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("1250.00"),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-9",
        beneficiary_type=beneficiary_type,
        destination_institution_id=destination_institution_id,
        correlation_id="corr-1",
    )


def test_high_beneficiary_risk_holds_transaction() -> None:
    decision = DecisionService(policy()).decide(
        transaction(),
        IntelligenceSnapshot(beneficiary_risk=0.91, transaction_risk=0.20),
    )
    assert decision.action == DecisionAction.HOLD
    assert decision.risk_score == 0.91
    assert "HIGH_BENEFICIARY_RISK" in decision.reason_codes
    assert decision.tenant_id == "tenant-a"
    assert decision.configuration_version == "tenant-config-7"
    assert decision.policy_version == "policy-3"
    assert decision.rule_version == "rules-2"


def test_tenant_policy_changes_action_without_bank_specific_code() -> None:
    intelligence = IntelligenceSnapshot(beneficiary_risk=0.80)
    standard = DecisionService(policy()).decide(transaction(), intelligence)
    stricter = DecisionService(
        policy(
            configuration_version="tenant-config-8",
            policy_version="policy-4",
            monitor_threshold=0.30,
            review_threshold=0.50,
            hold_threshold=0.75,
            block_threshold=0.90,
        )
    ).decide(transaction(), intelligence)

    assert standard.action == DecisionAction.REVIEW
    assert stricter.action == DecisionAction.HOLD
    assert stricter.configuration_version == "tenant-config-8"


def test_low_risk_transaction_is_allowed() -> None:
    decision = DecisionService(policy()).decide(transaction(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.ALLOW


def test_external_beneficiary_requires_destination_institution() -> None:
    with pytest.raises(ValidationError):
        transaction(destination_institution_id=None)


def test_internal_beneficiary_does_not_require_destination_institution() -> None:
    tx = transaction(
        beneficiary_type=BeneficiaryType.INTERNAL,
        destination_institution_id=None,
    )
    assert tx.beneficiary_type == BeneficiaryType.INTERNAL


def test_thresholds_must_be_strictly_increasing() -> None:
    with pytest.raises(ValidationError):
        policy(review_threshold=0.90, hold_threshold=0.80)
