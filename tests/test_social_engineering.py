from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
)
from gasha.intelligence.social_engineering import (
    SocialEngineeringDetector,
    SocialEngineeringSignals,
)



def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-7",
        policy_version="policy-3",
        rule_version="rules-2",
    )


def transaction() -> CanonicalTransaction:
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
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-social-engineering",
    )


def test_external_mule_aggregation_pattern_is_held_with_explainable_signals() -> None:
    tx = transaction()
    assessment = SocialEngineeringDetector().assess(
        tx,
        SocialEngineeringSignals(
            beneficiary_is_new_to_sender=True,
            amount_to_sender_baseline_ratio=4.2,
            sender_beneficiary_prior_transfer_count=0,
            beneficiary_unique_senders_1h=11,
            beneficiary_incoming_count_1h=13,
        ),
    )

    decision = DecisionService(policy()).decide(tx, assessment.intelligence)

    assert decision.action == DecisionAction.HOLD
    assert decision.risk_score == 0.88
    assert "NEW_BENEFICIARY" in assessment.reason_codes
    assert "AMOUNT_ABOVE_SENDER_BASELINE" in assessment.reason_codes
    assert "BENEFICIARY_MANY_UNIQUE_SENDERS" in assessment.reason_codes
    assert "BENEFICIARY_INCOMING_VELOCITY_SPIKE" in assessment.reason_codes
    assert "EXTERNAL_BENEFICIARY_OBSERVABLE_SIGNALS_ONLY" in assessment.reason_codes


def test_confirmed_fraud_link_blocks_under_default_policy() -> None:
    tx = transaction()
    assessment = SocialEngineeringDetector().assess(
        tx,
        SocialEngineeringSignals(beneficiary_confirmed_fraud_sender_count=2),
    )

    decision = DecisionService(policy()).decide(tx, assessment.intelligence)

    assert decision.action == DecisionAction.BLOCK
    assert "BENEFICIARY_LINKED_TO_CONFIRMED_FRAUD" in assessment.reason_codes


def test_normal_established_relationship_does_not_raise_social_engineering_risk() -> None:
    tx = transaction()
    assessment = SocialEngineeringDetector().assess(
        tx,
        SocialEngineeringSignals(
            beneficiary_is_new_to_sender=False,
            amount_to_sender_baseline_ratio=1.1,
            sender_beneficiary_prior_transfer_count=14,
            beneficiary_unique_senders_1h=1,
            beneficiary_incoming_count_1h=2,
            device_is_new_to_sender=False,
        ),
    )

    decision = DecisionService(policy()).decide(tx, assessment.intelligence)

    assert decision.action == DecisionAction.ALLOW
    assert assessment.intelligence.beneficiary_risk == 0.0


def test_new_device_is_optional_not_assumed_available() -> None:
    tx = transaction()
    without_device = SocialEngineeringDetector().assess(tx, SocialEngineeringSignals())
    with_new_device = SocialEngineeringDetector().assess(
        tx, SocialEngineeringSignals(device_is_new_to_sender=True)
    )

    assert without_device.intelligence.transaction_risk == 0.0
    assert with_new_device.intelligence.transaction_risk == 0.74
    assert "NEW_DEVICE_FOR_SENDER" in with_new_device.reason_codes
