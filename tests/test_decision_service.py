from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    IntelligenceSnapshot,
)


def transaction() -> CanonicalTransaction:
    return CanonicalTransaction(
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
        destination_institution_id="bank-2",
        correlation_id="corr-1",
    )


def test_high_beneficiary_risk_holds_transaction() -> None:
    decision = DecisionService().decide(
        transaction(),
        IntelligenceSnapshot(beneficiary_risk=0.91, transaction_risk=0.20),
    )
    assert decision.action == DecisionAction.HOLD
    assert decision.risk_score == 0.91
    assert "HIGH_BENEFICIARY_RISK" in decision.reason_codes


def test_low_risk_transaction_is_allowed() -> None:
    decision = DecisionService().decide(transaction(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.ALLOW
