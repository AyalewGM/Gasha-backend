from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from fastapi.testclient import TestClient

from gasha.api.synthetic import app
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
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
        correlation_id="corr-api-decision",
    )


def decision_request(**intelligence_overrides: object) -> dict[str, object]:
    intelligence: dict[str, object] = {
        "customer_risk": 0.0,
        "transaction_risk": 0.0,
        "velocity_risk": 0.0,
        "device_session_risk": 0.0,
        "beneficiary_risk": 0.0,
        "relationship_risk": 0.0,
        "network_risk": 0.0,
    }
    intelligence.update(intelligence_overrides)
    return {
        "transaction": transaction().model_dump(mode="json"),
        "policy": DecisionPolicy(
            configuration_version="tenant-config-9",
            policy_version="decision-policy-5",
            rule_version="rules-4",
        ).model_dump(mode="json"),
        **intelligence,
    }


def test_decision_endpoint_preserves_velocity_and_device_session_risk() -> None:
    client = TestClient(app)

    response = client.post(
        "/v1/decisions",
        json=decision_request(device_session_risk=0.78, velocity_risk=0.62),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "review"
    assert body["risk_score"] == 0.78
    assert "HIGH_DEVICE_SESSION_RISK" in body["reason_codes"]
