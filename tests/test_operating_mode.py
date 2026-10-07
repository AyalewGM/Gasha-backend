from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.decision.mode import ModeAwareDecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.poc.outcomes import (
    IncumbentControlOutcome,
    OutcomeRecord,
    OutcomeType,
)


def transaction() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("2500.00"),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-9",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-operating-mode",
    )


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version="policy-1",
        rule_version="rules-1",
    )


def step_clock() -> tuple[callable, list[datetime]]:
    ticks = [datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)]

    def clock() -> datetime:
        current = ticks[-1]
        ticks.append(current + timedelta(milliseconds=4))
        return current

    return clock, ticks


def test_enforcing_mode_passes_decision_action_through() -> None:
    service = ModeAwareDecisionService(
        policy(), operating_mode=OperatingMode.ENFORCING
    )

    envelope = service.decide(
        transaction(), IntelligenceSnapshot(beneficiary_risk=0.96)
    )

    assert envelope.operating_mode == OperatingMode.ENFORCING
    assert envelope.decision.action == DecisionAction.BLOCK
    assert envelope.effective_action == DecisionAction.BLOCK


def test_shadow_mode_preserves_hypothetical_but_never_enforces() -> None:
    service = ModeAwareDecisionService(
        policy(), operating_mode=OperatingMode.SHADOW
    )

    envelope = service.decide(
        transaction(),
        IntelligenceSnapshot(network_risk=0.97),
        evidence_reason_codes=["INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER"],
    )

    assert envelope.operating_mode == OperatingMode.SHADOW
    assert envelope.decision.action == DecisionAction.BLOCK
    assert envelope.decision.risk_score == 0.97
    assert "INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER" in envelope.decision.reason_codes
    assert envelope.effective_action == DecisionAction.NO_ACTION_SHADOW


def test_shadow_mode_low_risk_also_non_enforcing() -> None:
    service = ModeAwareDecisionService(
        policy(), operating_mode=OperatingMode.SHADOW
    )

    envelope = service.decide(transaction(), IntelligenceSnapshot())

    assert envelope.decision.action == DecisionAction.ALLOW
    assert envelope.effective_action == DecisionAction.NO_ACTION_SHADOW


def test_evaluation_latency_uses_injected_clock() -> None:
    clock, _ = step_clock()
    service = ModeAwareDecisionService(
        policy(), operating_mode=OperatingMode.SHADOW, clock=clock
    )

    envelope = service.decide(transaction(), IntelligenceSnapshot())

    assert envelope.evaluation_latency_ms == 4.0
    assert envelope.evaluated_at == datetime(
        2026, 2, 1, 12, 0, 0, 4000, tzinfo=UTC
    )


def test_shadow_evaluation_endpoint_never_returns_enforcing_action() -> None:
    client = TestClient(app)
    tx = transaction()
    payload: dict[str, object] = {
        "transaction": tx.model_dump(mode="json"),
        "policy": policy().model_dump(mode="json"),
        "operating_mode": "shadow",
        "network_risk": 0.97,
    }

    response = client.post("/v1/evaluations", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["operating_mode"] == "shadow"
    assert body["decision"]["action"] == "block"
    assert body["effective_action"] == "no_action_shadow"
    assert body["evaluation_latency_ms"] >= 0.0


def test_evaluation_endpoint_defaults_to_enforcing() -> None:
    client = TestClient(app)
    payload: dict[str, object] = {
        "transaction": transaction().model_dump(mode="json"),
        "policy": policy().model_dump(mode="json"),
        "beneficiary_risk": 0.91,
    }

    response = client.post("/v1/evaluations", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["operating_mode"] == "enforcing"
    assert body["effective_action"] == "hold"


def test_outcome_record_maps_normalized_outcomes_to_fraud_truth() -> None:
    base = {
        "tenant_id": "tenant-a",
        "event_id": uuid4(),
        "outcome_source": "synthetic-case-review",
        "outcome_version": "outcomes-1",
    }
    assert (
        OutcomeRecord(outcome=OutcomeType.CONFIRMED_FRAUD, **base).is_fraud
        is True
    )
    assert (
        OutcomeRecord(
            outcome=OutcomeType.CUSTOMER_REPORTED_SCAM, **base
        ).is_fraud
        is True
    )
    assert (
        OutcomeRecord(
            outcome=OutcomeType.BANK_CONFIRMED_FALSE_POSITIVE, **base
        ).is_fraud
        is False
    )
    assert (
        OutcomeRecord(outcome=OutcomeType.UNRESOLVED, **base).is_fraud
        is None
    )


def test_incumbent_outcome_alerted_semantics() -> None:
    assert IncumbentControlOutcome.NO_ALERT.alerted is False
    assert IncumbentControlOutcome.ALERT.alerted is True
    assert IncumbentControlOutcome.BLOCK.alerted is True
