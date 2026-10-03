from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from gasha.decision.audit import InMemoryDecisionAuditRepository
from gasha.decision.idempotency import IdempotentDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.intelligence.provenance import (
    IntelligenceEvidence,
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)


def transaction() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("2500"),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-7",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-audit",
    )


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-8",
        policy_version="decision-policy-4",
        rule_version="rules-3",
        model_version="model-2",
    )


def evidence() -> IntelligenceEvidence:
    return IntelligenceEvidence(
        reason_code="INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER",
        provenance=SignalProvenance(
            source=IntelligenceSource.TENANT_NETWORK,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=datetime.now(UTC),
            source_version="internal-graph-features-1",
            confidence=0.93,
        ),
    )


def test_duplicate_tenant_event_returns_first_persisted_decision() -> None:
    tx = transaction()
    repository = InMemoryDecisionAuditRepository()
    service = IdempotentDecisionService(DecisionService(policy()), repository)

    first = service.decide(
        tx,
        IntelligenceSnapshot(network_risk=0.96),
        evidence_reason_codes=["INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER"],
    )
    replay = service.decide(tx, IntelligenceSnapshot())

    assert first.action == DecisionAction.BLOCK
    assert replay == first


def test_same_event_id_is_isolated_by_tenant() -> None:
    tx_a = transaction()
    tx_b = tx_a.model_copy(update={"tenant_id": "tenant-b", "correlation_id": "corr-b"})
    repository = InMemoryDecisionAuditRepository()
    service = IdempotentDecisionService(DecisionService(policy()), repository)

    decision_a = service.decide(tx_a, IntelligenceSnapshot(network_risk=0.96))
    decision_b = service.decide(tx_b, IntelligenceSnapshot())

    assert decision_a.action == DecisionAction.BLOCK
    assert decision_b.action == DecisionAction.ALLOW


def test_audit_record_retains_policy_versions_and_evidence_provenance() -> None:
    tx = transaction()
    repository = InMemoryDecisionAuditRepository()
    service = IdempotentDecisionService(DecisionService(policy()), repository)
    graph_evidence = evidence()

    service.decide(
        tx,
        IntelligenceSnapshot(network_risk=0.96),
        evidence_reason_codes=[graph_evidence.reason_code],
        signal_policy_versions=["graph-policy-2", "behavioral-policy-2"],
        evidence=[graph_evidence],
    )

    record = repository.get(tx.tenant_id, tx.event_id)

    assert record is not None
    assert record.decision.configuration_version == "tenant-config-8"
    assert record.decision.policy_version == "decision-policy-4"
    assert record.decision.rule_version == "rules-3"
    assert record.decision.model_version == "model-2"
    assert record.signal_policy_versions == ("graph-policy-2", "behavioral-policy-2")
    assert record.evidence[0].provenance.source == IntelligenceSource.TENANT_NETWORK
    assert record.evidence[0].provenance.source_version == "internal-graph-features-1"
