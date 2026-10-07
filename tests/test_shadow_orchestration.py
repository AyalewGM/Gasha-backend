from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.contracts import AdapterMetadata, FraudEventEnvelope
from gasha.orchestration import (
    InMemoryShadowEvaluationRepository,
    ShadowOrchestrator,
)
from gasha.poc.historical import MissingTenantPolicyError

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version="policy-1",
        rule_version="rules-1",
        model_version="model-1",
    )


def envelope(
    *,
    tenant_id: str = "tenant-a",
    intelligence: IntelligenceSnapshot | None = None,
    mode: OperatingMode = OperatingMode.SHADOW,
) -> FraudEventEnvelope:
    return FraudEventEnvelope(
        tenant_id=tenant_id,
        event_id=uuid4(),
        operating_mode=mode,
        received_at=T0,
        correlation_id="synthetic-corr",
        canonical_transaction=CanonicalTransaction(
            tenant_id=tenant_id,
            event_id=uuid4(),
            occurred_at=T0,
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal("1000.00"),
            currency="ETB",
            sender_customer_id="synthetic-sender",
            sender_account_id="synthetic-account",
            beneficiary_id="synthetic-beneficiary",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="synthetic-destination",
            correlation_id="synthetic-corr",
        ),
        intelligence=intelligence or IntelligenceSnapshot(),
        signal_policy_versions=("behavioral-2",),
        adapter=AdapterMetadata(
            source_system="synthetic-core-banking",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=T0,
        ),
    )


def orchestrator(**kwargs) -> ShadowOrchestrator:
    return ShadowOrchestrator({"tenant-a": policy()}, **kwargs)


def test_shadow_hypothetical_block_never_enforces() -> None:
    ev = envelope(
        intelligence=IntelligenceSnapshot(network_risk=0.99)
    )
    result = orchestrator().evaluate(ev)

    assert result.decision.action == DecisionAction.BLOCK
    assert result.effective_action == DecisionAction.NO_ACTION_SHADOW
    assert result.operating_mode == OperatingMode.SHADOW


def test_enforcing_mode_passes_action_through() -> None:
    ev = envelope(
        intelligence=IntelligenceSnapshot(network_risk=0.99),
        mode=OperatingMode.ENFORCING,
    )
    result = orchestrator().evaluate(ev)
    assert result.decision.action == DecisionAction.BLOCK
    assert result.effective_action == DecisionAction.BLOCK


def test_persisted_record_reconstructs_full_context() -> None:
    repo = InMemoryShadowEvaluationRepository()
    ev = envelope(intelligence=IntelligenceSnapshot(device_session_risk=0.80))
    result = orchestrator(evaluations=repo).evaluate(ev)

    stored = repo.get("tenant-a", ev.event_id)
    assert stored is not None
    assert stored.evaluation.decision.action == DecisionAction.REVIEW
    assert stored.evaluation.effective_action == (
        DecisionAction.NO_ACTION_SHADOW
    )
    assert stored.event.adapter.adapter_version == "1.0.0"
    assert stored.event.adapter.schema_version == "1.0"
    assert stored.evaluation.decision.policy_version == "policy-1"
    assert stored.evaluation.decision.rule_version == "rules-1"
    assert stored.evaluation.decision.model_version == "model-1"
    assert stored.evaluation.decision.configuration_version == (
        "tenant-config-1"
    )
    assert stored.event.signal_policy_versions == ("behavioral-2",)
    assert stored.persisted_at is not None
    assert result.evaluation_latency_ms >= 0.0


def test_missing_tenant_policy_fails_closed() -> None:
    with pytest.raises(MissingTenantPolicyError):
        orchestrator().evaluate(envelope(tenant_id="tenant-unknown"))


def test_evaluation_records_are_tenant_scoped() -> None:
    repo = InMemoryShadowEvaluationRepository()
    ev = envelope(tenant_id="tenant-a")
    orchestrator(evaluations=repo).evaluate(ev)

    assert repo.get("tenant-a", ev.event_id) is not None
    assert repo.get("tenant-b", ev.event_id) is None


def test_latency_uses_injected_clock() -> None:
    ticks = iter(
        T0 + timedelta(milliseconds=offset) for offset in (0, 3, 5)
    )
    repo = InMemoryShadowEvaluationRepository()
    result = orchestrator(
        evaluations=repo, clock=lambda: next(ticks)
    ).evaluate(envelope())

    assert result.evaluation_latency_ms == 3.0
