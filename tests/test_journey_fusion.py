from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.contracts import AdapterMetadata, FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.journey.events import (
    AuthenticationSubtype,
    DeviceSessionSubtype,
    JourneyEvent,
    JourneyEventKind,
    TransactionSubtype,
)
from gasha.journey.ingestion import (
    JourneyIngestionOutcome,
    JourneyIngestionService,
)
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.provider import PolicyBoundJourneyIntelligence
from gasha.journey.repository import InMemoryJourneyEventRepository
from gasha.orchestration import (
    InMemoryShadowEvaluationRepository,
    ShadowOrchestrator,
)

T0 = datetime(2026, 2, 20, 9, 0, 0, tzinfo=UTC)


def journey_event(
    kind: JourneyEventKind,
    subtype: str,
    *,
    minutes_ago: float,
    customer_id: str = "synthetic-customer",
    **kwargs,
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id="tenant-a",
        event_id=uuid4(),
        kind=kind,
        subtype=subtype,
        occurred_at=T0 - timedelta(minutes=minutes_ago),
        customer_id=customer_id,
        **kwargs,
    )


def transaction(customer_id="synthetic-customer") -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=T0,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("4800.00"),
        currency="ETB",
        sender_customer_id=customer_id,
        sender_account_id="synthetic-account",
        beneficiary_id="synthetic-beneficiary",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="synthetic-destination",
        correlation_id="synthetic-corr",
    )


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="c1",
        policy_version="p1",
        rule_version="r1",
        model_version="m1",
    )


def test_journey_risk_is_first_class_fusion_component() -> None:
    decision = DecisionService(policy()).decide(
        transaction(), IntelligenceSnapshot(journey_risk=0.88)
    )
    assert decision.action == DecisionAction.HOLD
    assert "HIGH_JOURNEY_RISK" in decision.reason_codes


def test_shadow_orchestrator_enriches_with_journey() -> None:
    repo = InMemoryJourneyEventRepository()
    for e in (
        journey_event(
            JourneyEventKind.AUTHENTICATION,
            AuthenticationSubtype.LOGIN_FAILED.value,
            minutes_ago=25,
        ),
        journey_event(
            JourneyEventKind.AUTHENTICATION,
            AuthenticationSubtype.LOGIN_FAILED.value,
            minutes_ago=20,
        ),
        journey_event(
            JourneyEventKind.AUTHENTICATION,
            AuthenticationSubtype.LOGIN_SUCCESS.value,
            minutes_ago=15,
        ),
        journey_event(
            JourneyEventKind.DEVICE_SESSION,
            DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
            minutes_ago=10,
            device_id="sim-device",
        ),
        journey_event(
            JourneyEventKind.TRANSACTION,
            TransactionSubtype.PAYMENT_ATTEMPTED.value,
            minutes_ago=1,
        ),
    ):
        repo.append(e)

    journey = PolicyBoundJourneyIntelligence(
        repo,
        {
            "tenant-a": JourneyRiskPolicy(
                configuration_version="jc1", policy_version="jp1"
            )
        },
    )
    evals = InMemoryShadowEvaluationRepository()
    orchestrator = ShadowOrchestrator(
        {"tenant-a": policy()}, evaluations=evals, journey=journey
    )

    envelope = FraudEventEnvelope(
        tenant_id="tenant-a",
        event_id=uuid4(),
        operating_mode=OperatingMode.SHADOW,
        correlation_id="corr-1",
        canonical_transaction=transaction(),
        intelligence=IntelligenceSnapshot(),
        adapter=AdapterMetadata(
            source_system="sim",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=T0,
        ),
    )
    result = orchestrator.evaluate(envelope)

    assert result.decision.risk_score >= 0.85  # journey alone drives
    assert "MULTI_EVENT_ATO_PATTERN" in result.decision.reason_codes
    assert "HIGH_JOURNEY_RISK" in result.decision.reason_codes
    assert result.effective_action == DecisionAction.NO_ACTION_SHADOW

    stored = evals.get("tenant-a", envelope.event_id)
    assert stored is not None
    assert stored.journey is not None
    assert stored.journey.policy_version == "jp1"
    assert stored.journey.contributing_events


def test_journey_not_configured_degrades_not_blocks() -> None:
    journey = PolicyBoundJourneyIntelligence(
        InMemoryJourneyEventRepository(),
        {},  # tenant-a has no journey policy
    )
    orchestrator = ShadowOrchestrator(
        {"tenant-a": policy()}, journey=journey
    )
    ev = FraudEventEnvelope(
        tenant_id="tenant-a",
        event_id=uuid4(),
        correlation_id="c",
        canonical_transaction=transaction(),
        adapter=AdapterMetadata(
            source_system="sim",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=T0,
        ),
    )
    result = orchestrator.evaluate(ev)
    assert result.decision.action == DecisionAction.ALLOW
    assert result.decision.risk_score == 0.0


def test_journey_provider_failure_never_fabricates_risk() -> None:
    class ExplodingJourney:
        def assess(self, transaction):
            raise RuntimeError("repo unavailable")

    orchestrator = ShadowOrchestrator(
        {"tenant-a": policy()}, journey=ExplodingJourney()  # type: ignore[arg-type]
    )
    ev = FraudEventEnvelope(
        tenant_id="tenant-a",
        event_id=uuid4(),
        correlation_id="c",
        canonical_transaction=transaction(),
        adapter=AdapterMetadata(
            source_system="sim",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=T0,
        ),
    )
    result = orchestrator.evaluate(ev)
    assert result.decision.risk_score == 0.0
    assert result.decision.action == DecisionAction.ALLOW


def test_journey_event_ingestion_roundtrip_and_dedupe() -> None:
    repo = InMemoryJourneyEventRepository()
    service = JourneyIngestionService(
        {"sim-core": ReferenceJsonAdapter()}, repo
    )
    event_id = str(uuid4())
    inbound = InboundBankEvent(
        tenant_id="tenant-a",
        source_system="sim-core",
        schema_version="1.0",
        received_at=T0,
        payload={
            "event_id": event_id,
            "occurred_at": T0.isoformat(),
            "kind": "authentication",
            "subtype": "login_failed",
            "customer_id": "synthetic-customer",
            "session_id": "sim-session",
        },
    )
    first = service.ingest(inbound)
    second = service.ingest(inbound)
    assert first.outcome == JourneyIngestionOutcome.ACCEPTED
    assert second.outcome == JourneyIngestionOutcome.DUPLICATE
    assert first.envelope is not None
    assert first.envelope.event.kind == JourneyEventKind.AUTHENTICATION
    assert first.envelope.adapter.adapter_version == "1.0.0"


def test_journey_ingestion_rejects_invalid_payload() -> None:
    service = JourneyIngestionService(
        {"sim-core": ReferenceJsonAdapter()},
        InMemoryJourneyEventRepository(),
    )
    inbound = InboundBankEvent(
        tenant_id="tenant-a",
        source_system="sim-core",
        schema_version="1.0",
        payload={
            "event_id": str(uuid4()),
            "occurred_at": T0.isoformat(),
            "kind": "authentication",
            "subtype": "definitely-not-a-subtype",
            "customer_id": "synthetic-customer",
        },
    )
    result = service.ingest(inbound)
    assert result.outcome == JourneyIngestionOutcome.REJECTED
