from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionService
from gasha.journey.detector import JourneyDetector
from gasha.journey.events import JourneyEvent, JourneyEventKind
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.repository import InMemoryJourneyEventRepository
from gasha.observability.metrics import InMemoryMetricsRegistry
from gasha.poc.bank_simulator import SyntheticBankSimulator
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    replay_historical,
)

TENANT = "tenant-a"
BASE = datetime(2026, 3, 10, 12, 0, 0, tzinfo=UTC)


def _journey_event(
    customer_id: str, at: datetime, *, tenant_id: str = TENANT
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id=tenant_id,
        event_id=uuid4(),
        kind=JourneyEventKind.DEVICE_SESSION,
        subtype="session_anomaly",
        occurred_at=at,
        customer_id=customer_id,
        device_id="sim-device",
    )


def _transaction(at: datetime) -> HistoricalTransactionEvent:
    tx = CanonicalTransaction(
        tenant_id=TENANT,
        event_id=uuid4(),
        occurred_at=at,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("500.00"),
        currency="ETB",
        sender_customer_id="cust-1",
        sender_account_id="acct-1",
        beneficiary_id="ben-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="sim-destination",
        correlation_id="perf-corr",
    )
    return HistoricalTransactionEvent(
        transaction=tx,
        intelligence=IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(
            is_fraud=False, label_source="perf-fixture"
        ),
    )


def test_journey_lookup_is_bounded_by_window_not_history_size():
    """Recent() can never scan beyond the configured window."""

    repo = InMemoryJourneyEventRepository()
    # 2,000 ancient events plus 3 in-window — the query must return
    # only the in-window events regardless of total history size.
    for i in range(2000):
        repo.append(
            _journey_event(
                "cust-1", BASE - timedelta(days=30, minutes=i)
            )
        )
    for i in range(3):
        repo.append(
            _journey_event("cust-1", BASE - timedelta(minutes=i))
        )
    recent = repo.recent(
        TENANT,
        "cust-1",
        as_of=BASE,
        since=BASE - timedelta(hours=1),
    )
    assert len(recent) == 3


def test_evaluation_latency_is_measurable_under_synthetic_load():
    """Latency stats + throughput are measurable — no SLA assumed."""

    policies = {
        TENANT: DecisionPolicy(
            configuration_version="config-1",
            policy_version="policy-1",
            rule_version="rules-1",
        )
    }
    events = tuple(
        _transaction(BASE + timedelta(seconds=i)) for i in range(300)
    )
    report = replay_historical(events, policies)
    metrics = report.metrics
    assert metrics.cases == 300
    for field in (
        "mean_processing_latency_ms",
        "median_processing_latency_ms",
        "p95_processing_latency_ms",
        "p99_processing_latency_ms",
        "max_processing_latency_ms",
    ):
        assert getattr(metrics, field) is not None
    assert metrics.p95_processing_latency_ms >= 0
    assert (
        metrics.p99_processing_latency_ms
        >= metrics.p95_processing_latency_ms
    )


def test_journey_pipeline_metrics_cover_the_uc3_surface():
    """The §25 journey metrics exist and count real pipeline flow."""

    registry = InMemoryMetricsRegistry()
    adapter = ReferenceJsonAdapter()
    simulator = SyntheticBankSimulator()
    payments = IngestionService(
        {simulator.source_system: adapter}, metrics=registry
    )

    # Conflicting duplicate: same event_id, different payload.
    inbound = simulator.event("conflict-check")
    accepted = payments.ingest(inbound)
    assert accepted.envelope is not None
    tampered = inbound.model_copy(
        update={
            "payload": {**inbound.payload, "amount": "9999.00"}
        }
    )
    payments.ingest(tampered)
    assert (
        registry.counter(
            "gasha_events_conflicting_duplicates",
            labels={"tenant_id": TENANT},
        )
        == 1
    )

    # Journey assessment metrics through the orchestrator.
    repo = InMemoryJourneyEventRepository()
    repo.append(
        _journey_event(
            "sim-customer-check", BASE - timedelta(minutes=5)
        )
    )
    from gasha.journey.provider import PolicyBoundJourneyIntelligence
    from gasha.orchestration import ShadowOrchestrator

    orchestrator = ShadowOrchestrator(
        policies={
            TENANT: DecisionPolicy(
                configuration_version="config-1",
                policy_version="policy-1",
                rule_version="rules-1",
            )
        },
        journey=PolicyBoundJourneyIntelligence(
            repo,
            {
                TENANT: JourneyRiskPolicy(
                    configuration_version="jc-1",
                    policy_version="j-1",
                )
            },
        ),
        metrics=registry,
    )
    payment = simulator.event("metrics-check", amount="100.00")
    result = payments.ingest(payment)
    assert result.envelope is not None
    orchestrator.evaluate(result.envelope)
    assert (
        registry.counter(
            "gasha_journey_evaluations",
            labels={"tenant_id": TENANT},
        )
        == 1
    )
    summary = registry.latency_summary(
        "gasha_evaluation_latency_ms",
        labels={"tenant_id": TENANT},
    )
    assert summary is not None
    assert summary["count"] >= 1


def test_detector_assessment_handles_dense_journey_history():
    """Assessment over a large in-window history stays deterministic."""

    repo = InMemoryJourneyEventRepository()
    for i in range(500):
        repo.append(
            _journey_event("cust-1", BASE - timedelta(seconds=i))
        )
    detector = JourneyDetector(
        repo,
        JourneyRiskPolicy(
            configuration_version="jc-1", policy_version="j-1"
        ),
    )
    first = detector.assess(TENANT, "cust-1", as_of=BASE)
    second = detector.assess(TENANT, "cust-1", as_of=BASE)
    assert first is not None
    assert first == second
