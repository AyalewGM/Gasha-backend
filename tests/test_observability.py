from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.synthetic import app
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.contracts import (
    AdapterMetadata,
    FraudEventEnvelope,
    InboundBankEvent,
)
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionService
from gasha.observability.logging import build_log_record, log_operation
from gasha.observability.metrics import InMemoryMetricsRegistry
from gasha.orchestration import ShadowOrchestrator

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def valid_payload(**overrides):
    payload = {
        "event_id": str(uuid4()),
        "occurred_at": T0.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "1250.00",
        "currency": "ETB",
        "sender_customer_id": "synthetic-customer-1",
        "sender_account_id": "synthetic-account-1",
        "beneficiary_id": "synthetic-beneficiary-1",
        "beneficiary_type": "external",
        "destination_institution_id": "synthetic-destination",
        "correlation_id": "synthetic-corr-1",
    }
    payload.update(overrides)
    return payload


def inbound(payload, **kwargs) -> InboundBankEvent:
    defaults = {
        "tenant_id": "tenant-a",
        "source_system": "synthetic-core-banking",
        "schema_version": "1.0",
        "received_at": T0,
    }
    return InboundBankEvent(payload=payload, **(defaults | kwargs))


def envelope(
    *,
    tenant_id: str = "tenant-a",
    intelligence: IntelligenceSnapshot | None = None,
) -> FraudEventEnvelope:
    return FraudEventEnvelope(
        tenant_id=tenant_id,
        event_id=uuid4(),
        operating_mode=OperatingMode.SHADOW,
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
        adapter=AdapterMetadata(
            source_system="synthetic-core-banking",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=T0,
        ),
    )


def test_metrics_are_tenant_safe_by_construction() -> None:
    metrics = InMemoryMetricsRegistry()
    with pytest.raises(ValueError, match="not allowed"):
        metrics.increment(
            "gasha_events_received", labels={"account_number": "12345"}
        )
    with pytest.raises(ValueError, match="not allowed"):
        metrics.increment("x", labels={"customer_name": "xyz"})


def test_ingestion_emits_operational_metrics() -> None:
    metrics = InMemoryMetricsRegistry()
    service = IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()},
        metrics=metrics,
    )

    service.ingest(inbound(valid_payload()))
    service.ingest(inbound(valid_payload()))
    payload = valid_payload()
    service.ingest(inbound(payload))
    service.ingest(inbound(payload))  # identical resubmission

    labels = {
        "tenant_id": "tenant-a",
        "source_system": "synthetic-core-banking",
    }
    assert metrics.counter("gasha_events_received", labels=labels) == 4
    assert (
        metrics.counter(
            "gasha_events_accepted", labels={"tenant_id": "tenant-a"}
        )
        == 3
    )
    assert (
        metrics.counter(
            "gasha_events_duplicate", labels={"tenant_id": "tenant-a"}
        )
        == 1
    )


def test_rejection_metrics_carry_reason_not_payload() -> None:
    metrics = InMemoryMetricsRegistry()
    service = IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()},
        metrics=metrics,
    )
    bad = valid_payload()
    del bad["amount"]
    service.ingest(inbound(bad))

    assert (
        metrics.counter(
            "gasha_events_rejected",
            labels={"reason": "invalid_amount", "tenant_id": "tenant-a"},
        )
        == 1
    )


def test_orchestrator_emits_decision_and_latency_metrics() -> None:
    metrics = InMemoryMetricsRegistry()
    orchestrator = ShadowOrchestrator(
        {
            "tenant-a": DecisionPolicy(
                configuration_version="c1",
                policy_version="p1",
                rule_version="r1",
            )
        },
        metrics=metrics,
    )
    orchestrator.evaluate(
        envelope(intelligence=IntelligenceSnapshot(network_risk=0.99))
    )

    assert (
        metrics.counter(
            "gasha_evaluations_completed",
            labels={"tenant_id": "tenant-a"},
        )
        == 1
    )
    assert (
        metrics.counter(
            "gasha_shadow_hypothetical_decisions",
            labels={"action": "block", "tenant_id": "tenant-a"},
        )
        == 1
    )
    summary = metrics.latency_summary(
        "gasha_evaluation_latency_ms", labels={"tenant_id": "tenant-a"}
    )
    assert summary is not None
    assert summary["count"] == 1.0
    assert summary["max"] >= summary["mean"]


def test_structured_log_record_is_whitelisted() -> None:
    record = build_log_record(
        component="ingestion",
        operation="normalize",
        outcome="accepted",
        tenant_id="tenant-a",
        correlation_id="corr-1",
        latency_ms=3.5,
    )
    assert record["tenant_id"] == "tenant-a"
    assert set(record) <= {
        "tenant_id",
        "event_id",
        "correlation_id",
        "component",
        "operation",
        "outcome",
        "error_category",
        "latency_ms",
    }
    assert json.dumps(record)


def test_log_operation_strips_unexpected_keys(caplog) -> None:
    logger = logging.getLogger("gasha.test")
    with caplog.at_level(logging.INFO, logger="gasha.test"):
        log_operation(
            logger,
            {
                "component": "ingestion",
                "operation": "adapt",
                "outcome": "rejected",
                "raw_payload": "should-never-appear",
            },
        )
    rendered = caplog.records[-1].__dict__
    assert "raw_payload" not in rendered
    assert rendered["component"] == "ingestion"


def test_health_endpoints() -> None:
    client = TestClient(app)
    assert client.get("/health/live").status_code == 200
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert ready.json()["checks"]["outcome_ingestion"] is True


def test_readiness_fails_when_dependency_missing() -> None:
    original = app.state.outcome_ingestion
    try:
        app.state.outcome_ingestion = None
        client = TestClient(app)
        response = client.get("/health/ready")
        assert response.json()["status"] == "not_ready"
        assert response.json()["checks"]["outcome_ingestion"] is False
    finally:
        app.state.outcome_ingestion = original
