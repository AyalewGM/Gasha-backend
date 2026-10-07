from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from gasha.ingestion.bus import InMemoryEventBus
from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionOutcome, IngestionService

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def inbound(**overrides) -> InboundBankEvent:
    payload = {
        "event_id": str(uuid4()),
        "occurred_at": T0.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "100.00",
        "currency": "ETB",
        "sender_customer_id": "synthetic-customer",
        "sender_account_id": "synthetic-account",
        "beneficiary_id": "synthetic-beneficiary",
        "beneficiary_type": "external",
        "destination_institution_id": "synthetic-destination",
        "correlation_id": "synthetic-corr",
    }
    defaults = {
        "tenant_id": "tenant-a",
        "source_system": "synthetic-core-banking",
        "schema_version": "1.0",
        "payload": payload,
    }
    return InboundBankEvent(**(defaults | overrides))


def test_bus_is_fifo() -> None:
    bus = InMemoryEventBus()
    first, second = inbound(), inbound()
    bus.publish(first)
    bus.publish(second)

    batch = bus.poll(max_events=10)
    assert batch == (first, second)
    assert len(bus) == 0


def test_poll_respects_batch_size() -> None:
    bus = InMemoryEventBus()
    for _ in range(3):
        bus.publish(inbound())
    assert len(bus.poll(max_events=2)) == 2
    assert len(bus) == 1


def test_bus_feeds_the_ingestion_service_end_to_end() -> None:
    bus = InMemoryEventBus()
    service = IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()}
    )
    bus.publish(inbound())
    bus.publish(inbound())

    outcomes = [
        service.ingest(event).outcome for event in bus.poll(max_events=10)
    ]
    assert outcomes == [IngestionOutcome.ACCEPTED] * 2
