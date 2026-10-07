from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.errors import RejectionReason
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import (
    IngestionOutcome,
    IngestionService,
    InMemoryDeadLetterSink,
)

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def make_service(**kwargs) -> IngestionService:
    return IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()}, **kwargs
    )


def inbound(payload, **kwargs) -> InboundBankEvent:
    defaults = {
        "tenant_id": "tenant-a",
        "source_system": "synthetic-core-banking",
        "schema_version": "1.0",
        "received_at": T0,
    }
    return InboundBankEvent(payload=payload, **(defaults | kwargs))


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


def test_accepted_event_returns_envelope() -> None:
    result = make_service().ingest(inbound(valid_payload()))
    assert result.outcome == IngestionOutcome.ACCEPTED
    assert result.envelope is not None
    assert result.original_accepted_at is not None


def test_exact_duplicate_returns_original_without_reprocessing() -> None:
    service = make_service()
    event = inbound(valid_payload())

    first = service.ingest(event)
    second = service.ingest(event)

    assert first.outcome == IngestionOutcome.ACCEPTED
    assert second.outcome == IngestionOutcome.DUPLICATE
    assert second.envelope == first.envelope
    assert second.original_accepted_at == first.original_accepted_at


def test_conflicting_duplicate_is_rejected_and_dead_lettered() -> None:
    service = make_service()
    event_id = str(uuid4())
    original = valid_payload(event_id=event_id, amount="1250.00")
    tampered = valid_payload(event_id=event_id, amount="9999.99")

    service.ingest(inbound(original))
    conflict = service.ingest(inbound(tampered))

    assert conflict.outcome == IngestionOutcome.REJECTED
    assert conflict.rejection is not None
    assert conflict.rejection.reason == RejectionReason.DUPLICATE_CONFLICT
    # The original record is preserved — a resubmit never overwrites.
    original_again = service.ingest(inbound(original))
    assert original_again.outcome == IngestionOutcome.DUPLICATE
    assert original_again.envelope is not None
    assert str(original_again.envelope.canonical_transaction.amount) == (
        "1250.00"
    )
    dead_letters = service.dead_letter_sink
    assert isinstance(dead_letters, InMemoryDeadLetterSink)
    assert [r.reason for r in dead_letters.records] == [
        RejectionReason.DUPLICATE_CONFLICT
    ]


def test_same_event_id_is_isolated_per_tenant() -> None:
    service = make_service()
    event_id = str(uuid4())
    a = service.ingest(
        inbound(valid_payload(event_id=event_id), tenant_id="tenant-a")
    )
    b = service.ingest(
        inbound(
            valid_payload(event_id=event_id, amount="55.00"),
            tenant_id="tenant-b",
        )
    )
    assert a.outcome == IngestionOutcome.ACCEPTED
    assert b.outcome == IngestionOutcome.ACCEPTED
    assert str(b.envelope.canonical_transaction.amount) == "55.00"  # type: ignore[union-attr]


def test_invalid_event_is_rejected_and_dead_lettered() -> None:
    service = make_service()
    payload = valid_payload()
    del payload["amount"]
    result = service.ingest(inbound(payload))

    assert result.outcome == IngestionOutcome.REJECTED
    assert result.rejection is not None
    assert result.rejection.reason == RejectionReason.INVALID_AMOUNT
    dead_letters = service.dead_letter_sink
    assert isinstance(dead_letters, InMemoryDeadLetterSink)
    assert len(dead_letters.records) == 1


def test_unknown_source_is_rejected() -> None:
    result = make_service().ingest(
        inbound(valid_payload(), source_system="unregistered-core")
    )
    assert result.outcome == IngestionOutcome.REJECTED
    assert result.rejection is not None
    assert (
        result.rejection.reason
        == RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE
    )


class ExplodingAdapter:
    adapter_type = "exploding"
    adapter_version = "0.0.0"
    supported_schema_versions = frozenset({"1.0"})

    def adapt(self, event: InboundBankEvent):
        raise RuntimeError("simulated adapter crash")


def test_adapter_exception_fails_closed_into_dead_letter() -> None:
    service = IngestionService(
        {"flaky-source": ExplodingAdapter()},  # type: ignore[dict-item]
        dead_letters=InMemoryDeadLetterSink(),
    )
    result = service.ingest(
        inbound(valid_payload(), source_system="flaky-source")
    )
    assert result.outcome == IngestionOutcome.REJECTED
    assert result.rejection is not None
    assert result.rejection.reason == RejectionReason.ADAPTER_FAILURE
    # Exception internals must not leak raw payload.
    assert "synthetic-customer-1" not in result.rejection.model_dump_json()
