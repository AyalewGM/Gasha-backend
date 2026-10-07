from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from gasha.domain.models import IntelligenceSnapshot, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.errors import EventRejection, RejectionReason
from gasha.ingestion.reference import ReferenceJsonAdapter

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


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


def adapt(payload, **kwargs) -> FraudEventEnvelope:
    return ReferenceJsonAdapter().adapt(inbound(payload, **kwargs))


def rejection_of(payload, **kwargs) -> RejectionReason:
    with pytest.raises(EventRejection) as exc:
        adapt(payload, **kwargs)
    return exc.value.record.reason


def test_valid_payload_normalizes_to_versioned_envelope() -> None:
    envelope = adapt(valid_payload())

    assert envelope.envelope_version == "fraud-event-envelope-1"
    assert envelope.tenant_id == "tenant-a"
    assert envelope.operating_mode == OperatingMode.SHADOW
    assert envelope.canonical_transaction.amount == 1250
    assert envelope.canonical_transaction.currency == "ETB"
    assert envelope.adapter.adapter_type == "reference-json"
    assert envelope.adapter.adapter_version == "1.0.0"
    assert envelope.adapter.schema_version == "1.0"
    assert envelope.adapter.source_system == "synthetic-core-banking"


def test_optional_intelligence_is_carried_when_supplied() -> None:
    envelope = adapt(
        valid_payload(
            intelligence={
                "beneficiary_risk": 0.8,
                "device_session_risk": 0.9,
            },
            signal_policy_versions=["behavioral-2"],
        )
    )
    assert envelope.intelligence.beneficiary_risk == 0.8
    assert envelope.intelligence.device_session_risk == 0.9
    assert envelope.signal_policy_versions == ("behavioral-2",)


def test_missing_telemetry_is_valid_not_risky() -> None:
    envelope = adapt(valid_payload())
    assert envelope.intelligence.model_dump() == {
        field: 0.0 for field in IntelligenceSnapshot.model_fields
    }


def test_malformed_intelligence_degrades_to_unavailable() -> None:
    envelope = adapt(
        valid_payload(intelligence={"beneficiary_risk": "not-a-number"})
    )
    assert envelope.intelligence.beneficiary_risk == 0.0


def test_unsupported_schema_version_is_rejected() -> None:
    assert (
        rejection_of(valid_payload(), schema_version="9.9")
        == RejectionReason.UNSUPPORTED_SCHEMA_VERSION
    )


def test_missing_event_id_is_rejected() -> None:
    payload = valid_payload()
    del payload["event_id"]
    assert (
        rejection_of(payload)
        == RejectionReason.MISSING_REQUIRED_IDENTIFIER
    )


def test_missing_sender_is_rejected() -> None:
    payload = valid_payload()
    del payload["sender_account_id"]
    assert (
        rejection_of(payload)
        == RejectionReason.MISSING_REQUIRED_IDENTIFIER
    )


def test_missing_amount_is_invalid() -> None:
    payload = valid_payload()
    del payload["amount"]
    assert rejection_of(payload) == RejectionReason.INVALID_AMOUNT


def test_non_positive_amount_is_invalid() -> None:
    assert (
        rejection_of(valid_payload(amount="-5"))
        == RejectionReason.INVALID_AMOUNT
    )


def test_bad_timestamp_is_rejected() -> None:
    assert (
        rejection_of(valid_payload(occurred_at="not-a-time"))
        == RejectionReason.INVALID_TIMESTAMP
    )


def test_unsupported_currency_when_configured() -> None:
    adapter = ReferenceJsonAdapter(supported_currencies=("ETB",))
    with pytest.raises(EventRejection) as exc:
        adapter.adapt(inbound(valid_payload(currency="USD")))
    assert exc.value.record.reason == RejectionReason.UNSUPPORTED_CURRENCY


def test_external_beneficiary_needs_destination() -> None:
    payload = valid_payload()
    del payload["destination_institution_id"]
    assert (
        rejection_of(payload) == RejectionReason.NORMALIZATION_FAILURE
    )


def test_enforcing_mode_must_be_requested_explicitly() -> None:
    assert (
        adapt(valid_payload(operating_mode="enforcing")).operating_mode
        == OperatingMode.ENFORCING
    )
    assert (
        rejection_of(valid_payload(operating_mode="bogus"))
        == RejectionReason.INVALID_SCHEMA
    )


def test_rejection_record_is_minimized() -> None:
    payload = valid_payload(
        amount="-5", sender_customer_id="raw-customer-name-xyz"
    )
    with pytest.raises(EventRejection) as exc:
        adapt(payload)
    record = exc.value.record
    assert record.payload_fingerprint
    serialized = record.model_dump_json()
    assert "raw-customer-name-xyz" not in serialized
    assert "synthetic-account-1" not in serialized
