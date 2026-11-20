"""#146/#47 synthetic SHADOW copy boundary and existing ingestion integration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from gasha.decision.mode import ModeAwareDecisionService
from gasha.domain.models import (
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.errors import EventRejection, RejectionReason
from gasha.ingestion.service import (
    IngestionOutcome,
    IngestionService,
    InMemoryDeadLetterSink,
)
from gasha.ingestion.shadow_copy import (
    SHADOW_COPY_SCHEMA,
    SyntheticShadowCopyAdapter,
)

ID = "00000000-0000-4000-8000-000000000041"
T0 = datetime(2026, 11, 20, 12, tzinfo=UTC)


def payload(**changes: object) -> dict[str, object]:
    p: dict[str, object] = {
        "event_id": ID,
        "occurred_at": T0.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "1250.00",
        "currency": "ETB",
        "sender_customer_id": "synthetic-customer",
        "sender_account_id": "synthetic-account",
        "beneficiary_id": "synthetic-beneficiary",
        "beneficiary_type": "external",
        "destination_institution_id": "synthetic-destination",
        "correlation_id": "synthetic-corr",
    }
    p.update(changes)
    return p


def inbound(*, tenant: str = "tenant-a", received: datetime | None = T0,
            fields: dict[str, object] | None = None,
            schema: str = SHADOW_COPY_SCHEMA,
            source: str = "synthetic-shadow-copy") -> InboundBankEvent:
    return InboundBankEvent(
        tenant_id=tenant, source_system=source, schema_version=schema,
        received_at=received, payload=fields if fields is not None else payload(),
    )


def service() -> IngestionService:
    return IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()})


def test_shadow_copy_only_mints_transaction_not_caller_risk_or_authority() -> None:
    result = service().ingest(inbound())
    assert result.outcome is IngestionOutcome.ACCEPTED
    env = result.envelope
    assert env is not None
    assert env.operating_mode is OperatingMode.SHADOW
    assert env.canonical_transaction.event_id == UUID(ID)
    assert env.canonical_transaction.amount.as_tuple().exponent == -2
    assert env.intelligence == IntelligenceSnapshot()
    assert env.signal_policy_versions == ()
    assert env.evidence_reason_codes == ()
    assert env.adapter.adapter_type == "synthetic-shadow-copy"
    assert env.adapter.schema_version == SHADOW_COPY_SCHEMA

    policy = DecisionPolicy(
        configuration_version="cfg-1", policy_version="p-1", rule_version="r-1"
    )
    # Later independently computed risks can produce a hypothetical BLOCK,
    # but even that result has no bank-effective action in shadow mode.
    envelope = ModeAwareDecisionService(
        policy, operating_mode=OperatingMode.SHADOW
    ).decide(
        env.canonical_transaction, IntelligenceSnapshot(transaction_risk=0.99)
    )
    assert envelope.decision.action is DecisionAction.BLOCK
    assert envelope.effective_action is DecisionAction.NO_ACTION_SHADOW


@pytest.mark.parametrize(
    "field,value",
    [
        ("operating_mode", "enforcing"),
        ("operating_mode", "shadow"),
        ("intelligence", {"transaction_risk": 1.0}),
        ("signal_policy_versions", ["attacker-policy"]),
        ("evidence_reason_codes", ["FRAUD_CONFIRMED"]),
        ("enforcement_activated", True),
        ("challenge", True),
        ("customer_name", "PRIVATE PERSON"),
        ("policy", {"block_threshold": 0.1}),
    ],
)
def test_never_accepts_asserted_authority_or_extra_pii(
    field: str, value: object
) -> None:
    r = service().ingest(inbound(fields=payload(**{field: value})))
    assert r.outcome is IngestionOutcome.REJECTED
    assert r.rejection is not None
    assert r.rejection.reason is RejectionReason.INVALID_SCHEMA
    dump = r.rejection.model_dump_json()
    assert "PRIVATE PERSON" not in dump
    assert "synthetic-customer" not in dump
    assert "attacker-policy" not in dump


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"amount": "1e1000000"}, RejectionReason.INVALID_AMOUNT),
        ({"amount": "NaN"}, RejectionReason.INVALID_AMOUNT),
        ({"amount": "0.000000"}, RejectionReason.INVALID_AMOUNT),
        ({"amount": "1234567890123456"}, RejectionReason.INVALID_AMOUNT),
        ({"amount": True}, RejectionReason.INVALID_AMOUNT),
        ({"currency": "etb"}, RejectionReason.INVALID_SCHEMA),
        ({"event_id": "not a uuid"}, RejectionReason.INVALID_SCHEMA),
        ({"occurred_at": "2026-11-20T12:00:00"}, RejectionReason.INVALID_TIMESTAMP),
        ({"occurred_at": "not-a-time"}, RejectionReason.INVALID_TIMESTAMP),
        ({"sender_customer_id": ""}, RejectionReason.INVALID_SCHEMA),
        ({"device_id": 7}, RejectionReason.INVALID_SCHEMA),
    ],
)
def test_malformed_copy_fails_closed(
    change: dict[str, object], reason: RejectionReason
) -> None:
    result = service().ingest(inbound(fields=payload(**change)))
    assert result.outcome is IngestionOutcome.REJECTED
    assert result.rejection is not None
    assert result.rejection.reason is reason


def test_schema_missing_receipt_future_and_source_mismatch_rejected() -> None:
    adapter = SyntheticShadowCopyAdapter()
    for event in (
        inbound(schema="unknown"),
        inbound(received=None),
        inbound(received=T0 - timedelta(seconds=1)),
        inbound(fields={"event_id": ID}),
    ):
        with pytest.raises(EventRejection):
            adapter.adapt(event)
    with pytest.raises(EventRejection) as exc:
        adapter.adapt(inbound(source="foreign-synthetic-source"))
    assert exc.value.record.reason is RejectionReason.INVALID_SCHEMA


def test_equal_instant_with_offset_passes_but_later_event_does_not() -> None:
    # Clocks are compared as UTC instants, never by a fold-sensitive wall clock.
    offset = timezone(timedelta(hours=-5))
    received = datetime(2026, 11, 20, 7, tzinfo=offset)
    assert service().ingest(inbound(received=received)).outcome is IngestionOutcome.ACCEPTED
    late = payload(occurred_at="2026-11-20T12:00:01+00:00")
    assert service().ingest(
        inbound(received=received, fields=late)
    ).outcome is IngestionOutcome.REJECTED


def test_duplicate_conflict_and_tenant_isolation_reuse_existing_store() -> None:
    store = service()
    first = inbound()
    assert store.ingest(first).outcome is IngestionOutcome.ACCEPTED
    assert store.ingest(first).outcome is IngestionOutcome.DUPLICATE
    conflict = store.ingest(inbound(fields=payload(amount="1300.00")))
    assert conflict.outcome is IngestionOutcome.REJECTED
    assert conflict.rejection is not None
    assert conflict.rejection.reason is RejectionReason.DUPLICATE_CONFLICT
    # Same source event ID in another tenant is a distinct observation.
    other = store.ingest(inbound(tenant="tenant-b", fields=payload(amount="700.00")))
    assert other.outcome is IngestionOutcome.ACCEPTED
    assert other.envelope is not None
    assert other.envelope.tenant_id == "tenant-b"


def test_no_event_or_bank_access_occurs_on_ingestion_failure() -> None:
    # This adapter only returns data to the existing worker. It has no dispatch
    # hook or identity material; malformed observations produce no envelope.
    result = service().ingest(inbound(fields=payload(operating_mode="enforcing")))
    assert result.outcome is IngestionOutcome.REJECTED
    assert result.envelope is None
    assert result.rejection is not None


@pytest.mark.parametrize(
    "changes,marker,reason",
    [
        (
            {"event_id": "sensitiveaccount123"},
            "sensitiveaccount123",
            RejectionReason.INVALID_SCHEMA,
        ),
        (
            {"beneficiary_type": "sensitivebeneficiary123"},
            "sensitivebeneficiary123",
            RejectionReason.INVALID_SCHEMA,
        ),
        (
            {
                "beneficiary_id": "sensitivebeneficiary123",
                "destination_institution_id": None,
            },
            "sensitivebeneficiary123",
            RejectionReason.NORMALIZATION_FAILURE,
        ),
    ],
)
def test_invalid_copy_identifiers_never_leak_to_rejection_dead_letter_or_audit(
    changes: dict[str, object], marker: str, reason: RejectionReason
) -> None:
    # Exercise token-valid values that previously reached reference normalization.
    # Its general-purpose rejector echoes raw values; the synthetic boundary must
    # not let those values escape through any returned or stored error record.
    dead_letters = InMemoryDeadLetterSink()
    ingestion = IngestionService(
        {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
        dead_letters=dead_letters,
    )
    result = ingestion.ingest(inbound(fields=payload(**changes)))
    assert result.outcome is IngestionOutcome.REJECTED
    assert result.envelope is None
    assert result.rejection is not None
    assert result.rejection.reason is reason
    assert result.rejection.event_id is None
    assert len(dead_letters.records) == 1
    assert dead_letters.records[0] == result.rejection
    # These are the serializable error and audit/dead-letter representations.
    for evidence in (
        result.rejection.model_dump_json(),
        dead_letters.records[0].model_dump_json(),
        repr(dead_letters.records[0]),
    ):
        assert marker not in evidence
