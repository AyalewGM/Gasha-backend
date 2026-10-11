from __future__ import annotations

from datetime import UTC, datetime
from typing import Self
from uuid import uuid4

from gasha.decision.mode import DecisionEnvelope
from gasha.domain.models import (
    DecisionAction,
    FraudDecision,
    OperatingMode,
)
from gasha.ingestion.contracts import (
    AdapterMetadata,
    FraudEventEnvelope,
)
from gasha.orchestration import ShadowEvaluationRecord
from gasha.postgres_evaluations import PostgresShadowEvaluationRepository


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.row: dict[str, object] | None = None

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO shadow_evaluations"):
            tenant_id, event_id, record_json, persisted_at = params
            self.connection.rows.setdefault(
                (str(tenant_id), str(event_id)),
                {"record_json": record_json, "persisted_at": persisted_at},
            )
            return
        if normalized.startswith("SELECT record_json"):
            tenant_id, event_id = params
            self.row = self.connection.rows.get(
                (str(tenant_id), str(event_id))
            )
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self) -> dict[str, object] | None:
        return self.row

    def fetchall(self) -> list[dict[str, object]]:
        raise AssertionError("fetchall not expected")

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.commits = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1


def _record(
    tenant_id: str = "tenant-a", event_id=None
) -> ShadowEvaluationRecord:
    event_id = event_id or uuid4()
    now = datetime.now(UTC)
    decision = FraudDecision(
        tenant_id=tenant_id,
        event_id=event_id,
        action=DecisionAction.HOLD,
        risk_score=0.9,
        reason_codes=["HIGH_JOURNEY_RISK"],
        configuration_version="config-1",
        policy_version="policy-1",
        rule_version="rules-1",
        model_version=None,
        decided_at=now,
        correlation_id="corr-1",
    )
    envelope = FraudEventEnvelope(
        tenant_id=tenant_id,
        event_id=event_id,
        correlation_id="corr-1",
        canonical_transaction=_stub_transaction(tenant_id, event_id, now),
        operating_mode=OperatingMode.SHADOW,
        adapter=AdapterMetadata(
            source_system="test-source",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=now,
        ),
    )
    return ShadowEvaluationRecord(
        event=envelope,
        evaluation=DecisionEnvelope(
            operating_mode=OperatingMode.SHADOW,
            decision=decision,
            effective_action=DecisionAction.NO_ACTION_SHADOW,
            evaluated_at=now,
            evaluation_latency_ms=1.5,
        ),
        persisted_at=now,
    )


def _stub_transaction(tenant_id, event_id, now):
    from decimal import Decimal

    from gasha.domain.models import BeneficiaryType, CanonicalTransaction

    return CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=event_id,
        occurred_at=now,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("100.00"),
        currency="ETB",
        sender_customer_id="cust-1",
        sender_account_id="acct-1",
        beneficiary_id="ben-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="dest-1",
        correlation_id="corr-1",
    )


def test_get_returns_none_for_missing_record() -> None:
    repo = PostgresShadowEvaluationRepository(FakeConnection())
    assert repo.get("tenant-a", uuid4()) is None


def test_save_persists_and_returns_decodable_record() -> None:
    repo = PostgresShadowEvaluationRepository(FakeConnection())
    record = _record()
    persisted = repo.save(record)
    assert persisted == record
    assert (
        persisted.evaluation.effective_action
        == DecisionAction.NO_ACTION_SHADOW
    )


def test_save_is_first_write_wins() -> None:
    connection = FakeConnection()
    repo = PostgresShadowEvaluationRepository(connection)
    original = _record()
    assert repo.save(original) == original
    tampered = _record(event_id=original.event.event_id)
    assert repo.save(tampered) == original
    assert len(connection.rows) == 1


def test_tenant_scoped_lookup() -> None:
    repo = PostgresShadowEvaluationRepository(FakeConnection())
    record = _record(tenant_id="tenant-b")
    repo.save(record)
    assert repo.get("tenant-a", record.event.event_id) is None
    assert repo.get("tenant-b", record.event.event_id) == record
