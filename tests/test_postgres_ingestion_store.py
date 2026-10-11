from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Self
from uuid import uuid4

from gasha.domain.models import BeneficiaryType, CanonicalTransaction
from gasha.ingestion.contracts import (
    AdapterMetadata,
    FraudEventEnvelope,
)
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.outcome_ingestion import IncumbentOutcomeRecord
from gasha.ingestion.postgres_store import (
    PostgresDeadLetterSink,
    PostgresIngestionStore,
    PostgresOutcomeStore,
)
from gasha.ingestion.service import IngestionRecord
from gasha.poc.outcomes import (
    IncumbentControlOutcome,
    OutcomeRecord,
    OutcomeType,
)


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.row: dict[str, object] | None = None
        self.rows_out: list[dict[str, object]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO ingestion_records"):
            tenant_id, event_id, envelope_json, fingerprint, accepted_at = (
                params
            )
            self.connection.records.setdefault(
                (str(tenant_id), str(event_id)),
                {
                    "envelope_json": envelope_json,
                    "payload_fingerprint": fingerprint,
                    "accepted_at": accepted_at,
                },
            )
            return
        if normalized.startswith("INSERT INTO dead_letters"):
            self.connection.dead_letters.append(params)
            return
        if normalized.startswith("INSERT INTO outcome_records"):
            self.connection.outcomes.setdefault(
                (params[0], str(params[1])), []
            ).append({"record_json": params[2]})
            return
        if normalized.startswith("INSERT INTO incumbent_outcome_records"):
            self.connection.incumbents.setdefault(
                (params[0], str(params[1])), []
            ).append({"record_json": params[2]})
            return
        if normalized.startswith(
            "SELECT envelope_json, payload_fingerprint, accepted_at"
        ):
            tenant_id, event_id = params
            self.row = self.connection.records.get(
                (str(tenant_id), str(event_id))
            )
            return
        if "FROM outcome_records" in normalized:
            tenant_id, event_id = params
            self.rows_out = self.connection.outcomes.get(
                (tenant_id, str(event_id)), []
            )
            return
        if "FROM incumbent_outcome_records" in normalized:
            tenant_id, event_id = params
            self.rows_out = self.connection.incumbents.get(
                (tenant_id, str(event_id)), []
            )
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self) -> dict[str, object] | None:
        return self.row

    def fetchall(self) -> list[dict[str, object]]:
        return self.rows_out

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str], dict[str, object]] = {}
        self.dead_letters: list[tuple[object, ...]] = []
        self.outcomes: dict[
            tuple[str, str], list[dict[str, object]]
        ] = {}
        self.incumbents: dict[
            tuple[str, str], list[dict[str, object]]
        ] = {}
        self.commits = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1


def _envelope(tenant_id: str, event_id) -> FraudEventEnvelope:
    now = datetime.now(UTC)
    return FraudEventEnvelope(
        tenant_id=tenant_id,
        event_id=event_id,
        correlation_id="corr-1",
        adapter=AdapterMetadata(
            source_system="test-source",
            adapter_type="reference-json",
            adapter_version="1.0.0",
            schema_version="1.0",
            normalized_at=now,
        ),
        canonical_transaction=CanonicalTransaction(
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
        ),
    )


class TestIngestionStore:
    def test_get_missing_returns_none(self) -> None:
        store = PostgresIngestionStore(FakeConnection())
        assert store.get("tenant-a", uuid4()) is None

    def test_save_then_get_roundtrips(self) -> None:
        store = PostgresIngestionStore(FakeConnection())
        record = IngestionRecord(
            envelope=_envelope("tenant-a", uuid4()),
            payload_fingerprint="fp-1",
            accepted_at=datetime.now(UTC),
        )
        persisted = store.save(record)
        assert persisted == record
        assert store.get(
            "tenant-a", record.envelope.event_id
        ) == record

    def test_save_is_first_write_wins(self) -> None:
        store = PostgresIngestionStore(FakeConnection())
        event_id = uuid4()
        first = IngestionRecord(
            envelope=_envelope("tenant-a", event_id),
            payload_fingerprint="fp-1",
            accepted_at=datetime.now(UTC),
        )
        tampered = IngestionRecord(
            envelope=_envelope("tenant-a", event_id),
            payload_fingerprint="fp-TAMPERED",
            accepted_at=datetime.now(UTC),
        )
        store.save(first)
        assert store.save(tampered).payload_fingerprint == "fp-1"


class TestDeadLetterSink:
    def test_put_appends_record(self) -> None:
        connection = FakeConnection()
        sink = PostgresDeadLetterSink(connection)
        sink.put(
            RejectionRecord(
                reason=RejectionReason.DUPLICATE_CONFLICT,
                detail="conflict",
                tenant_id="tenant-a",
                event_id=str(uuid4()),
            )
        )
        assert len(connection.dead_letters) == 1
        assert connection.commits == 1


class TestOutcomeStore:
    def _outcome(self, outcome: OutcomeType) -> OutcomeRecord:
        return OutcomeRecord(
            tenant_id="tenant-a",
            event_id=self.event_id,
            outcome=outcome,
            outcome_source="case-review",
            outcome_version="v1",
            confirmed_at=datetime.now(UTC),
        )

    event_id = uuid4()

    def test_append_then_history_in_order(self) -> None:
        store = PostgresOutcomeStore(FakeConnection())
        first = self._outcome(OutcomeType.UNRESOLVED)
        second = self._outcome(OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD)
        store.append(first)
        store.append(second)
        assert store.outcomes("tenant-a", self.event_id) == (
            first,
            second,
        )

    def test_incumbent_history_is_separate(self) -> None:
        store = PostgresOutcomeStore(FakeConnection())
        incumbent = IncumbentOutcomeRecord(
            tenant_id="tenant-a",
            event_id=self.event_id,
            outcome=IncumbentControlOutcome.ALERT,
            source_system="incumbent-stack",
        )
        store.append_incumbent(incumbent)
        assert store.outcomes("tenant-a", self.event_id) == ()
        assert store.incumbent_outcomes(
            "tenant-a", self.event_id
        ) == (incumbent,)

    def test_tenant_isolation(self) -> None:
        store = PostgresOutcomeStore(FakeConnection())
        store.append(self._outcome(OutcomeType.CONFIRMED_LEGITIMATE))
        assert store.outcomes("tenant-b", self.event_id) == ()
