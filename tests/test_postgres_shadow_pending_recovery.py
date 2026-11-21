"""#43/#47 synthetic PostgreSQL pending-ledger recovery on the shadow-copy path.

This is a **test-only** simulation of an independent Bank/NetGuardians path.
It does not install a broker, kill a process, attest Bank clocks or prove
physical fault isolation. Gasha never issues or acknowledges payment actions.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from json import dumps, loads
from pathlib import Path
from threading import Event, Thread
from time import perf_counter_ns

import pytest
import test_postgres_evaluation_alerts as alerts
import test_postgres_synthetic_fraud_workflow as workflow
from pydantic import TypeAdapter
from test_kafka_ingestion import FakeRecord, make_consumer
from test_postgres_case_writer_bridge import principal
from test_postgres_evaluations import POLICY, envelope, inbound_for
from test_postgres_shadow_copy_mve import (
    TENANT,
    _computed_graph_from_normalized,
    _synthetic_copy,
)

from gasha.cases.evaluation_alerts import PostgresEvaluationAlertWriter
from gasha.domain.models import DecisionAction
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.postgres_store import (
    PostgresPendingEvaluationStore,
    _restored_pending_clock,
)
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionOutcome, IngestionService
from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
from gasha.ingestion.worker import IngestionWorker
from gasha.security.access import Capability

schema = alerts.schema
installation = workflow.installation


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_acknowledged_shadow_copy_recovers_from_postgres_without_broker_redelivery(
    installation, tmp_path: Path,
) -> None:
    """Primary SQLite commits survive a stalled real PostgreSQL shadow worker.

    The Bank and incumbent-shaped responses are fictional and not observations
    of NetGuardians, installed interfaces, or actual Bank performance.
    """
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    with workflow.connect(installation) as db:
        for migration in (
            "005_create_dead_letters.sql",
            "007_create_pending_evaluations.sql",
            "008_pending_lease_fencing.sql",
            "009_pending_terminal_state.sql",
            "020_pending_adapter_contract.sql",
        ):
            db.execute((alerts.MIGRATIONS / migration).read_text())

    # An independently committed SQLite primary emulator and outbox exist
    # before Gasha starts. No primary operation requests or waits on a verdict.
    primary = sqlite3.connect(tmp_path / "synthetic-primary.sqlite3")
    primary.executescript("""
        CREATE TABLE bank_completions (event_id TEXT PRIMARY KEY, status TEXT NOT NULL);
        CREATE TABLE fictional_incumbent_receipts (event_id TEXT PRIMARY KEY, status TEXT NOT NULL);
        CREATE TABLE synthetic_copy_outbox (
            event_id TEXT PRIMARY KEY, wire TEXT NOT NULL,
            handed_to_worker INTEGER NOT NULL DEFAULT 0
        );
    """)
    primary_latencies_ms: list[float] = []

    def complete_primary(copy: InboundBankEvent) -> None:
        start = perf_counter_ns()
        event_id = str(copy.payload["event_id"])
        primary.execute(
            "INSERT INTO bank_completions VALUES (?, ?)",
            (event_id, "synthetic_accepted"),
        )
        primary.execute(
            "INSERT INTO fictional_incumbent_receipts VALUES (?, ?)",
            (event_id, "fixture_observed_only"),
        )
        primary.execute(
            "INSERT INTO synthetic_copy_outbox (event_id, wire) VALUES (?, ?)",
            (event_id, dumps(copy.model_dump(mode="json"))),
        )
        primary.commit()
        primary_latencies_ms.append((perf_counter_ns() - start) / 1_000_000)

    first, second = _synthetic_copy(), _synthetic_copy()
    complete_primary(first)
    primary.execute(
        "UPDATE synthetic_copy_outbox SET handed_to_worker=1 WHERE event_id=?",
        (str(first.payload["event_id"]),),
    )
    primary.commit()
    wire_first = dumps(first.model_dump(mode="json")).encode()
    consumer, batch, dead_letters = make_consumer([FakeRecord(wire_first, 100)])
    ingestion = IngestionService(
        {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
        dead_letters=dead_letters,
    )

    failed_calls = 0
    entered_shadow = Event()
    release_shadow = Event()
    thread_errors: list[Exception] = []

    def failed_evaluator(_event: FraudEventEnvelope, _policy=None) -> None:
        nonlocal failed_calls
        failed_calls += 1
        entered_shadow.set()
        if not release_shadow.wait(timeout=5):
            raise TimeoutError("synthetic consumer watchdog expired")
        raise TimeoutError("synthetic Gasha-only evaluator unavailable")

    def run_stalled_consumer() -> None:
        try:
            with workflow.connect(installation) as db:
                worker = IngestionWorker(
                    consumer, ingestion, evaluate=failed_evaluator,
                    pending=PostgresPendingEvaluationStore(
                        db, tenant_ids=(TENANT,), worker_id="synthetic-failed",
                    ),
                    dead_letters=dead_letters, tenant_ids=(TENANT,),
                    policy_for=lambda _tenant: POLICY,
                    retry_backoff=timedelta(0), worker_id="synthetic-failed",
                )
                assert worker.run_once(max_events=1) == 1
        except Exception as exc:  # noqa: BLE001 - propagate thread failures to test
            thread_errors.append(exc)

    stalled = Thread(target=run_stalled_consumer, daemon=True)
    stalled.start()
    try:
        assert entered_shadow.wait(timeout=3), "worker never reached pending evaluator"
        assert stalled.is_alive()
        # The second fictional Bank/NG response COMMITS independently while
        # Gasha's actual PostgreSQL pending evaluation is still blocked.
        complete_primary(second)
        assert primary.execute(
            "SELECT count(*) FROM bank_completions"
        ).fetchone()[0] == 2
        assert primary.execute(
            "SELECT count(*) FROM fictional_incumbent_receipts"
        ).fetchone()[0] == 2
        assert primary.execute(
            "SELECT count(*) FROM synthetic_copy_outbox WHERE handed_to_worker=0"
        ).fetchone()[0] == 1
        assert stalled.is_alive(), "Gasha resumed before primary completed"
    finally:
        release_shadow.set()
        stalled.join(timeout=10)
    assert not stalled.is_alive(), "synthetic consumer did not exit"
    assert not thread_errors, thread_errors
    assert batch.commits == 1
    assert failed_calls == 1
    assert dead_letters.records == ()

    with workflow.connect(installation) as db:
        rows = db.execute(
            "SELECT tenant_id, event_id, attempts, terminal FROM pending_evaluations"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["tenant_id"] == TENANT
        assert rows[0]["attempts"] == 1 and not rows[0]["terminal"]
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 0

    # A five-second watchdog is fixture safety, NOT a Bank latency SLA.
    assert len(primary_latencies_ms) == 2
    assert max(primary_latencies_ms) < 5000

    recovered: list[str] = []

    def durable_evaluator(normalized: FraudEventEnvelope, policy=None) -> None:
        assert policy == POLICY  # pinned before the Gasha outage
        assessed = _computed_graph_from_normalized(normalized)
        outcome = alerts.evaluate(
            installation, assessed, policy=policy,
            writer=PostgresEvaluationAlertWriter(
                TENANT, workflow.ALERT_POLICY,
                principal(caps=frozenset({Capability.CASE_CREATE})),
            ),
        )
        assert outcome.decision.action is DecisionAction.HOLD
        assert outcome.effective_action is DecisionAction.NO_ACTION_SHADOW
        recovered.append(str(normalized.event_id))

    queued_wire = primary.execute(
        "SELECT wire FROM synthetic_copy_outbox WHERE handed_to_worker=0"
    ).fetchone()[0]
    assert loads(queued_wire)["payload"]["event_id"] == str(second.payload["event_id"])
    recovery_consumer, recovery_batch, recovery_dead_letters = make_consumer([
        FakeRecord(queued_wire.encode(), 101),
    ])
    recovered_ingestion = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    })
    with workflow.connect(installation) as db:
        recovered_worker = IngestionWorker(
            recovery_consumer,
            recovered_ingestion,
            evaluate=durable_evaluator,
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="synthetic-recovered",
            ),
            worker_id="synthetic-recovered", tenant_ids=(TENANT,),
            dead_letters=recovery_dead_letters,
            policy_for=lambda _tenant: POLICY,
        )
        assert recovered_worker.run_once(max_events=1) == 1
        # FIRST event recovers without broker redelivery from PostgreSQL.
        # SECOND event is replayed from the independent SQLite copy outbox.
        assert recovery_batch.commits == 1
        assert recovered_ingestion.ingest(second).outcome is IngestionOutcome.DUPLICATE
        # Include sanitized failure classes/attempt counts if recovery is blocked.
        diagnostics = db.execute(
            "SELECT attempts, last_error, leased_by, terminal "
            "FROM pending_evaluations ORDER BY enqueued_at"
        ).fetchall()
        assert len(recovered) == len(set(recovered)) == 2, [
            (row["attempts"], row["last_error"], row["leased_by"], row["terminal"])
            for row in diagnostics
        ]
        assert recovery_dead_letters.records == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations"
        ).fetchone()["n"] == 0
        alerts_rows = db.execute(
            "SELECT tenant_id, event_id, case_id, context_ref FROM evaluation_alerts"
        ).fetchall()
        assert len(alerts_rows) == 2
        assert {row["tenant_id"] for row in alerts_rows} == {TENANT}
        assert len({row["case_id"] for row in alerts_rows}) == 1
        assert len({row["context_ref"] for row in alerts_rows}) == 2
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 2

        # A foreign-tenant input must fail *before* transport acknowledgement
        # or durable evaluation, without changing tenant A evidence.
        foreign = dumps(_synthetic_copy("tenant-b").model_dump(mode="json")).encode()
        other_consumer, other_batch, other_dead_letters = make_consumer([
            FakeRecord(foreign, 103),
        ])
        foreign_worker = IngestionWorker(
            other_consumer, ingestion, evaluate=durable_evaluator,
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="synthetic-recovered",
            ),
            tenant_ids=(TENANT,), worker_id="synthetic-recovered",
            dead_letters=other_dead_letters,
        )
        with pytest.raises(PermissionError, match="tenant outside authorized"):
            foreign_worker.run_once(max_events=1)
        assert other_batch.commits == 0
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 2

    # Shadow recovery and foreign-tenant denial must never mutate the
    # independently committed primary/fictional incumbent records.
    assert primary.execute("SELECT count(*) FROM bank_completions").fetchone()[0] == 2
    assert primary.execute(
        "SELECT count(*) FROM fictional_incumbent_receipts"
    ).fetchone()[0] == 2
    assert primary.execute(
        "SELECT status FROM bank_completions ORDER BY event_id"
    ).fetchall() == [("synthetic_accepted",)] * 2
    assert primary.execute(
        "SELECT status FROM fictional_incumbent_receipts ORDER BY event_id"
    ).fetchall() == [("fixture_observed_only",)] * 2
    print(
        "SYNTHETIC_PRIMARY_ISOLATION "
        f"primary_count=2 primary_errors=0 copy_backlog_peak=1 "
        f"primary_max_ms={max(primary_latencies_ms):.3f} "
        "alerts=2 cases=1 gasha_timeout=1 "
        "bank_kpi_approved=false bank_execution=unknown enforcement_activated=false"
    )
    primary.close()


@pytest.mark.parametrize(
    "clock_text",
    ["2026-11-20T15:00:00Z", "2026-11-20T20:30:00+05:30",
     "2026-11-20T09:00:00-06:00"],
)
def test_pending_clock_restores_exact_pydantic_offsets(clock_text: str) -> None:
    """JSON offsets preserve their absolute instant and become stdlib clocks."""
    original = TypeAdapter(datetime).validate_json(dumps(clock_text))
    restored = _restored_pending_clock(original)
    assert restored is not None
    assert type(restored) is datetime
    assert type(restored.tzinfo) is timezone
    assert restored == original
    assert restored.utcoffset() == original.utcoffset()
    assert restored.timestamp() == original.timestamp()


def test_pending_clock_fails_closed_before_any_custom_timezone_callback() -> None:
    """Untrusted tzinfo code and datetime subclasses never execute on restore."""
    calls: list[str] = []

    class UnsafeTimezone(tzinfo):
        def utcoffset(self, dt: datetime | None):
            calls.append("utcoffset")
            raise AssertionError("custom timezone callback must not execute")

        def dst(self, dt: datetime | None):
            calls.append("dst")
            raise AssertionError("custom timezone callback must not execute")

        def tzname(self, dt: datetime | None):
            calls.append("tzname")
            raise AssertionError("custom timezone callback must not execute")

    class UnsafeDateTime(datetime):
        pass

    for bad in (
        datetime(2026, 11, 20),
        datetime(2026, 11, 20, tzinfo=UnsafeTimezone()),
        UnsafeDateTime(2026, 11, 20, tzinfo=UTC),
        "SENSITIVE_MALFORMED_CLOCK",
    ):
        with pytest.raises(ValueError, match="invalid persisted pending timestamp"):
            _restored_pending_clock(bad)  # type: ignore[arg-type]
    assert calls == []
    with pytest.raises(ValueError, match="invalid persisted pending timestamp"):
        _restored_pending_clock(None)
    assert _restored_pending_clock(None, optional=True) is None
    standard = datetime(2026, 11, 20, tzinfo=UTC)
    assert _restored_pending_clock(standard) is standard


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
@pytest.mark.parametrize(
    "tamper",
    [
        "invalid-receipt-clock",
        "tenant-substitution",
        "nested-tenant-substitution",
        "nested-event-id-substitution",
        "adapter-only-relabel",
        "adapter-and-naive-clock-relabel",
    ],
)
@pytest.mark.parametrize("forced_dlq_failure", [False, True])
def test_poison_pending_row_is_quarantined_without_blocking_healthy_recovery(
    installation, tamper: str, forced_dlq_failure: bool,
) -> None:
    """A bad persisted row is terminal/DLQ, while a neighbor can be claimed.

    This uses actual PostgreSQL leasing and an untrusted persisted JSON
    mutation; it does not claim a Bank source, broker or installed IdP.
    """
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    with workflow.connect(installation) as db:
        for migration in (
            "005_create_dead_letters.sql",
            "007_create_pending_evaluations.sql",
            "008_pending_lease_fencing.sql",
            "009_pending_terminal_state.sql",
            "020_pending_adapter_contract.sql",
        ):
            db.execute((alerts.MIGRATIONS / migration).read_text())

    service = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    })
    poison_result = service.ingest(_synthetic_copy())
    good_result = service.ingest(_synthetic_copy())
    assert poison_result.envelope is not None
    assert good_result.envelope is not None
    poison, good = poison_result.envelope, good_result.envelope
    stale = datetime.now(UTC) - timedelta(minutes=10)
    with workflow.connect(installation) as db:
        seeder = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="seed-poison",
            lease_ttl=timedelta(seconds=1),
        )
        seeder.enqueue(poison, enqueued_at=stale, policy=POLICY)
        seeder.enqueue(good, enqueued_at=stale, policy=POLICY)
        stored = db.execute(
            "SELECT record_json FROM pending_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(poison.event_id)),
        ).fetchone()
        assert stored is not None
        malformed = loads(str(stored["record_json"]))
        if tamper == "invalid-receipt-clock":
            malformed["event"]["received_at"] = "SENSITIVE_MALFORMED_CLOCK"
        elif tamper == "tenant-substitution":
            malformed["event"]["tenant_id"] = "tenant-b"
        elif tamper == "nested-tenant-substitution":
            malformed["event"]["canonical_transaction"]["tenant_id"] = "tenant-b"
        elif tamper == "nested-event-id-substitution":
            malformed["event"]["canonical_transaction"]["event_id"] = (
                "00000000-0000-4000-8000-000000000042"
            )
        elif tamper in ("adapter-only-relabel", "adapter-and-naive-clock-relabel"):
            malformed["event"]["adapter"]["adapter_type"] = "reference-json"
            malformed["event"]["adapter"]["schema_version"] = "1.0"
            if tamper == "adapter-and-naive-clock-relabel":
                malformed["event"]["received_at"] = "2026-11-20T12:15:00"
        else:
            pytest.fail(f"unknown synthetic tamper case: {tamper}")
        db.execute(
            "UPDATE pending_evaluations SET record_json=%s "
            "WHERE tenant_id=%s AND event_id=%s",
            (dumps(malformed), TENANT, str(poison.event_id)),
        )
        db.commit()

    with workflow.connect(installation) as db:
        worker = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="recover-poison",
        )
        if forced_dlq_failure:
            # The injected SQL failure must rollback *both* the poison
            # terminalization and the healthy row's lease claim.
            db.execute("""
                CREATE FUNCTION reject_synthetic_dead_letter()
                RETURNS trigger LANGUAGE plpgsql AS $gasha_test$
                BEGIN
                    RAISE EXCEPTION 'synthetic dead-letter write failure';
                END;
                $gasha_test$;
            """)
            db.execute("""
                CREATE TRIGGER reject_synthetic_dead_letter
                BEFORE INSERT ON dead_letters
                FOR EACH ROW EXECUTE FUNCTION reject_synthetic_dead_letter()
            """)
            db.commit()
            with pytest.raises(Exception, match="synthetic dead-letter write failure"):
                worker.due(datetime.now(UTC))
            unchanged = db.execute(
                "SELECT tenant_id, event_id, terminal, attempts, leased_by "
                "FROM pending_evaluations"
            ).fetchall()
            assert len(unchanged) == 2
            assert all(
                row["tenant_id"] == TENANT
                and row["terminal"] is False
                and row["attempts"] == 0
                and row["leased_by"] == "seed-poison"
                for row in unchanged
            )
            assert db.execute(
                "SELECT count(*) AS n FROM dead_letters"
            ).fetchone()["n"] == 0
            db.execute("DROP TRIGGER reject_synthetic_dead_letter ON dead_letters")
            db.execute("DROP FUNCTION reject_synthetic_dead_letter()")
            db.commit()

        claimed = worker.due(datetime.now(UTC))
        assert len(claimed) == 1
        assert claimed[0].event.event_id == good.event_id
        assert claimed[0].event.tenant_id == TENANT
        assert type(claimed[0].event.received_at.tzinfo) is timezone
        rows = db.execute(
            "SELECT tenant_id, event_id, terminal, leased_by, last_error "
            "FROM pending_evaluations ORDER BY event_id"
        ).fetchall()
        poison_row = next(row for row in rows if str(row["event_id"]) == str(poison.event_id))
        assert poison_row["tenant_id"] == TENANT
        assert poison_row["terminal"] is True
        assert poison_row["leased_by"] is None
        assert poison_row["last_error"] == "InvalidPendingRecord"
        dlq = db.execute(
            "SELECT record_json FROM dead_letters "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(poison.event_id)),
        ).fetchall()
        assert len(dlq) == 1
        serialized = str(dlq[0]["record_json"])
        assert "invalid persisted pending record" in serialized
        assert "SENSITIVE_MALFORMED_CLOCK" not in serialized
        assert "tenant-b" not in serialized
        assert "00000000-0000-4000-8000-000000000042" not in serialized
        assert str(good.event_id) not in serialized
        worker.complete(
            TENANT, good.event_id, owner="recover-poison",
            claim_token=claimed[0].claim_token,
            now=datetime.now(UTC),
        )
        assert worker.due(datetime.now(UTC)) == ()
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 0


def test_reference_receipt_clock_can_remain_naive_without_weakening_shadow_clock() -> None:
    """Legacy reference-json is not a receipt-time synthetic feature provider."""
    legacy = TypeAdapter(datetime).validate_json(dumps("2026-11-20T12:15:00"))
    assert legacy.tzinfo is None
    assert _restored_pending_clock(legacy, allow_naive=True) is legacy
    with pytest.raises(ValueError, match="invalid persisted pending timestamp"):
        _restored_pending_clock(legacy)
    with pytest.raises(ValueError, match="invalid persisted pending timestamp"):
        _restored_pending_clock(None, allow_naive=True)


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_reference_naive_receipt_survives_enqueue_and_fresh_pending_claim(
    installation,
) -> None:
    """The shared ledger must not poison a valid reference-json receipt clock."""
    with workflow.connect(installation) as db:
        for migration in (
            "005_create_dead_letters.sql",
            "007_create_pending_evaluations.sql",
            "008_pending_lease_fencing.sql",
            "009_pending_terminal_state.sql",
            "020_pending_adapter_contract.sql",
        ):
            db.execute((alerts.MIGRATIONS / migration).read_text())

    naive = datetime(2026, 11, 20, 12, 15)
    inbound = inbound_for(envelope(TENANT)).model_copy(
        update={"received_at": naive}
    )
    receipt = IngestionService({inbound.source_system: ReferenceJsonAdapter()}).ingest(
        inbound
    )
    assert receipt.envelope is not None
    assert receipt.envelope.received_at == naive
    assert receipt.envelope.received_at.tzinfo is None
    stale = datetime.now(UTC) - timedelta(minutes=10)
    with workflow.connect(installation) as db:
        seeder = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="reference-seeder",
            lease_ttl=timedelta(seconds=1),
        )
        saved = seeder.enqueue(
            receipt.envelope, enqueued_at=stale, policy=POLICY,
        )
        assert saved.event.received_at == naive
        assert saved.event.received_at.tzinfo is None
        contract = db.execute(
            "SELECT adapter_type, adapter_schema_version FROM pending_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(receipt.envelope.event_id)),
        ).fetchone()
        assert contract is not None
        assert (contract["adapter_type"], contract["adapter_schema_version"]) == (
            "reference-json", "1.0",
        )

    with workflow.connect(installation) as db:
        pending = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="reference-recovered",
        )
        claimed = pending.due(datetime.now(UTC))
        assert len(claimed) == 1
        assert claimed[0].event.event_id == receipt.envelope.event_id
        assert claimed[0].event.adapter.adapter_type == "reference-json"
        assert claimed[0].event.received_at == naive
        assert claimed[0].event.received_at.tzinfo is None
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters"
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations WHERE terminal"
        ).fetchone()["n"] == 0


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
@pytest.mark.parametrize(
    "tamper",
    ("outer-tenant", "outer-event", "nested-tenant", "nested-event", "adapter-only"),
)
def test_conflicting_pending_enqueue_readback_checks_sql_identity_and_adapter(
    installation, tamper: str,
) -> None:
    """An existing poisoned SQL key must never be returned to the caller."""
    with workflow.connect(installation) as db:
        for migration in (
            "005_create_dead_letters.sql",
            "007_create_pending_evaluations.sql",
            "008_pending_lease_fencing.sql",
            "009_pending_terminal_state.sql",
            "020_pending_adapter_contract.sql",
        ):
            db.execute((alerts.MIGRATIONS / migration).read_text())
    ingested = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    }).ingest(_synthetic_copy())
    assert ingested.envelope is not None
    original = ingested.envelope
    stale = datetime.now(UTC) - timedelta(minutes=10)

    with workflow.connect(installation) as db:
        pending = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="readback-seed",
            lease_ttl=timedelta(seconds=1),
        )
        pending.enqueue(original, enqueued_at=stale, policy=POLICY)
        row = db.execute(
            "SELECT record_json FROM pending_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(original.event_id)),
        ).fetchone()
        assert row is not None
        corrupt = loads(str(row["record_json"]))
        if tamper == "outer-tenant":
            corrupt["event"]["tenant_id"] = "tenant-b"
        elif tamper == "outer-event":
            corrupt["event"]["event_id"] = "00000000-0000-4000-8000-000000000042"
        elif tamper == "nested-tenant":
            corrupt["event"]["canonical_transaction"]["tenant_id"] = "tenant-b"
        elif tamper == "nested-event":
            corrupt["event"]["canonical_transaction"]["event_id"] = (
                "00000000-0000-4000-8000-000000000042"
            )
        else:
            corrupt["event"]["adapter"]["adapter_type"] = "reference-json"
        db.execute(
            "UPDATE pending_evaluations SET record_json=%s "
            "WHERE tenant_id=%s AND event_id=%s",
            (dumps(corrupt), TENANT, str(original.event_id)),
        )
        db.commit()
        with pytest.raises(ValueError, match="persisted pending identity or adapter mismatch"):
            pending.enqueue(original, enqueued_at=stale, policy=POLICY)
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 0
        # The same SQL-keyed poison is then safely quarantined by the due worker.
        claimed = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="readback-recovered",
        ).due(datetime.now(UTC))
        assert claimed == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations WHERE terminal"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters"
        ).fetchone()["n"] == 1


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_legacy_unbound_adapter_contract_is_not_inferred_from_pending_json(
    installation,
) -> None:
    """Pre-migration rows without independently bound adapter policy fail closed."""
    with workflow.connect(installation) as db:
        for migration in (
            "005_create_dead_letters.sql",
            "007_create_pending_evaluations.sql",
            "008_pending_lease_fencing.sql",
            "009_pending_terminal_state.sql",
            "020_pending_adapter_contract.sql",
        ):
            db.execute((alerts.MIGRATIONS / migration).read_text())
    receipt = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    }).ingest(_synthetic_copy())
    assert receipt.envelope is not None
    with workflow.connect(installation) as db:
        pending = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="legacy-seed",
            lease_ttl=timedelta(seconds=1),
        )
        pending.enqueue(
            receipt.envelope,
            enqueued_at=datetime.now(UTC) - timedelta(minutes=10),
            policy=POLICY,
        )
        db.execute(
            "UPDATE pending_evaluations "
            "SET adapter_type=NULL, adapter_schema_version=NULL "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(receipt.envelope.event_id)),
        )
        db.commit()
        assert pending.due(datetime.now(UTC)) == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations WHERE terminal"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters"
        ).fetchone()["n"] == 1
