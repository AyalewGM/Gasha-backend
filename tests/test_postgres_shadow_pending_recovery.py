"""#43/#47 synthetic PostgreSQL pending-ledger recovery on the shadow-copy path.

This is a **test-only** simulation of an independent Bank/NetGuardians path.
It does not install a broker, kill a process, attest Bank clocks or prove
physical fault isolation. Gasha never issues or acknowledges payment actions.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo
from json import dumps, loads

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
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.postgres_store import (
    PostgresPendingEvaluationStore,
    _restored_pending_clock,
)
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionService
from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
from gasha.ingestion.worker import IngestionWorker
from gasha.security.access import Capability

schema = alerts.schema
installation = workflow.installation


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_acknowledged_shadow_copy_recovers_from_postgres_without_broker_redelivery(
    installation,
) -> None:
    """Two wire events + replay; fail Gasha, then recover using only durable pending.

    All committed/alert/case/audit counts are independently reconciled. The
    Bank/incumbent simulation does not call the Gasha worker and proceeds
    through a separate list even when Gasha's evaluator is unavailable.
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

    first, second = _synthetic_copy(), _synthetic_copy()
    bank_accepted = [str(first.payload["event_id"]), str(second.payload["event_id"])]
    incumbent_observed = list(bank_accepted)
    frozen_primary = (tuple(bank_accepted), tuple(incumbent_observed))
    wire_first = dumps(first.model_dump(mode="json")).encode()
    wire_second = dumps(second.model_dump(mode="json")).encode()
    consumer, batch, dead_letters = make_consumer([
        FakeRecord(wire_first, 100),
        FakeRecord(wire_second, 101),
        FakeRecord(wire_first, 102),  # transport retry must not create another pending item
    ])
    ingestion = IngestionService(
        {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
        dead_letters=dead_letters,
    )

    failed_calls = 0

    def failed_evaluator(_event: FraudEventEnvelope, _policy=None) -> None:
        nonlocal failed_calls
        failed_calls += 1
        raise TimeoutError("synthetic Gasha-only PostgreSQL evaluator outage")

    with workflow.connect(installation) as db:
        pending = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="synthetic-failed",
        )
        failed_worker = IngestionWorker(
            consumer, ingestion, evaluate=failed_evaluator,
            pending=pending, dead_letters=dead_letters, tenant_ids=(TENANT,),
            policy_for=lambda _tenant: POLICY,
            retry_backoff=timedelta(0),
            worker_id="synthetic-failed",
        )
        assert failed_worker.run_once(max_events=3) == 3
        assert batch.commits == 1  # acknowledged after durable pending writes
        assert failed_calls == 2
        assert dead_letters.records == ()
        rows = db.execute(
            "SELECT tenant_id, event_id, attempts, terminal FROM pending_evaluations"
        ).fetchall()
        assert len(rows) == 2
        assert {row["tenant_id"] for row in rows} == {TENANT}
        assert all(row["attempts"] == 1 and not row["terminal"] for row in rows)
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

    # The primary payment/NetGuardians simulation proceeds independently of
    # a timed-out Gasha consumer; it receives no hold, block or callback.
    assert (tuple(bank_accepted), tuple(incumbent_observed)) == frozen_primary
    subsequent = "independent-bank-event-during-gasha-outage"
    bank_accepted.append(subsequent)
    incumbent_observed.append(subsequent)
    continued_primary = (tuple(bank_accepted), tuple(incumbent_observed))

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

    empty_consumer, empty_batch, recovery_dead_letters = make_consumer([])
    with workflow.connect(installation) as db:
        recovered_worker = IngestionWorker(
            empty_consumer,
            IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()}),
            evaluate=durable_evaluator,
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="synthetic-recovered",
            ),
            worker_id="synthetic-recovered", tenant_ids=(TENANT,),
            dead_letters=recovery_dead_letters,
        )
        assert recovered_worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0  # no broker redelivery was required
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
            "SELECT tenant_id, event_id, case_id FROM evaluation_alerts"
        ).fetchall()
        assert len(alerts_rows) == 2
        assert {row["tenant_id"] for row in alerts_rows} == {TENANT}
        assert len({row["case_id"] for row in alerts_rows}) == 1
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

    assert (tuple(bank_accepted), tuple(incumbent_observed)) == continued_primary


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
