"""#43 regression: completed evaluations must survive migration-020 legacy pending recovery.

Real PostgreSQL only. This uses synthetic events and independently tests durable
shadow evidence, tenant-scoped completion, rollback and an empty consumer. It is
not an installed bank, broker, or NetGuardians isolation test.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import test_postgres_evaluation_alerts as alerts
import test_postgres_synthetic_fraud_workflow as workflow
from test_kafka_ingestion import make_consumer
from test_postgres_case_writer_bridge import principal
from test_postgres_evaluations import POLICY
from test_postgres_shadow_copy_mve import (
    TENANT,
    _computed_graph_from_normalized,
    _synthetic_copy,
)

from gasha.cases.evaluation_alerts import PostgresEvaluationAlertWriter
from gasha.domain.models import DecisionAction
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.postgres_store import PostgresPendingEvaluationStore
from gasha.ingestion.service import IngestionService
from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
from gasha.ingestion.worker import IngestionWorker
from gasha.security.access import Capability

installation = workflow.installation


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
@pytest.mark.parametrize("injected_delete_failure", [False, True])
def test_legacy_pending_with_committed_evaluation_is_retired_without_false_dlq(
    installation, injected_delete_failure: bool,
) -> None:
    """Post-evaluation crash + migration-020 must not strand healthy recovery."""
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

    ingestion = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    })
    completed = ingestion.ingest(_synthetic_copy()).envelope
    healthy = ingestion.ingest(_synthetic_copy()).envelope
    foreign = ingestion.ingest(_synthetic_copy("tenant-b")).envelope
    assert completed is not None and healthy is not None and foreign is not None
    stale = datetime.now(UTC) - timedelta(minutes=10)
    with workflow.connect(installation) as db:
        seeder = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="legacy-seed",
            lease_ttl=timedelta(seconds=1),
        )
        seeder.enqueue(completed, enqueued_at=stale, policy=POLICY)
        seeder.enqueue(healthy, enqueued_at=stale, policy=POLICY)
        PostgresPendingEvaluationStore(
            db, tenant_ids=("tenant-b",), worker_id="foreign-seed",
            lease_ttl=timedelta(seconds=1),
        ).enqueue(foreign, enqueued_at=stale, policy=POLICY)

    # Model the real crash interval: evaluation, alert, case and audit commit,
    # but pending.complete() has not yet removed the entry.
    assessed = _computed_graph_from_normalized(completed)
    saved = alerts.evaluate(
        installation, assessed, policy=POLICY,
        writer=PostgresEvaluationAlertWriter(
            TENANT, workflow.ALERT_POLICY,
            principal(caps=frozenset({Capability.CASE_CREATE})),
        ),
    )
    assert saved.effective_action is DecisionAction.NO_ACTION_SHADOW

    # Migration 020 does not backfill identity from untrusted record JSON.
    # The row is old/unverified even though its evaluation already committed.
    with workflow.connect(installation) as db:
        db.execute(
            "UPDATE pending_evaluations "
            "SET adapter_type=NULL, adapter_schema_version=NULL "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(completed.event_id)),
        )
        db.commit()
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(completed.event_id)),
        ).fetchone()["n"] == 1

    calls: list[str] = []

    def evaluate_healthy(event: FraudEventEnvelope, policy=None) -> None:
        assert event.tenant_id == TENANT
        assert event.event_id == healthy.event_id
        assert policy == POLICY
        result = alerts.evaluate(
            installation, _computed_graph_from_normalized(event), policy=policy,
            writer=PostgresEvaluationAlertWriter(
                TENANT, workflow.ALERT_POLICY,
                principal(caps=frozenset({Capability.CASE_CREATE})),
            ),
        )
        assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
        calls.append(str(event.event_id))

    empty, batch, dead_letters = make_consumer([])
    with workflow.connect(installation) as db:
        store = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="recovery-worker",
        )
        worker = IngestionWorker(
            empty, ingestion, evaluate=evaluate_healthy,
            pending=store, worker_id="recovery-worker",
            tenant_ids=(TENANT,), dead_letters=dead_letters,
        )
        if injected_delete_failure:
            db.execute("""
                CREATE FUNCTION reject_legacy_cleanup()
                RETURNS trigger LANGUAGE plpgsql AS $gasha_test$
                BEGIN
                    RAISE EXCEPTION 'synthetic stale cleanup failure';
                END;
                $gasha_test$;
            """)
            db.execute("""
                CREATE TRIGGER reject_legacy_cleanup
                BEFORE DELETE ON pending_evaluations
                FOR EACH ROW EXECUTE FUNCTION reject_legacy_cleanup();
            """)
            db.commit()
            with pytest.raises(Exception, match="synthetic stale cleanup failure"):
                worker.run_once()
            # The failed cleanup must roll back the healthy claim as well.
            current = db.execute(
                "SELECT event_id, leased_by FROM pending_evaluations "
                "WHERE tenant_id=%s",
                (TENANT,),
            ).fetchall()
            assert len(current) == 2
            assert {row["leased_by"] for row in current} == {"legacy-seed"}
            assert db.execute(
                "SELECT count(*) AS n FROM dead_letters",
            ).fetchone()["n"] == 0
            db.execute(
                "DROP TRIGGER reject_legacy_cleanup ON pending_evaluations"
            )
            db.execute("DROP FUNCTION reject_legacy_cleanup()")
            db.commit()

        assert worker.run_once() == 0
        assert worker.run_once() == 0
        assert batch.commits == 0
        assert calls == [str(healthy.event_id)]
        assert dead_letters.records == ()
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters",
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations "
            "WHERE tenant_id=%s", (TENANT,),
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations "
            "WHERE tenant_id='tenant-b' AND event_id=%s",
            (str(foreign.event_id),),
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations "
            "WHERE tenant_id=%s", (TENANT,),
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts "
            "WHERE tenant_id=%s", (TENANT,),
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'",
        ).fetchone()["n"] == 2
