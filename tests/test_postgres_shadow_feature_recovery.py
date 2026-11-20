"""#43/#48/#145: PostgreSQL post-ACK synthetic worker-to-evidence recovery.

Bank/NetGuardians continuity here is a disconnected test fixture, NOT physical
broker/Bank isolation or source authenticity. No Bank feed or payment actions.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from json import dumps
from uuid import UUID

import pytest
import test_postgres_evaluation_alerts as alerts
import test_postgres_synthetic_fraud_workflow as workflow
from test_kafka_ingestion import FakeRecord, make_consumer
from test_postgres_case_writer_bridge import principal
from test_postgres_evaluations import POLICY
from test_postgres_shadow_copy_mve import TENANT, _synthetic_copy

from gasha.cases.evaluation_alerts import (
    PostgresEvaluationAlertWriter,
    evaluation_context_ref,
)
from gasha.domain.models import DecisionAction
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.postgres_store import PostgresPendingEvaluationStore
from gasha.ingestion.service import IngestionService
from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
from gasha.ingestion.worker import IngestionWorker
from gasha.intelligence.feature_set_v1 import ObservedTransfer
from gasha.intelligence.internal_graph import InternalGraphPolicy
from gasha.intelligence.synthetic_shadow_provider import (
    SyntheticHistorySnapshotV1,
    SyntheticShadowWorkerEvaluator,
)
from gasha.orchestration import ShadowOrchestrator
from gasha.postgres_evaluations import (
    PostgresEvaluationPersistence,
    PostgresShadowEvaluationRepository,
)
from gasha.security.access import Capability

installation = workflow.installation


class SyntheticFixtures:
    def __init__(self, values: tuple[SyntheticHistorySnapshotV1, ...]) -> None:
        self.items = {(v.tenant_id, v.event_id): v for v in values}

    def snapshot_for(self, tenant_id: str, event_id: UUID):
        return self.items.get((tenant_id, event_id))


def snapshot_for_copy(copy):
    event_id = UUID(str(copy.payload["event_id"]))
    occurred = datetime.fromisoformat(str(copy.payload["occurred_at"]))
    beneficiary = str(copy.payload["beneficiary_id"])
    return SyntheticHistorySnapshotV1(
        tenant_id=copy.tenant_id,
        event_id=event_id,
        source_system=copy.source_system,
        receipt_cutoff=copy.received_at,
        observations=tuple(
            ObservedTransfer(
                copy.tenant_id, f"prior-{n}", f"sender-{n}", beneficiary,
                None, occurred - timedelta(minutes=n),
                occurred - timedelta(minutes=n),
            )
            for n in range(1, 6)
        ),
        graph_policy=InternalGraphPolicy(policy_version="synthetic-graph-v1"),
        relationship_history_complete=True,
    )


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_post_ack_fresh_worker_derives_atomic_lineage_alerts_case_and_audits(
    installation,
) -> None:
    """Durable pending survives failed evaluator/ACK and empty consumer recovery."""
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    with workflow.connect(installation) as db:
        for migration in (
            "005_create_dead_letters.sql",
            "007_create_pending_evaluations.sql",
            "008_pending_lease_fencing.sql",
            "009_pending_terminal_state.sql",
        ):
            db.execute((alerts.MIGRATIONS / migration).read_text())

    first, second = _synthetic_copy(), _synthetic_copy()
    copies = (first, second)
    bank_path = [str(first.payload["event_id"]), str(second.payload["event_id"])]
    netguardians_path = list(bank_path)
    fixtures = SyntheticFixtures(tuple(snapshot_for_copy(copy) for copy in copies))
    wire = tuple(dumps(x.model_dump(mode="json")).encode() for x in copies)
    consumer, batch, dead_letters = make_consumer([
        FakeRecord(wire[0], 1), FakeRecord(wire[1], 2),
        FakeRecord(wire[0], 3),
    ])

    def unavailable(_event: FraudEventEnvelope, _policy=None):
        raise TimeoutError("synthetic Gasha-only evaluator failure")

    with workflow.connect(installation) as db:
        failed = IngestionWorker(
            consumer,
            IngestionService(
                {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
                dead_letters=dead_letters,
            ),
            evaluate=unavailable,
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="lineage-failed",
            ),
            policy_for=lambda _tenant: POLICY,
            worker_id="lineage-failed", tenant_ids=(TENANT,),
            retry_backoff=timedelta(0), dead_letters=dead_letters,
        )
        assert failed.run_once(max_events=3) == 3
        assert batch.commits == 1
        assert dead_letters.records == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 0

    # Deliberately disjoint from the Gasha worker; no callbacks or holds.
    bank_path.append("independent-bank-event-during-Gasha-outage")
    netguardians_path.append("independent-bank-event-during-Gasha-outage")

    empty_consumer, empty_batch, recovery_dlq = make_consumer([])
    with workflow.connect(installation) as db:
        writer = PostgresEvaluationAlertWriter(
            TENANT, workflow.ALERT_POLICY,
            principal(caps=frozenset({Capability.CASE_CREATE})),
        )
        orchestrator = ShadowOrchestrator(
            {TENANT: POLICY},
            persistence=PostgresEvaluationPersistence(
                db, tenant_ids=(TENANT,), require_lease=True, alerts=writer,
            ),
        )
        evaluated: list[UUID] = []

        class Evaluator:
            def __init__(self) -> None:
                self.port = SyntheticShadowWorkerEvaluator(
                    orchestrator, history_source=fixtures,
                )

            def __call__(self, event: FraudEventEnvelope, policy=None):
                result = self.port(event, policy)
                assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
                assert result.decision.action is DecisionAction.HOLD
                evaluated.append(event.event_id)
                return result

        recovered = IngestionWorker(
            empty_consumer,
            IngestionService(
                {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
            ),
            evaluate=Evaluator(),
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="lineage-recovered",
            ),
            worker_id="lineage-recovered", tenant_ids=(TENANT,),
            dead_letters=recovery_dlq,
        )
        assert recovered.run_once(max_events=1) == 0
        assert empty_batch.commits == 0
        assert recovery_dlq.records == ()
        assert len(evaluated) == len(set(evaluated)) == 2
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations"
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM fraud_decision_audit"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 2
        rows = db.execute(
            "SELECT event_id, case_id, context_ref FROM evaluation_alerts"
        ).fetchall()
        assert len(rows) == 2
        assert len({row["case_id"] for row in rows}) == 1
        repository = PostgresShadowEvaluationRepository(db, tenant_ids=(TENANT,))
        for row in rows:
            saved = repository.get(TENANT, UUID(str(row["event_id"])))
            assert saved is not None and saved.feature_evidence is not None
            snapshot = fixtures.snapshot_for(TENANT, saved.event.event_id)
            assert snapshot is not None
            evidence = saved.feature_evidence
            assert evidence.tenant_id == snapshot.tenant_id
            assert evidence.event_id == snapshot.event_id
            assert evidence.decision_as_of == snapshot.receipt_cutoff
            assert evidence.eligible_observations == 5
            assert evidence.lineage_ref
            assert row["context_ref"] == evaluation_context_ref(saved)
            assert "sender-1" not in evidence.model_dump_json()

        # The empty transport never triggers redelivery or new audit/case rows.
        assert recovered.run_once(max_events=1) == 0
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 2
    assert bank_path == netguardians_path
    assert len(bank_path) == 3
