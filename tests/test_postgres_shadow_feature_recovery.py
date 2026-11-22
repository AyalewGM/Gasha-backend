"""#43/#48/#145: PostgreSQL post-ACK synthetic worker-to-evidence recovery.

Bank/NetGuardians continuity here is a disconnected test fixture, NOT physical
broker/Bank isolation or source authenticity. No Bank feed or payment actions.
"""
from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from json import dumps
from uuid import UUID, uuid4

import pytest
import test_postgres_evaluation_alerts as alerts
import test_postgres_synthetic_fraud_workflow as workflow
from fastapi.testclient import TestClient
from test_kafka_ingestion import FakeRecord, make_consumer
from test_postgres_case_writer_bridge import ASSIGNEE, AssigneeDirectory, principal
from test_postgres_evaluations import POLICY
from test_postgres_shadow_copy_mve import (
    TENANT,
    _computed_graph_from_normalized,
    _synthetic_copy,
)

from gasha.api.main import app
from gasha.cases.evaluation_alerts import (
    PostgresEvaluationAlertWriter,
    evaluation_context_ref,
)
from gasha.cases.postgres_feature_view import ExplicitPostgresCaseFeatureReader
from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader
from gasha.cases.postgres_writer_bridge import ExplicitPostgresCaseTransitionWriter
from gasha.cases.synthetic_ranking import SyntheticPostgresRankingSource
from gasha.cases.timeline import VerifiedEvaluation
from gasha.domain.models import DecisionAction
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.postgres_store import PostgresPendingEvaluationStore
from gasha.ingestion.service import IngestionService
from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
from gasha.ingestion.worker import IngestionWorker
from gasha.intelligence.feature_set_v1 import ObservedTransfer
from gasha.intelligence.internal_graph import InternalGraphPolicy
from gasha.intelligence.redis_feature_history import RedisFeatureHistory
from gasha.intelligence.synthetic_shadow_provider import (
    RedisSyntheticHistorySource,
    SyntheticHistorySnapshotV1,
    SyntheticShadowWorkerEvaluator,
)
from gasha.orchestration import ShadowOrchestrator
from gasha.postgres_evaluations import (
    PostgresEvaluationPersistence,
    PostgresShadowEvaluationRepository,
)
from gasha.security.access import Capability, CredentialRejected
from gasha.security.postgres_audit import PostgresSecurityAuditSink

schema = alerts.schema
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
@pytest.mark.parametrize("history_mode", ("fixture", "redis"))
def test_post_ack_fresh_worker_derives_atomic_lineage_alerts_case_and_audits(
    installation, monkeypatch, request: pytest.FixtureRequest, history_mode: str,
) -> None:
    """Durable pending survives failed evaluator/ACK and empty consumer recovery."""
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
    copies = (first, second)
    bank_path = [str(first.payload["event_id"]), str(second.payload["event_id"])]
    netguardians_path = list(bank_path)
    fixtures = SyntheticFixtures(tuple(snapshot_for_copy(copy) for copy in copies))
    worker_history = fixtures
    if history_mode == "redis":
        redis_url = os.environ.get("GASHA_TEST_REDIS_URL")
        if not redis_url:
            pytest.skip("synthetic Redis and PostgreSQL integration services required")
        from redis import Redis

        redis_client = Redis.from_url(
            redis_url, socket_timeout=2, socket_connect_timeout=2,
        )
        request.addfinalizer(redis_client.close)
        assert redis_client.ping()
        store = RedisFeatureHistory(
            redis_client, tenant_id=TENANT, epoch=uuid4().hex,
        )
        first_snapshot = snapshot_for_copy(first)
        second_snapshot = snapshot_for_copy(second)
        assert first_snapshot.observations == second_snapshot.observations
        occurred = datetime.fromisoformat(str(first.payload["occurred_at"]))
        store.open_epoch(
            covered_from=occurred - timedelta(hours=1), ttl_seconds=120,
        )
        for prior in first_snapshot.observations:
            assert store.append(prior)
        # Intentionally leave the Redis window unsealed through the first
        # PostgreSQL recovery attempt. No alert or case may be persisted.
        worker_history = RedisSyntheticHistorySource(
            store,
            tenant_id=TENANT,
            source_system=first.source_system,
            graph_policy=first_snapshot.graph_policy,
        )
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
                    orchestrator, history_source=worker_history,
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
            retry_backoff=timedelta(0), max_evaluation_attempts=4,
            dead_letters=recovery_dlq,
        )
        if history_mode == "redis":
            assert recovered.run_once(max_events=1) == 0
            assert evaluated == []
            assert db.execute(
                "SELECT count(*) AS n FROM pending_evaluations"
            ).fetchone()["n"] == 2
            for table in (
                "shadow_evaluations", "evaluation_alerts",
                "analyst_case_events", "security_audit_events",
            ):
                assert db.execute(
                    f"SELECT count(*) AS n FROM {table}"
                ).fetchone()["n"] == 0
            store.seal(available_through=max(copy.received_at for copy in copies))
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
            if history_mode == "redis":
                assert "sender_beneficiary_history_coverage" in evidence.unavailable_signals
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

    # The SAME recovered PostgreSQL case must be readable through the
    # protected FastAPI endpoint, not merely through a direct Python adapter.
    # This explicitly installed TestClient identity is synthetic and is NOT
    # an approved Bank browser/BFF/session/CSRF integration.
    with workflow.connect(installation) as db:
        founding = db.execute(
            "SELECT source_event_id, source_context_ref FROM analyst_case_events "
            "WHERE tenant_id=%s AND case_id=%s AND revision=1",
            (TENANT, rows[0]["case_id"]),
        ).fetchone()
        assert founding is not None
        before_cases = db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"]
        before_alerts = db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"]

    class SyntheticReadIdentity:
        def verify(self, bearer: str):
            if bearer == "synthetic-analyst":
                return principal(caps=frozenset({Capability.CASE_READ}))
            if bearer == "synthetic-foreign":
                return principal(
                    tenant="tenant-b", caps=frozenset({Capability.CASE_READ}),
                )
            if bearer == "synthetic-no-read":
                return principal(caps=frozenset({Capability.CASE_TRIAGE}))
            raise CredentialRejected("synthetic credential refused")

    monkeypatch.setattr(app.state, "identity_verifier", SyntheticReadIdentity())
    monkeypatch.setattr(
        app.state,
        "case_feature_reader",
        ExplicitPostgresCaseFeatureReader(
            connections=lambda: workflow.connect(installation),
        ),
    )
    monkeypatch.setattr(
        app.state,
        "security_audit",
        PostgresSecurityAuditSink(
            connections=lambda: workflow.connect(installation),
        ),
    )
    target = f"/v1/tenants/{TENANT}/cases/{rows[0]['case_id']}/feature-evidence"
    auth = {"Authorization": "Bearer synthetic-analyst"}
    with TestClient(app) as http:
        for denied_headers, status in (
            ({}, 401),
            ({"Authorization": "Bearer synthetic-foreign"}, 404),
            ({"Authorization": "Bearer synthetic-no-read"}, 403),
        ):
            denied = http.get(target, headers=denied_headers)
            assert denied.status_code == status, denied.text
            assert "feature_evidence" not in denied.text

        success = http.get(target, headers=auth)
        assert success.status_code == 200, success.text
        projected = success.json()
        evidence = projected["feature_evidence"]
        assert evidence["scope"] == "case_creation_source_only"
        assert evidence["availability"] == "available"
        assert evidence["source_assurance"] == "synthetic_unattested"
        assert evidence["context_ref"] == founding["source_context_ref"]
        assert evidence["eligible_observations"] == 5
        assert evidence["decision_as_of"] is not None
        assert projected["enforcement_activated"] is False
        assert projected["bank_source_attested"] is False
        assert str(founding["source_event_id"]) not in success.text
        assert "sender-1" not in success.text

        # Failure of the mandatory per-append PostgreSQL audit connection
        # denies the same valid analyst before reading or disclosing evidence.
        def refused_audit_connection():
            raise RuntimeError("synthetic audit database unavailable")

        monkeypatch.setattr(
            app.state, "security_audit",
            PostgresSecurityAuditSink(connections=refused_audit_connection),
        )
        refused = http.get(target, headers=auth)
        assert refused.status_code == 503
        assert "feature_evidence" not in refused.text

    with workflow.connect(installation) as db:
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == before_cases
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == before_alerts
        audits = db.execute(
            "SELECT action, result, tenant_ref, actor_ref, attempt_ref, "
            "context_ref FROM security_audit_events "
            "WHERE action='case.read' ORDER BY id"
        ).fetchall()
        assert any(row["result"] == "succeeded" for row in audits)
        assert any(row["result"] == "authorized" for row in audits)
        assert any(row["result"] == "denied" for row in audits)
        assert all(len(row["tenant_ref"]) == 64 for row in audits)
        assert "tenant-a" not in str(audits) and "tenant-b" not in str(audits)

    assert bank_path == netguardians_path
    assert len(bank_path) == 3

    # #45/Frontend #9 integration contract: exercise analyst transitions
    # against the very same recovered and deduplicated founding case.
    # This still uses FastAPI TestClient, not a browser/BFF/CSRF installation.
    analyst_caps = frozenset({
        Capability.CASE_READ, Capability.CASE_TRIAGE, Capability.CASE_ASSIGN,
        Capability.CASE_DISPOSITION, Capability.CASE_FEEDBACK,
    })

    class SyntheticInvestigatorIdentity:
        def verify(self, bearer: str):
            if bearer == "synthetic-investigator":
                return principal(caps=analyst_caps)
            if bearer == "synthetic-foreign-investigator":
                return principal(tenant="tenant-b", caps=analyst_caps)
            if bearer == "synthetic-read-only":
                return principal(caps=frozenset({Capability.CASE_READ}))
            if bearer == "synthetic-expired":
                return replace(
                    principal(caps=analyst_caps),
                    expires_at=datetime.now(UTC) - timedelta(seconds=1),
                )
            raise CredentialRejected("synthetic credential refused or revoked")

    class CommittedEvaluationDirectory:
        """Synthetic lookup uses the persisted, tenant-bound evaluation, not JSON."""

        def resolve(self, *, principal, tenant_id, event_id, at):
            if tenant_id != TENANT or tenant_id not in principal.tenant_ids:
                raise LookupError("wrong synthetic evaluation scope")
            with workflow.connect(installation) as connection:
                persisted = PostgresShadowEvaluationRepository(
                    connection, tenant_ids=(TENANT,),
                ).get(tenant_id, event_id)
            if persisted is None or persisted.persisted_at > at:
                raise LookupError("synthetic evaluation unavailable")
            return VerifiedEvaluation(
                tenant_id, event_id, evaluation_context_ref(persisted),
            )

    connections = lambda: workflow.connect(installation)
    working_audit = PostgresSecurityAuditSink(connections=connections)
    monkeypatch.setattr(app.state, "identity_verifier", SyntheticInvestigatorIdentity())
    monkeypatch.setattr(app.state, "security_audit", working_audit)
    monkeypatch.setattr(
        app.state, "case_history_reader",
        ExplicitPostgresCaseHistoryReader(connections=connections),
    )
    monkeypatch.setattr(
        app.state, "case_queue_reader",
        ExplicitPostgresCaseQueueReader(
            connections=connections,
            ranking=SyntheticPostgresRankingSource(
                connections=connections, tenant_id=TENANT,
                alert_policies=(workflow.ALERT_POLICY,),
            ),
        ),
    )
    monkeypatch.setattr(
        app.state, "case_transition_writer",
        ExplicitPostgresCaseTransitionWriter(
            connections=connections, evaluations=CommittedEvaluationDirectory(),
            assignees=AssigneeDirectory(),
        ),
    )
    full_auth = {"Authorization": "Bearer synthetic-investigator"}
    case_id = rows[0]["case_id"]
    case_path = f"/v1/tenants/{TENANT}/cases/{case_id}"
    with TestClient(app) as http:
        queue = http.get(f"/v1/tenants/{TENANT}/cases/queue", headers=full_auth)
        assert queue.status_code == 200, queue.text
        [selected] = queue.json()["items"]
        assert selected["case_id"] == str(case_id)
        assert selected["source_event_id"] == str(founding["source_event_id"])
        assert selected["source_context_ref"] == founding["source_context_ref"]
        assert "MM-02" in selected["scenario_ids"]
        assert queue.json()["enforcement_activated"] is False
        initial_history = http.get(f"{case_path}/history", headers=full_auth)
        assert initial_history.status_code == 200, initial_history.text
        assert [item["operation"] for item in initial_history.json()["events"]] == ["create"]
        initial_feature = http.get(f"{case_path}/feature-evidence", headers=full_auth)
        assert initial_feature.status_code == 200, initial_feature.text
        assert initial_feature.json()["feature_evidence"]["context_ref"] == (
            founding["source_context_ref"]
        )

        triage = {
            "source_event_id": str(founding["source_event_id"]),
            "expected_revision": 1,
            "idempotency_key": uuid4().hex,
            "reason_code": "analyst_triage",
        }
        target = f"{case_path}/transitions/triage"
        for denied_headers, expected in (
            ({}, 401),
            ({"Authorization": "Bearer synthetic-revoked"}, 401),
            ({"Authorization": "Bearer synthetic-expired"}, 401),
            ({"Authorization": "Bearer synthetic-read-only"}, 403),
            ({"Authorization": "Bearer synthetic-foreign-investigator"}, 404),
        ):
            refused = http.post(target, json=triage, headers=denied_headers)
            assert refused.status_code == expected, refused.text
            assert "source_context_ref" not in refused.text
        with workflow.connect(installation) as db:
            assert db.execute(
                "SELECT count(*) AS n FROM analyst_case_events"
            ).fetchone()["n"] == before_cases

        def broken_audit():
            raise RuntimeError("synthetic database audit unavailable")

        monkeypatch.setattr(
            app.state, "security_audit",
            PostgresSecurityAuditSink(connections=broken_audit),
        )
        blocked = http.post(target, json=triage, headers=full_auth)
        assert blocked.status_code == 503
        assert "source_event_id" not in blocked.text
        monkeypatch.setattr(app.state, "security_audit", working_audit)
        with workflow.connect(installation) as db:
            assert db.execute(
                "SELECT count(*) AS n FROM analyst_case_events"
            ).fetchone()["n"] == before_cases

        commands = (
            ("triage", triage),
            ("assign", {
                "source_event_id": triage["source_event_id"],
                "expected_revision": 2,
                "idempotency_key": uuid4().hex,
                "reason_code": "investigation_assigned",
                "assignee_selector": str(ASSIGNEE),
            }),
            ("dispose", {
                "source_event_id": triage["source_event_id"],
                "expected_revision": 3,
                "idempotency_key": uuid4().hex,
                "reason_code": "legitimate_evidence",
                "disposition": "confirmed_legitimate",
            }),
            ("reconcile", {
                "source_event_id": triage["source_event_id"],
                "expected_revision": 4,
                "idempotency_key": uuid4().hex,
                "reason_code": "feedback_reconciled",
            }),
        )
        for revision, (operation, body) in enumerate(commands, 1):
            route = f"{case_path}/transitions/{operation}"
            completed = http.post(route, json=body, headers=full_auth)
            assert completed.status_code == 200, completed.text
            assert completed.json()["revision"] == revision + 1
            assert completed.json()["bank_execution"] == "unknown"
            assert completed.json()["enforcement_activated"] is False
            # The same idempotency key must never append another case event.
            repeated = http.post(route, json=body, headers=full_auth)
            assert repeated.status_code == 200, repeated.text
            assert repeated.json() == completed.json()
            refreshed = http.get(f"{case_path}/history", headers=full_auth)
            assert refreshed.status_code == 200, refreshed.text
            assert len(refreshed.json()["events"]) == revision + 1
            assert refreshed.json()["events"][0] == initial_history.json()["events"][0]
            evidence = http.get(f"{case_path}/feature-evidence", headers=full_auth)
            assert evidence.status_code == 200, evidence.text
            assert evidence.json()["feature_evidence"]["context_ref"] == (
                founding["source_context_ref"]
            )
            assert evidence.json()["enforcement_activated"] is False
        end_queue = http.get(f"/v1/tenants/{TENANT}/cases/queue", headers=full_auth)
        assert end_queue.status_code == 200, end_queue.text
        assert end_queue.json()["items"] == []

    with workflow.connect(installation) as db:
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == before_cases + len(commands)
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == before_alerts
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 2
        event_rows = db.execute(
            "SELECT event_json->>\'operation\' AS operation, bank_execution, revision "
            "FROM analyst_case_events WHERE tenant_id=%s AND case_id=%s ORDER BY revision",
            (TENANT, case_id),
        ).fetchall()
        assert [row["operation"] for row in event_rows] == [
            "create", "triage", "assign", "dispose", "reconcile",
        ]
        assert [row["revision"] for row in event_rows] == [1, 2, 3, 4, 5]
        assert all(row["bank_execution"] == "unknown" for row in event_rows)
        redacted = db.execute(
            "SELECT action, tenant_ref, actor_ref FROM security_audit_events"
        ).fetchall()
        assert all("tenant-a" not in str(row) for row in redacted)
        assert all("synthetic-investigator" not in str(row) for row in redacted)
        assert sum(row["action"] == "case.triage" for row in redacted) >= 1

    assert bank_path == netguardians_path


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
@pytest.mark.parametrize(
    "fault",
    ("absent", "tenant", "event", "source", "cutoff", "foreign_observation"),
)
def test_post_ack_provider_rejection_retries_without_partial_shadow_evidence(
    installation, fault: str,
) -> None:
    """Actual PostgreSQL: a bad in-process history source cannot commit evidence.

    Recovery after a corrected fixture must succeed from the pending ledger,
    without another transport delivery and without duplicate audit/cases.
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

    copy = _synthetic_copy()
    wire = dumps(copy.model_dump(mode="json")).encode()
    incoming, batch, initial_dlq = make_consumer([FakeRecord(wire, 1)])

    def unavailable(_event: FraudEventEnvelope, _policy=None):
        raise TimeoutError("Gasha evaluator unavailable; bank not involved")

    with workflow.connect(installation) as db:
        failed = IngestionWorker(
            incoming,
            IngestionService(
                {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
                dead_letters=initial_dlq,
            ),
            evaluate=unavailable,
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="provider-initial",
            ),
            policy_for=lambda _tenant: POLICY,
            worker_id="provider-initial", tenant_ids=(TENANT,),
            retry_backoff=timedelta(0), max_evaluation_attempts=3,
            dead_letters=initial_dlq,
        )
        assert failed.run_once(max_events=1) == 1
        assert batch.commits == 1 and initial_dlq.records == ()
        assert db.execute(
            "SELECT attempts FROM pending_evaluations"
        ).fetchone()["attempts"] == 1

    good_snapshot = snapshot_for_copy(copy)
    bad_snapshot = good_snapshot
    if fault == "tenant":
        bad_snapshot = replace(good_snapshot, tenant_id="tenant-b")
    elif fault == "event":
        bad_snapshot = replace(good_snapshot, event_id=uuid4())
    elif fault == "source":
        bad_snapshot = replace(good_snapshot, source_system="forged-source")
    elif fault == "cutoff":
        bad_snapshot = replace(
            good_snapshot,
            receipt_cutoff=good_snapshot.receipt_cutoff + timedelta(seconds=1),
        )
    elif fault == "foreign_observation":
        observation = replace(good_snapshot.observations[0], tenant_id="tenant-b")
        bad_snapshot = replace(
            good_snapshot,
            observations=(observation, *good_snapshot.observations[1:]),
        )
    bad_source = SyntheticFixtures(()) if fault == "absent" else SyntheticFixtures((bad_snapshot,))

    def make_recovery(db, *, worker_id: str, source: SyntheticFixtures):
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
        transport, transport_batch, dlq = make_consumer([])
        worker = IngestionWorker(
            transport,
            IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()}),
            evaluate=SyntheticShadowWorkerEvaluator(
                orchestrator, history_source=source,
            ),
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id=worker_id,
            ),
            worker_id=worker_id, tenant_ids=(TENANT,),
            retry_backoff=timedelta(0), max_evaluation_attempts=3,
            dead_letters=dlq,
        )
        return worker, transport_batch, dlq

    with workflow.connect(installation) as db:
        worker, empty_batch, dlq = make_recovery(
            db, worker_id="provider-invalid", source=bad_source,
        )
        assert worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0 and dlq.records == ()
        assert db.execute(
            "SELECT attempts FROM pending_evaluations"
        ).fetchone()["attempts"] == 2
        for table in (
            "shadow_evaluations", "fraud_decision_audit",
            "evaluation_alerts", "analyst_case_events", "security_audit_events",
        ):
            assert db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 0

    # A new process/connection fixes the configured provider, not the input JSON.
    with workflow.connect(installation) as db:
        worker, empty_batch, dlq = make_recovery(
            db, worker_id="provider-recovered",
            source=SyntheticFixtures((good_snapshot,)),
        )
        assert worker.run_once(max_events=1) == 0
        assert worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0 and dlq.records == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations"
        ).fetchone()["n"] == 0
        assert db.execute("SELECT count(*) AS n FROM shadow_evaluations").fetchone()["n"] == 1
        assert db.execute("SELECT count(*) AS n FROM evaluation_alerts").fetchone()["n"] == 1
        assert db.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] == 1
        assert db.execute("SELECT count(*) AS n FROM fraud_decision_audit").fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 1
        record = PostgresShadowEvaluationRepository(db, tenant_ids=(TENANT,)).get(
            TENANT, good_snapshot.event_id,
        )
        assert record is not None and record.feature_evidence is not None
        assert record.feature_evidence.tenant_id == good_snapshot.tenant_id
        assert record.feature_evidence.event_id == good_snapshot.event_id
        assert record.feature_evidence.decision_as_of == good_snapshot.receipt_cutoff
        assert record.evaluation.effective_action is DecisionAction.NO_ACTION_SHADOW


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_post_ack_missing_provider_terminal_dlq_is_idempotent(installation) -> None:
    """Two failed post-ACK attempts terminalize exactly once without fraud evidence."""
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

    copy = _synthetic_copy()
    incoming, batch, dlq = make_consumer([
        FakeRecord(dumps(copy.model_dump(mode="json")).encode(), 1),
    ])

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
        first = IngestionWorker(
            incoming,
            IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()}),
            evaluate=SyntheticShadowWorkerEvaluator(orchestrator, history_source=None),
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="missing-provider-first",
            ),
            policy_for=lambda _tenant: POLICY,
            worker_id="missing-provider-first", tenant_ids=(TENANT,),
            max_evaluation_attempts=2, retry_backoff=timedelta(0), dead_letters=dlq,
        )
        assert first.run_once(max_events=1) == 1
        assert batch.commits == 1
        assert db.execute(
            "SELECT attempts, terminal FROM pending_evaluations"
        ).fetchone() == {"attempts": 1, "terminal": False}

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
        empty, empty_batch, next_dlq = make_consumer([])
        worker = IngestionWorker(
            empty,
            IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()}),
            evaluate=SyntheticShadowWorkerEvaluator(orchestrator, history_source=None),
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="missing-provider-second",
            ),
            worker_id="missing-provider-second", tenant_ids=(TENANT,),
            max_evaluation_attempts=2, retry_backoff=timedelta(0),
            dead_letters=next_dlq,
        )
        assert worker.run_once(max_events=1) == 0
        assert worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0
        row = db.execute(
            "SELECT attempts, terminal, leased_by, lease_token FROM pending_evaluations"
        ).fetchone()
        assert row == {
            "attempts": 2, "terminal": True, "leased_by": None, "lease_token": None,
        }
        assert db.execute("SELECT count(*) AS n FROM dead_letters").fetchone()["n"] == 1
        assert db.execute("SELECT count(*) AS n FROM shadow_evaluations").fetchone()["n"] == 0
        assert db.execute("SELECT count(*) AS n FROM fraud_decision_audit").fetchone()["n"] == 0
        assert db.execute("SELECT count(*) AS n FROM evaluation_alerts").fetchone()["n"] == 0
        assert db.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] == 0
        assert db.execute("SELECT count(*) AS n FROM security_audit_events").fetchone()["n"] == 0


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_post_ack_worker_audit_outage_rolls_back_lineage_then_recovers(installation) -> None:
    """A failed alert audit cannot partially commit a recovered worker evaluation.

    The pending event remains retryable after the rejected transaction. Once
    the synthetic audit outage is lifted, one evidence/alert/case is committed.
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

    copy = _synthetic_copy()
    incoming, batch, initial_dlq = make_consumer([
        FakeRecord(dumps(copy.model_dump(mode="json")).encode(), 1),
    ])

    def outage(_event: FraudEventEnvelope, _policy=None):
        raise TimeoutError("synthetic evaluator unavailable")

    with workflow.connect(installation) as db:
        first = IngestionWorker(
            incoming,
            IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()}),
            evaluate=outage,
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="audit-initial",
            ),
            policy_for=lambda _tenant: POLICY,
            worker_id="audit-initial", tenant_ids=(TENANT,),
            max_evaluation_attempts=3, retry_backoff=timedelta(0),
            dead_letters=initial_dlq,
        )
        assert first.run_once(max_events=1) == 1
        assert batch.commits == 1 and initial_dlq.records == ()

    def recovered_worker(db, worker_id: str):
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
        empty, empty_batch, dlq = make_consumer([])
        worker = IngestionWorker(
            empty,
            IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()}),
            evaluate=SyntheticShadowWorkerEvaluator(
                orchestrator,
                history_source=SyntheticFixtures((snapshot_for_copy(copy),)),
            ),
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id=worker_id,
            ),
            worker_id=worker_id, tenant_ids=(TENANT,),
            max_evaluation_attempts=3, retry_backoff=timedelta(0),
            dead_letters=dlq,
        )
        return worker, empty_batch, dlq

    with workflow.connect(installation) as db:
        db.execute(
            "ALTER TABLE security_audit_events ADD CONSTRAINT "
            "recovered_feature_audit_outage "
            "CHECK (action <> 'alert.generate') NOT VALID"
        )
    with workflow.connect(installation) as db:
        worker, empty_batch, dlq = recovered_worker(db, "audit-denied")
        assert worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0 and dlq.records == ()
        assert db.execute(
            "SELECT attempts, terminal FROM pending_evaluations"
        ).fetchone() == {"attempts": 2, "terminal": False}
        for table in (
            "shadow_evaluations", "fraud_decision_audit", "evaluation_alerts",
            "analyst_case_events", "evaluation_alert_policy_provenance",
            "security_audit_events", "dead_letters",
        ):
            assert db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 0
        db.execute(
            "ALTER TABLE security_audit_events "
            "DROP CONSTRAINT recovered_feature_audit_outage"
        )

    with workflow.connect(installation) as db:
        worker, empty_batch, dlq = recovered_worker(db, "audit-recovered")
        assert worker.run_once(max_events=1) == 0
        assert worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0 and dlq.records == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations"
        ).fetchone()["n"] == 0
        for table in (
            "shadow_evaluations", "fraud_decision_audit",
            "evaluation_alerts", "analyst_case_events",
            "evaluation_alert_policy_provenance",
        ):
            assert db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 1
        saved = PostgresShadowEvaluationRepository(db, tenant_ids=(TENANT,)).get(
            TENANT, UUID(str(copy.payload["event_id"])),
        )
        assert saved is not None and saved.feature_evidence is not None
        assert saved.evaluation.effective_action is DecisionAction.NO_ACTION_SHADOW
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters"
        ).fetchone()["n"] == 0


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_legacy_completed_pending_and_source_bound_shadow_recover_together(
    installation,
) -> None:
    """One empty-transport recovery retires committed legacy state and derives
    fresh synthetic feature evidence without touching a foreign tenant.

    This is a PostgreSQL/worker simulation, not physical Bank/NetGuardians
    fault isolation, Bank-trusted source attestation, or payment enforcement.
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

    completed_copy = _synthetic_copy()
    first_copy, second_copy = _synthetic_copy(), _synthetic_copy()
    incomplete_copy, foreign_copy = _synthetic_copy(), _synthetic_copy("tenant-b")
    ingestion = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    })
    completed = ingestion.ingest(completed_copy).envelope
    healthy = tuple(
        ingestion.ingest(copy).envelope
        for copy in (first_copy, second_copy, incomplete_copy)
    )
    foreign = ingestion.ingest(foreign_copy).envelope
    assert completed is not None and foreign is not None
    assert all(event is not None for event in healthy)
    stale = datetime.now(UTC) - timedelta(minutes=10)

    with workflow.connect(installation) as db:
        seeder = PostgresPendingEvaluationStore(
            db, tenant_ids=(TENANT,), worker_id="combined-legacy-seed",
            lease_ttl=timedelta(seconds=1),
        )
        seeder.enqueue(completed, enqueued_at=stale, policy=POLICY)
        for event in healthy:
            assert event is not None
            seeder.enqueue(event, enqueued_at=stale, policy=POLICY)
        PostgresPendingEvaluationStore(
            db, tenant_ids=("tenant-b",), worker_id="combined-foreign-seed",
            lease_ttl=timedelta(seconds=1),
        ).enqueue(foreign, enqueued_at=stale, policy=POLICY)

    # Crash after evaluation/alert/case/audit commit, before pending.complete.
    committed = alerts.evaluate(
        installation, _computed_graph_from_normalized(completed),
        policy=POLICY,
        writer=PostgresEvaluationAlertWriter(
            TENANT, workflow.ALERT_POLICY,
            principal(caps=frozenset({Capability.CASE_CREATE})),
        ),
    )
    assert committed.effective_action is DecisionAction.NO_ACTION_SHADOW
    with workflow.connect(installation) as db:
        db.execute(
            "UPDATE pending_evaluations "
            "SET adapter_type=NULL, adapter_schema_version=NULL "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(completed.event_id)),
        )
        db.commit()

    # Independent synthetic downstream paths do not invoke the Gasha worker.
    bank_path = ["bank-synthetic-continues-during-Gasha-failure"]
    netguardians_path = list(bank_path)
    snapshots = (
        snapshot_for_copy(first_copy),
        snapshot_for_copy(second_copy),
        replace(
            snapshot_for_copy(incomplete_copy),
            relationship_history_complete=False,
        ),
    )
    empty, empty_batch, dead_letters = make_consumer([])
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
        worker = IngestionWorker(
            empty,
            ingestion,
            evaluate=SyntheticShadowWorkerEvaluator(
                orchestrator, history_source=SyntheticFixtures(snapshots),
            ),
            pending=PostgresPendingEvaluationStore(
                db, tenant_ids=(TENANT,), worker_id="combined-recovery",
            ),
            worker_id="combined-recovery", tenant_ids=(TENANT,),
            dead_letters=dead_letters,
        )
        assert worker.run_once(max_events=1) == 0
        assert empty_batch.commits == 0 and dead_letters.records == ()
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations WHERE tenant_id=%s",
            (TENANT,),
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM pending_evaluations WHERE tenant_id=%s",
            ("tenant-b",),
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM dead_letters",
        ).fetchone()["n"] == 0
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations WHERE tenant_id=%s",
            (TENANT,),
        ).fetchone()["n"] == 4
        assert db.execute(
            "SELECT count(*) AS n FROM fraud_decision_audit WHERE tenant_id=%s",
            (TENANT,),
        ).fetchone()["n"] == 4
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events",
        ).fetchone()["n"] == 1

        repository = PostgresShadowEvaluationRepository(db, tenant_ids=(TENANT,))
        for copy in (first_copy, second_copy, incomplete_copy):
            saved = repository.get(TENANT, UUID(str(copy.payload["event_id"])))
            assert saved is not None and saved.feature_evidence is not None
            assert saved.evaluation.effective_action is DecisionAction.NO_ACTION_SHADOW
            assert saved.feature_evidence.decision_as_of == copy.received_at
            assert "sender-1" not in saved.feature_evidence.model_dump_json()
        unavailable = repository.get(
            TENANT, UUID(str(incomplete_copy.payload["event_id"])),
        )
        assert unavailable is not None and unavailable.feature_evidence is not None
        assert (
            "beneficiary_unique_senders_1h"
            in unavailable.feature_evidence.unavailable_signals
        )
        assert "UNAVAILABLE_BENEFICIARY_FAN_IN" in (
            unavailable.event.evidence_reason_codes
        )
        for copy in (first_copy, second_copy):
            event_id = str(copy.payload["event_id"])
            alert = db.execute(
                "SELECT context_ref FROM evaluation_alerts "
                "WHERE tenant_id=%s AND event_id=%s",
                (TENANT, event_id),
            ).fetchone()
            assert alert is not None
            saved = repository.get(TENANT, UUID(event_id))
            assert saved is not None
            assert alert["context_ref"] == evaluation_context_ref(saved)

        counts = {
            table: db.execute(
                f"SELECT count(*) AS n FROM {table}",
            ).fetchone()["n"]
            for table in (
                "shadow_evaluations", "fraud_decision_audit",
                "evaluation_alerts", "analyst_case_events",
                "security_audit_events", "dead_letters",
            )
        }
        assert counts["evaluation_alerts"] >= 3
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'",
        ).fetchone()["n"] == counts["evaluation_alerts"]
        # No broker redelivery, duplicate alert/case, false legacy DLQ or
        # payment action is introduced by another recovery pass.
        assert worker.run_once(max_events=1) == 0
        for table, count in counts.items():
            assert db.execute(
                f"SELECT count(*) AS n FROM {table}",
            ).fetchone()["n"] == count

    assert bank_path == netguardians_path
