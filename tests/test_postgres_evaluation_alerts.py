"""Synthetic reference ingestion and PostgreSQL alert/case acceptance for #148."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic, sleep
from uuid import uuid4

import pytest
import test_postgres_case_writer_bridge as bridge
from test_postgres_case_writer_bridge import (
    CAPABILITIES,
    DSN,
    MIGRATIONS,
    connect,
    principal,
)
from test_postgres_evaluations import POLICY, envelope, inbound_for

from gasha.cases.evaluation_alerts import AlertPolicy, PostgresEvaluationAlertWriter
from gasha.cases.metrics import SyntheticAlertClock, summarize_synthetic_case_metrics
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import (
    AuthorizedAssignee,
    CaseCommand,
    CaseDisposition,
    CaseOperation,
    CaseReason,
    VerifiedEvaluation,
)
from gasha.domain.models import DecisionAction, IntelligenceSnapshot
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionService
from gasha.orchestration import ShadowOrchestrator
from gasha.postgres_evaluations import PostgresEvaluationPersistence
from gasha.security.access import AuthorizationRejected, Capability

pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
schema = bridge.schema
ALERT_POLICY = AlertPolicy("synthetic-alerts-v1", 0.7, (("HIGH_DEVICE_SESSION_RISK", "ATO-02"),))


@pytest.fixture
def installation(schema):
    with connect(schema) as connection:
        for migration in (
            "001_create_fraud_decision_audit.sql",
            "003_create_shadow_evaluations.sql",
            "017_evaluation_alerts.sql",
        ):
            connection.execute((MIGRATIONS / migration).read_text())
    return schema


def event(tenant="tenant-a", score=0.91):
    sample = envelope(tenant)
    inbound = inbound_for(sample)
    inbound.payload = {
        **inbound.payload,
        "device_id": "synthetic-device",
        "intelligence": IntelligenceSnapshot(device_session_risk=score).model_dump(),
    }
    normalized = IngestionService({inbound.source_system: ReferenceJsonAdapter()}).ingest(inbound)
    assert normalized.envelope is not None
    return normalized.envelope


def evaluate(installation, sample, *, writer=None):
    if writer is None:
        writer = PostgresEvaluationAlertWriter(
            sample.tenant_id, ALERT_POLICY, principal(tenant=sample.tenant_id),
        )
    with connect(installation) as connection:
        persistence = PostgresEvaluationPersistence(connection, alerts=writer)
        return ShadowOrchestrator(
            {sample.tenant_id: POLICY}, persistence=persistence,
        ).evaluate(sample)


def test_ingestion_alert_case_disposition_feedback_and_kpis(installation):
    sample = event()
    result = evaluate(installation, sample)
    assert result.decision.action is DecisionAction.HOLD
    assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
    assert result.decision.risk_score == 0.91

    with connect(installation) as connection:
        alert = connection.execute("SELECT * FROM evaluation_alerts").fetchone()
        assert alert["scenario_ids"] == ["ATO-02"]
        assert alert["priority_seed"] == 2
        assert alert["risk_score"] == 0.91
        assert alert["policy_version"] == ALERT_POLICY.version
        case_id = alert["case_id"]

        class Source:
            def resolve(self, tenant_id, event_id):
                assert (tenant_id, event_id) == (alert["tenant_id"], alert["event_id"])
                return VerifiedEvaluation(tenant_id, event_id, alert["context_ref"])

        timeline = PostgresCaseTimelineService(connection)
        analyst = replace(
            principal(caps=CAPABILITIES | {Capability.CASE_READ}), subject="synthetic-investigator",
        )
        for revision, (operation, reason, fields) in enumerate((
            (CaseOperation.TRIAGE, CaseReason.ANALYST_TRIAGE, {}),
            (CaseOperation.ASSIGN, CaseReason.INVESTIGATION_ASSIGNED,
             {"assignee": AuthorizedAssignee(sample.tenant_id, analyst.audit_actor)}),
            (CaseOperation.DISPOSE, CaseReason.FRAUD_EVIDENCE,
             {"disposition": CaseDisposition.FRAUD}),
            (CaseOperation.RECONCILE, CaseReason.FEEDBACK_RECONCILED, {}),
        ), start=1):
            timeline.apply(
                CaseCommand(
                    sample.tenant_id, case_id, sample.event_id, operation, revision,
                    uuid4().hex, reason, **fields,
                ),
                principal=analyst, source=Source(), at=datetime.now(UTC),
            )
        now = datetime.now(UTC)
        history = timeline.history(
            principal=analyst, tenant_id=sample.tenant_id, case_id=case_id, at=now,
        )
        assert history[0].source_context_ref == alert["context_ref"]
        assert history[-1].operation is CaseOperation.RECONCILE
        metrics = summarize_synthetic_case_metrics(
            tenant_id=sample.tenant_id, histories=(history,), as_of=now,
            alert_clocks=(SyntheticAlertClock(
                sample.tenant_id, case_id, sample.event_id,
                sample.canonical_transaction.occurred_at, alert["generated_at"],
            ),),
        )
        assert metrics["counts"]["confirmed_fraud"] == metrics["counts"]["reconciled"] == 1
        assert metrics["counts"]["open_investigations"] == 0
        assert metrics["investigation_turnaround"]["count"] == 1
        assert metrics["alert_latency"]["count"] == 1
        assert metrics["enforcement_activated"] is False


def test_concurrent_groups_deduplicate_and_isolate_tenants(installation):
    first, second, foreign = event(), event(), event("tenant-b")
    with ThreadPoolExecutor(max_workers=4) as workers:
        futures = [
            workers.submit(evaluate, installation, item) for item in (first, second, first, foreign)
        ]
        for future in futures:
            future.result(timeout=15)
    with connect(installation) as connection:
        alerts = connection.execute("SELECT * FROM evaluation_alerts").fetchall()
        assert len(alerts) == 3
        assert len({row["case_id"] for row in alerts if row["tenant_id"] == "tenant-a"}) == 1
        assert len({row["case_id"] for row in alerts}) == 2
        assert len({row["context_ref"] for row in alerts}) == 3
        assert connection.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] == 2


@pytest.mark.parametrize("score", [0.1, 0.6])
def test_allow_and_monitor_do_not_open_alerts(installation, score):
    evaluate(installation, event(score=score))
    with connect(installation) as connection:
        assert connection.execute("SELECT * FROM evaluation_alerts").fetchall() == []
        assert connection.execute("SELECT * FROM analyst_case_events").fetchall() == []
        assert len(connection.execute("SELECT * FROM shadow_evaluations").fetchall()) == 1


def test_wrong_service_tenant_cannot_create_or_attach(installation):
    writer = PostgresEvaluationAlertWriter("tenant-a", ALERT_POLICY, principal(tenant="tenant-b"))
    with pytest.raises(AuthorizationRejected):
        evaluate(installation, event(), writer=writer)
    with connect(installation) as connection:
        assert connection.execute("SELECT * FROM shadow_evaluations").fetchall() == []
        assert connection.execute("SELECT * FROM evaluation_alerts").fetchall() == []


@pytest.mark.parametrize("existing_case", [False, True])
def test_alert_audit_failure_rolls_back_evaluation_alert_and_any_new_case(
    installation, existing_case,
):
    if existing_case:
        evaluate(installation, event())
    with connect(installation) as connection:
        connection.execute(
            "ALTER TABLE security_audit_events ADD CHECK (action <> 'alert.generate') NOT VALID"
        )
    from psycopg.errors import CheckViolation

    sample = event()
    with pytest.raises(CheckViolation):
        evaluate(installation, sample)
    with connect(installation) as connection:
        for table in (
            "shadow_evaluations", "fraud_decision_audit", "evaluation_alerts", "analyst_case_events",
        ):
            assert len(connection.execute(f"SELECT * FROM {table}").fetchall()) == int(existing_case)
        connection.execute(
            "ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_events_action_check"
        )
    evaluate(installation, sample)
    with connect(installation) as connection:
        assert len(connection.execute("SELECT * FROM evaluation_alerts").fetchall()) == 1 + existing_case
        assert len(connection.execute("SELECT * FROM analyst_case_events").fetchall()) == 1


def test_grouping_rejects_transaction_snapshot_isolation(installation):
    from psycopg import IsolationLevel

    sample = event()
    with connect(installation) as connection:
        connection.isolation_level = IsolationLevel.REPEATABLE_READ
        persistence = PostgresEvaluationPersistence(
            connection, alerts=PostgresEvaluationAlertWriter("tenant-a", ALERT_POLICY, principal()),
        )
        with pytest.raises(ValueError, match="read committed"):
            ShadowOrchestrator({"tenant-a": POLICY}, persistence=persistence).evaluate(sample)
        assert connection.execute("SELECT * FROM shadow_evaluations").fetchall() == []


def test_expired_credential_cannot_attach_after_waiting_for_group_lock(installation):
    evaluate(installation, event())
    sample = event()
    with ThreadPoolExecutor(max_workers=1) as workers, connect(installation) as locker:
        row = locker.execute("SELECT group_ref FROM evaluation_alerts").fetchone()
        locker.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (row["group_ref"],))
        expiry = datetime.now(UTC) + timedelta(seconds=1)
        writer = PostgresEvaluationAlertWriter(
            "tenant-a", ALERT_POLICY, replace(principal(), expires_at=expiry),
        )
        future = workers.submit(evaluate, installation, sample, writer=writer)
        try:
            deadline = monotonic() + 3
            while not locker.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted)"
                " AS waiting"
            ).fetchone()["waiting"]:
                if monotonic() > deadline:
                    pytest.fail("alert worker did not wait on the held group lock")
                sleep(0.01)
            sleep(max(0, (expiry - datetime.now(UTC)).total_seconds()) + 0.02)
        finally:
            locker.rollback()
        with pytest.raises(ValueError, match="current service credential"):
            future.result(timeout=4)
    with connect(installation) as connection:
        assert connection.execute("SELECT count(*) AS n FROM evaluation_alerts").fetchone()["n"] == 1
        assert connection.execute("SELECT count(*) AS n FROM shadow_evaluations").fetchone()["n"] == 1


def test_evaluation_retry_returns_the_original_alert_decision(installation):
    sample = event(score=0.91)
    original = evaluate(installation, sample)
    sample.intelligence = IntelligenceSnapshot(device_session_risk=0.1)
    assert evaluate(installation, sample) == original
    with connect(installation) as connection:
        assert connection.execute("SELECT risk_score FROM evaluation_alerts").fetchone()["risk_score"] == 0.91
