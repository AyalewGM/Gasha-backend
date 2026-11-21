"""Synthetic policy #142 against real #148 persisted alerts and protected HTTP."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest
import test_postgres_evaluation_alerts as alert_tests
from fastapi.testclient import TestClient
from test_postgres_case_writer_bridge import DSN, IngressAudit, connect, principal
from test_postgres_evaluation_alerts import ALERT_POLICY, evaluate, event

from gasha.api.main import app
from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader
from gasha.cases.queue import CaseQueueRejected
from gasha.cases.synthetic_ranking import SyntheticPostgresRankingSource, _RankedEvidence
from gasha.security.access import AuthorizationRejected, Capability, CredentialRejected

installation = alert_tests.installation
schema = alert_tests.schema
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")


class SyntheticVerifier:
    def verify(self, bearer):
        if bearer == "analyst":
            return principal(caps=frozenset({Capability.CASE_READ}))
        if bearer == "foreign":
            return principal(tenant="tenant-b", caps=frozenset({Capability.CASE_READ}))
        raise CredentialRejected("synthetic credential revoked")


def test_authenticated_ranking_uses_strongest_group_alert_and_isolates_tenant(
    installation, monkeypatch,
):
    low, high = event(score=0.72), event(score=0.97)
    distinct = event(score=0.90)
    distinct.canonical_transaction.device_id = "synthetic-other-device"
    foreign = event(tenant="tenant-b", score=0.99)
    for sample in (low, high, distinct, foreign):
        evaluate(installation, sample)

    def connections():
        return connect(installation)

    source = SyntheticPostgresRankingSource(
        connections=connections, tenant_id="tenant-a", alert_policies=(ALERT_POLICY,),
    )
    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    monkeypatch.setattr(app.state, "security_audit", IngressAudit())
    monkeypatch.setattr(app.state, "case_queue_reader", ExplicitPostgresCaseQueueReader(
        connections=connections, ranking=source,
    ))
    with TestClient(app) as client:
        url = "/v1/tenants/tenant-a/cases/queue"
        response = client.get(url, headers={"Authorization": "Bearer analyst"})
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ranking_policy_version"] == "synthetic-alert-priority-v1"
        assert [row["rank"] for row in payload["items"]] == [1, 2]
        assert [row["source_event_id"] for row in payload["items"]] == [
            str(low.event_id), str(distinct.event_id),
        ]
        assert payload["bank_ranking_approved"] is payload["enforcement_activated"] is False
        assert client.get(url, headers={"Authorization": "Bearer foreign"}).status_code == 404
        assert client.get(url, headers={"Authorization": "Bearer revoked"}).status_code == 401


def test_recomputes_priority_and_rejects_tampered_or_future_evidence(installation):
    sample = event()
    evaluate(installation, sample)
    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation),
        tenant_id="tenant-a", alert_policies=(ALERT_POLICY,),
    )
    analyst = principal(caps=frozenset({Capability.CASE_READ}))
    now = datetime.now(UTC)
    assert source.select(principal=analyst, tenant_id="tenant-a", limit=1, at=now).items

    with pytest.raises(AuthorizationRejected):
        source.select(principal=replace(analyst, expires_at=now), tenant_id="tenant-a", limit=1, at=now)
    with pytest.raises(CaseQueueRejected, match="future"):
        source.select(principal=analyst, tenant_id="tenant-a", limit=1, at=now - timedelta(days=1))

    with connect(installation) as connection:
        connection.execute("UPDATE evaluation_alerts SET priority_seed = 3")
    with pytest.raises(CaseQueueRejected, match="disagree"):
        source.select(principal=analyst, tenant_id="tenant-a", limit=1, at=now)


def test_grouped_alert_cannot_be_reassigned_to_an_unrelated_case(installation):
    initial, grouped, distinct = event(score=0.72), event(score=0.97), event(score=0.9)
    distinct.canonical_transaction.device_id = "unrelated-device"
    for sample in (initial, distinct, grouped):
        evaluate(installation, sample)
    with connect(installation) as connection:
        connection.execute(
            "UPDATE evaluation_alerts SET case_id = ("
            "SELECT case_id FROM evaluation_alerts WHERE tenant_id = %s AND event_id = %s"
            ") WHERE tenant_id = %s AND event_id = %s",
            ("tenant-a", distinct.event_id, "tenant-a", grouped.event_id),
        )
    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation),
        tenant_id="tenant-a", alert_policies=(ALERT_POLICY,),
    )
    analyst = principal(caps=frozenset({Capability.CASE_READ}))
    with pytest.raises(CaseQueueRejected, match="unrelated"):
        source.select(principal=analyst, tenant_id="tenant-a", limit=2, at=datetime.now(UTC))


def test_dst_fallback_ranks_and_validates_by_utc_instant(installation):
    """The second 1 AM hour is later, despite its smaller New York wall time."""
    sample = event()
    evaluate(installation, sample)
    with connect(installation) as connection:
        row = connection.execute("""
            SELECT a.*, e.record_json, initial.source_event_id,
                   initial.source_context_ref, initial.occurred_at AS opened_at,
                   initial.occurred_at AS last_transition_at
            FROM evaluation_alerts a
            JOIN shadow_evaluations e USING (tenant_id, event_id)
            JOIN analyst_case_events initial
              ON initial.tenant_id = a.tenant_id
             AND initial.case_id = a.case_id AND initial.revision = 1
        """).fetchone()
    assert row is not None
    zone = ZoneInfo("America/New_York")
    opened = datetime(2026, 11, 1, 1, 50, tzinfo=zone, fold=0)
    later = datetime(2026, 11, 1, 1, 10, tzinfo=zone, fold=1)
    as_of = datetime(2026, 11, 1, 7, tzinfo=UTC)
    assert opened.astimezone(UTC) < later.astimezone(UTC)
    assert not opened <= later  # Regression: Python compares same-zone wall time.

    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation), tenant_id="tenant-a",
        alert_policies=(ALERT_POLICY,),
    )
    evidence = dict(row, opened_at=opened, generated_at=opened, last_transition_at=later)
    assert source._verify(evidence, at=as_of).case_id == row["case_id"]

    # Same wall-time with a different DST fold is not the same evidence instant.
    altered = dict(evidence, generated_at=opened.replace(fold=1))
    with pytest.raises(CaseQueueRejected, match="disagree"):
        source._verify(altered, at=as_of)

    first = _RankedEvidence(
        UUID(int=2), sample.event_id, sample.event_id, "0" * 64,
        "1" * 64, ("ATO-02",), opened, 2, 0.91,
    )
    second = replace(first, case_id=UUID(int=1), opened_at=later)
    assert first.sort_key(as_of) < second.sort_key(as_of)


def test_legacy_null_context_and_feature_evidence_coexist_with_durable_queue_and_replay(
    installation, monkeypatch,
):
    """P1: a legacy null field never breaks ranked history, replay or new evidence.

    Real PostgreSQL with immutable evaluation rows, two fictional cases, no
    trusted Bank source, no external payment action or analyst intervention.
    """
    from json import dumps, loads

    import test_postgres_synthetic_fraud_workflow as workflow
    from test_postgres_evaluations import POLICY
    from test_postgres_shadow_copy_mve import _computed_graph_assessment, _synthetic_copy

    from gasha.cases.evaluation_alerts import (
        PostgresEvaluationAlertWriter,
        evaluation_context_ref,
    )
    from gasha.domain.models import DecisionAction
    from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
    from gasha.orchestration import ShadowEvaluationRecord, ShadowOrchestrator
    from gasha.postgres_evaluations import (
        PostgresEvaluationPersistence,
        PostgresShadowEvaluationRepository,
    )

    old_dump = ShadowEvaluationRecord.model_dump_json

    def old_serializer(self, *args, **kwargs):
        # Model the supported dependency variant that writes an optional null,
        # without altering PostgreSQL's immutable trigger or stored digest.
        saved = loads(old_dump(self, *args, **kwargs))
        if self.feature_evidence is None:
            saved["feature_evidence"] = None
        return dumps(saved, sort_keys=True, separators=(",", ":"))

    old = event()
    with monkeypatch.context() as patch:
        patch.setattr(ShadowEvaluationRecord, "model_dump_json", old_serializer)
        initial = evaluate(installation, old)
        assert initial.effective_action is DecisionAction.NO_ACTION_SHADOW

    with connect(installation) as db:
        legacy_row = db.execute(
            """SELECT e.record_json, a.context_ref, a.case_id
               FROM shadow_evaluations e
               JOIN evaluation_alerts a USING (tenant_id, event_id)
               WHERE e.tenant_id = %s AND e.event_id = %s""",
            ("tenant-a", old.event_id),
        ).fetchone()
        assert legacy_row is not None
        assert loads(legacy_row["record_json"])["feature_evidence"] is None
        assert legacy_row["context_ref"] == evaluation_context_ref(
            ShadowEvaluationRecord.model_validate_json(legacy_row["record_json"])
        )

    # The same event must be an idempotent replay after the optional-null
    # serializer is no longer active, including installed policy provenance.
    replay = evaluate(installation, old)
    assert replay.effective_action is DecisionAction.NO_ACTION_SHADOW

    # Add a genuinely provider-derived new synthetic feature-evidence alert,
    # with a separate historical policy version and independent case.
    alert_tests.install_policy(installation, workflow.ALERT_POLICY)
    assessment = _computed_graph_assessment(
        SyntheticShadowCopyAdapter().adapt(_synthetic_copy())
    )
    with connect(installation) as db:
        writer = PostgresEvaluationAlertWriter(
            "tenant-a", workflow.ALERT_POLICY,
            principal(caps=frozenset({Capability.CASE_CREATE})),
        )
        result = ShadowOrchestrator(
            {"tenant-a": POLICY},
            persistence=PostgresEvaluationPersistence(db, alerts=writer),
        ).evaluate(assessment.assessed_envelope, feature_assessment=assessment)
        assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
        current = PostgresShadowEvaluationRepository(db).get(
            "tenant-a", assessment.event_id,
        )
        assert current is not None and current.feature_evidence is not None
        assert evaluation_context_ref(current) != legacy_row["context_ref"]

    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation),
        tenant_id="tenant-a", alert_policies=(ALERT_POLICY, workflow.ALERT_POLICY),
    )
    analyst = principal(caps=frozenset({Capability.CASE_READ}))
    now = datetime.now(UTC)
    selection = source.select(
        principal=analyst, tenant_id="tenant-a", limit=10, at=now,
    )
    assert len(selection.items) == 2
    assert {item.source_event_id for item in selection.items} == {
        old.event_id, assessment.event_id,
    }
    assert len({item.case_id for item in selection.items}) == 2
    assert any(item.source_context_ref == legacy_row["context_ref"]
               for item in selection.items)
    assert all(set(item.scenario_ids) <= {"ATO-02", "MM-02"}
               for item in selection.items)

    # Reuse the actual installed, protected synthetic API ports: ranking must
    # revalidate both immutable case histories, not just raw SQL references.
    from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader

    reader = ExplicitPostgresCaseQueueReader(
        connections=lambda: connect(installation), ranking=source,
    )
    audit = IngressAudit()
    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    monkeypatch.setattr(app.state, "security_audit", audit)
    monkeypatch.setattr(app.state, "case_queue_reader", reader)
    monkeypatch.setattr(
        app.state, "case_history_reader",
        ExplicitPostgresCaseHistoryReader(connections=lambda: connect(installation)),
    )
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer analyst"}
        queue_response = client.get(
            "/v1/tenants/tenant-a/cases/queue?limit=10", headers=headers,
        )
        assert queue_response.status_code == 200, queue_response.text
        queue = queue_response.json()
        assert [item["rank"] for item in queue["items"]] == [1, 2]
        assert queue["enforcement_activated"] is False
        assert {item["source_event_id"] for item in queue["items"]} == {
            str(old.event_id), str(assessment.event_id),
        }
        for item in selection.items:
            detail = client.get(
                f"/v1/tenants/tenant-a/cases/{item.case_id}/history",
                headers=headers,
            )
            assert detail.status_code == 200, detail.text
            assert detail.json()["events"][0]["source_context_ref"] == (
                item.source_context_ref
            )
            assert detail.json()["events"][0]["bank_execution"] == "unknown"
        assert client.get(
            "/v1/tenants/tenant-a/cases/queue",
            headers={"Authorization": "Bearer foreign"},
        ).status_code == 404
        assert client.get(
            "/v1/tenants/tenant-a/cases/queue",
            headers={"Authorization": "Bearer revoked"},
        ).status_code == 401
    assert all("tenant-a" not in str(e) for e in audit.events)

    with connect(installation) as db:
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM fraud_decision_audit"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action = 'alert.generate'"
        ).fetchone()["n"] == 2

        row = db.execute(
            """SELECT a.*, e.record_json, initial.source_event_id,
                      initial.source_context_ref,
                      initial.occurred_at AS opened_at,
                      initial.occurred_at AS last_transition_at
               FROM evaluation_alerts a
               JOIN shadow_evaluations e USING (tenant_id, event_id)
               JOIN analyst_case_events initial
                 ON initial.tenant_id = a.tenant_id
                AND initial.case_id = a.case_id AND initial.revision = 1
               WHERE a.tenant_id = %s AND a.event_id = %s""",
            ("tenant-a", assessment.event_id),
        ).fetchone()
        assert row is not None
        with pytest.raises(CaseQueueRejected, match="disagree"):
            source._verify(dict(row, context_ref="0" * 64), at=now)
        with pytest.raises(CaseQueueRejected, match="invalid"):
            source._verify(dict(row, tenant_id="tenant-b"), at=now)
        altered = loads(row["record_json"])
        altered["feature_evidence"]["eligible_observations"] += 1
        with pytest.raises(ValueError, match="digest|evidence"):
            source._verify(dict(row, record_json=dumps(altered)), at=now)

    # A foreign principal and tenant cannot inherit either case via ranking.
    with pytest.raises(AuthorizationRejected):
        source.select(
            principal=principal(tenant="tenant-b", caps=frozenset({Capability.CASE_READ})),
            tenant_id="tenant-a", limit=10, at=now,
        )
