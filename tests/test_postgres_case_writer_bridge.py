"""#45 synthetic protected HTTP -> PostgreSQL case + audit, not Bank UAT.

No deployed IdP, authoritative evaluation/assignee directory, role provisioning,
proxy or bank activation is represented by these opt-in integration tests.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.cases.postgres_writer_bridge import ExplicitPostgresCaseTransitionWriter
from gasha.cases.timeline import AuthorizedAssignee, VerifiedEvaluation
from gasha.security.access import Capability, CredentialRejected, TrustedPrincipal

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
CAPABILITIES = frozenset({
    Capability.CASE_CREATE, Capability.CASE_TRIAGE, Capability.CASE_ASSIGN,
    Capability.CASE_DISPOSITION, Capability.CASE_CORRECT, Capability.CASE_FEEDBACK,
})
CASE, EVENT, ASSIGNEE = uuid4(), uuid4(), uuid4()


def principal(*, tenant: str = "tenant-a", caps=CAPABILITIES) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-analyst", issuer="synthetic-test",
        credential_ref="synthetic-only", tenant_ids=frozenset({tenant}),
        capabilities=caps, expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


class Verifier:
    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer == "valid":
            return principal()
        if bearer == "other-tenant":
            return principal(tenant="tenant-b")
        if bearer == "no-assign":
            return principal(caps=CAPABILITIES - {Capability.CASE_ASSIGN})
        raise CredentialRejected("revoked synthetic credential")


class IngressAudit:
    def __init__(self) -> None:
        self.events: list[object] = []

    def append(self, event: object) -> None:
        self.events.append(event)


class EvaluationDirectory:
    def __init__(self) -> None:
        self.calls = 0
        self.wrong_tenant = False

    def resolve(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        event_id: UUID, at: datetime,
    ) -> VerifiedEvaluation:
        self.calls += 1
        assert at.utcoffset() is not None
        if tenant_id != "tenant-a" or event_id != EVENT:
            raise LookupError("synthetic source unavailable")
        return VerifiedEvaluation(
            "tenant-b" if self.wrong_tenant else tenant_id,
            event_id, "c" * 64,
        )


class AssigneeDirectory:
    def __init__(self) -> None:
        self.calls = 0
        self.wrong_tenant = False

    def resolve(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        selector: UUID, at: datetime,
    ) -> AuthorizedAssignee:
        self.calls += 1
        if selector != ASSIGNEE or tenant_id != "tenant-a":
            raise LookupError("unknown synthetic assignee")
        return AuthorizedAssignee(
            "tenant-b" if self.wrong_tenant else tenant_id, "a" * 64,
        )


def connect(schema_name: str):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
    connection.commit()
    return connection


@pytest.fixture
def schema():
    import psycopg
    from psycopg import sql

    name = "gasha_bridge_" + uuid4().hex[:14]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            with connect(name) as installation:
                for version in ("010_security_audit_events.sql", "011_analyst_case_events.sql"):
                    installation.execute((MIGRATIONS / version).read_text())
                installation.commit()
            yield name
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


@pytest.fixture
def wired(schema: str):
    names = ("identity_verifier", "security_audit", "case_transition_writer")
    saved = tuple(getattr(app.state, name) for name in names)
    ingress = IngressAudit()
    evaluations = EvaluationDirectory()
    assignees = AssigneeDirectory()
    connections = [0]

    def factory():
        connections[0] += 1
        return connect(schema)

    app.state.identity_verifier = Verifier()
    app.state.security_audit = ingress
    app.state.case_transition_writer = ExplicitPostgresCaseTransitionWriter(
        connections=factory, evaluations=evaluations, assignees=assignees,
    )
    try:
        with TestClient(app) as client:
            yield client, schema, ingress, evaluations, assignees, connections
    finally:
        for name, prior in zip(names, saved, strict=True):
            setattr(app.state, name, prior)


def url(operation: str) -> str:
    return f"/v1/tenants/tenant-a/cases/{CASE}/transitions/{operation}"


def body(reason: str, revision: int, *, key: str | None = None, **extra: object) -> dict:
    return {
        "source_event_id": str(EVENT), "expected_revision": revision,
        "idempotency_key": key or f"{revision + 1:032x}",
        "reason_code": reason, **extra,
    }


def post(client: TestClient, operation: str, payload: dict, *, token="valid"):
    return client.post(
        url(operation), json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


def counts(schema: str) -> tuple[int, int]:
    with connect(schema) as connection:
        row = connection.execute(
            "SELECT (SELECT count(*) FROM analyst_case_events) AS cases, "
            "(SELECT count(*) FROM security_audit_events) AS audits"
        ).fetchone()
        assert row is not None
        return int(row["cases"]), int(row["audits"])


def test_synthetic_http_six_stage_flow_commits_atomic_events_and_audit(wired) -> None:
    client, schema, _audit, evaluations, assignees, connections = wired
    commands = (
        ("create", "source_evaluation", {}),
        ("triage", "analyst_triage", {}),
        ("assign", "investigation_assigned", {"assignee_selector": str(ASSIGNEE)}),
        ("dispose", "fraud_evidence", {"disposition": "confirmed_fraud"}),
        ("correct", "corrected_finding", {"disposition": "confirmed_legitimate"}),
        ("reconcile", "feedback_reconciled", {}),
    )
    for index, (operation, reason, extra) in enumerate(commands):
        response = post(client, operation, body(reason, index, **extra))
        assert response.status_code == 200, response.text
        assert response.json()["revision"] == index + 1
        assert response.json()["bank_execution"] == "unknown"
        assert response.json()["enforcement_activated"] is False
        assert counts(schema) == (index + 1, index + 1)
    assert connections[0] == 6 and evaluations.calls == 6 and assignees.calls == 1
    with connect(schema) as connection:
        audits = connection.execute(
            "SELECT action, result, actor_ref, tenant_ref, context_ref "
            "FROM security_audit_events ORDER BY id"
        ).fetchall()
        assert [entry["action"] for entry in audits] == [
            "case.create", "case.triage", "case.assign", "case.dispose",
            "case.correct", "case.reconcile",
        ]
        assert all(entry["result"] == "allowed" for entry in audits)
        assert all(entry["actor_ref"] == principal().audit_actor for entry in audits)
        assert all(entry["context_ref"] == "c" * 64 for entry in audits)
        assert all(len(entry["tenant_ref"]) == 64 for entry in audits)


def test_idempotent_duplicate_and_stale_revision_keep_durable_counts(wired) -> None:
    client, schema, *_ = wired
    command = body("source_evaluation", 0)
    assert post(client, "create", command).status_code == 200
    replay = post(client, "create", command)
    assert replay.status_code == 200 and replay.json()["revision"] == 1
    assert counts(schema) == (1, 1)
    conflicting = post(client, "create", {**command, "expected_revision": 1})
    assert conflicting.status_code == 409
    stale = post(client, "triage", body("analyst_triage", 0))
    assert stale.status_code == 409
    assert counts(schema) == (1, 1)


def test_cross_tenant_capability_and_untrusted_directory_results_fail_closed(wired) -> None:
    client, schema, _audit, evaluations, assignees, connections = wired
    create = body("source_evaluation", 0)
    assert post(client, "create", create, token="other-tenant").status_code == 404
    assert post(client, "create", create, token="revoked").status_code == 401
    assert connections[0] == 0 and evaluations.calls == 0
    evaluations.wrong_tenant = True
    assert post(client, "create", create).status_code == 503
    assert counts(schema) == (0, 0)
    evaluations.wrong_tenant = False
    assert post(client, "create", create).status_code == 200
    assert post(client, "triage", body("analyst_triage", 1)).status_code == 200
    assert post(client, "assign", body(
        "investigation_assigned", 2, assignee_selector=str(ASSIGNEE),
    ), token="no-assign").status_code == 403
    assert assignees.calls == 0
    assignees.wrong_tenant = True
    assert post(client, "assign", body(
        "investigation_assigned", 2, assignee_selector=str(ASSIGNEE),
    )).status_code == 404
    assert counts(schema) == (2, 2)


def test_postgres_audit_insert_outage_rolls_back_case_event(wired) -> None:
    client, schema, ingress, *_ = wired
    with connect(schema) as connection:
        connection.execute("DROP TABLE security_audit_events")
        connection.commit()
    response = post(client, "create", body("source_evaluation", 0))
    assert response.status_code == 503
    with connect(schema) as connection:
        row = connection.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()
        assert row is not None and row["n"] == 0
    assert any(getattr(item, "reason", None) == "case_transition_unavailable"
               for item in ingress.events)
