"""#42/#45 test-only composition: verified reads plus durable redacted audit.

This is deliberately NOT an application entrypoint, Bank IdP/session, approved
ranking service, queue-wide snapshot, production audit configuration or stage
authority. The protected default app stays unwired outside this isolated test.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
from gasha.cases.postgres_queue_reader import (
    ExplicitPostgresCaseQueueReader,
    RankedCaseReference,
    RankedCaseSelection,
)
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import CaseCommand, CaseOperation, CaseReason, VerifiedEvaluation
from gasha.security.access import (
    Capability,
    CredentialRejected,
    TrustedPrincipal,
    tenant_audit_ref,
)
from gasha.security.postgres_audit import PostgresSecurityAuditSink

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
TENANTS = ("fictional-lab-a", "fictional-lab-b")
SOURCE_CONTEXT = "c" * 64


def connect(schema: str):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
    connection.commit()
    return connection


def principal(tenant: str, *, read: bool = True) -> TrustedPrincipal:
    return TrustedPrincipal(
        issuer="test-only-provider",
        subject=f"fictional-analyst-{tenant}",
        credential_ref="test-only-not-a-bank-credential",
        tenant_ids=frozenset({tenant}),
        capabilities=frozenset({Capability.CASE_READ} if read else {Capability.CASE_TRIAGE}),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


class LabVerifier:
    """Fake provider for the isolated lab; every request checks current revocation."""

    def __init__(self) -> None:
        self.revoked: set[str] = set()
        self.read_denied: set[str] = set()
        self.outage = False

    def verify(self, bearer: str) -> TrustedPrincipal:
        if self.outage:
            raise RuntimeError("synthetic identity service unavailable")
        if bearer in self.revoked or bearer not in TENANTS:
            raise CredentialRejected("synthetic credential rejected")
        return principal(bearer, read=bearer not in self.read_denied)


class SyntheticSource:
    def resolve(self, tenant_id: str, event_id: UUID) -> VerifiedEvaluation:
        return VerifiedEvaluation(tenant_id, event_id, SOURCE_CONTEXT)


class LabRanking:
    """Declared synthetic/unverified; never treated as Bank ranking provenance."""

    def __init__(self, selections: dict[str, RankedCaseSelection]) -> None:
        self.selections = selections
        self.calls = 0

    def select(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        limit: int, at: datetime,
    ) -> RankedCaseSelection:
        self.calls += 1
        return self.selections[tenant_id]


class Connections:
    def __init__(self, schema: str) -> None:
        self.schema = schema
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return connect(self.schema)


@pytest.fixture
def lab():
    if not DSN:
        pytest.skip("GASHA_TEST_POSTGRES_DSN not set")
    import psycopg
    from psycopg import sql

    schema = "gasha_analyst_lab_" + uuid4().hex[:12]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        audit_connection = None
        keys = ("identity_verifier", "security_audit", "case_queue_reader",
                "case_history_reader")
        previous = {key: getattr(app.state, key) for key in keys}
        try:
            refs: dict[str, RankedCaseReference] = {}
            with connect(schema) as connection:
                for filename in ("010_security_audit_events.sql", "011_analyst_case_events.sql"):
                    connection.execute((MIGRATIONS / filename).read_text())
                connection.commit()
                store = PostgresCaseTimelineService(connection)
                for tenant in TENANTS:
                    case_id, event_id = uuid4(), uuid4()
                    store.apply(
                        CaseCommand(
                            tenant_id=tenant, case_id=case_id, source_event_id=event_id,
                            operation=CaseOperation.CREATE, expected_revision=0,
                            idempotency_key=uuid4().hex,
                            reason_code=CaseReason.SOURCE_EVALUATION,
                        ),
                        principal=TrustedPrincipal(
                            issuer="test-only-provider", subject="fixture-writer",
                            credential_ref="test-only-writer",
                            tenant_ids=frozenset({tenant}),
                            capabilities=frozenset({Capability.CASE_CREATE}),
                            expires_at=datetime.now(UTC) + timedelta(hours=1),
                        ),
                        source=SyntheticSource(), at=datetime.now(UTC),
                    )
                    refs[tenant] = RankedCaseReference(
                        case_id, event_id, SOURCE_CONTEXT, ("APP-01",),
                    )
            ranking = LabRanking({
                tenant: RankedCaseSelection(
                    tenant, "synthetic-unapproved-v1", (refs[tenant],),
                )
                for tenant in TENANTS
            })
            verifier = LabVerifier()
            factory = Connections(schema)
            audit_connection = connect(schema)
            app.state.identity_verifier = verifier
            app.state.security_audit = PostgresSecurityAuditSink(audit_connection)
            app.state.case_queue_reader = ExplicitPostgresCaseQueueReader(
                connections=factory, ranking=ranking,
            )
            app.state.case_history_reader = ExplicitPostgresCaseHistoryReader(
                connections=factory,
            )
            with TestClient(app) as client:
                yield schema, refs, verifier, ranking, factory, audit_connection, client
        finally:
            for key, value in previous.items():
                setattr(app.state, key, value)
            if audit_connection is not None:
                audit_connection.close()
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def auth(tenant: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tenant}"}


def queue(tenant: str) -> str:
    return f"/v1/tenants/{tenant}/cases/queue"


def history(tenant: str, case_id: UUID) -> str:
    return f"/v1/tenants/{tenant}/cases/{case_id}/history"


def events(schema: str):
    with connect(schema) as connection:
        return connection.execute(
            """SELECT action, result, actor_ref, tenant_ref, reason,
                      attempt_ref, event_ref, context_ref
               FROM security_audit_events ORDER BY id"""
        ).fetchall()


def test_one_session_reads_matching_queue_and_immutable_history_with_durable_audit(lab):
    schema, refs, _, ranking, factory, _, client = lab
    for tenant in TENANTS:
        queue_response = client.get(queue(tenant), headers=auth(tenant))
        assert queue_response.status_code == 200, queue_response.text
        body = queue_response.json()
        assert body["bank_ranking_approved"] is False
        assert body["enforcement_activated"] is False
        assert len(body["items"]) == 1
        assert body["items"][0]["case_id"] == str(refs[tenant].case_id)
        assert body["items"][0]["source_event_id"] == str(refs[tenant].source_event_id)
        detail = client.get(history(tenant, refs[tenant].case_id), headers=auth(tenant))
        assert detail.status_code == 200, detail.text
        assert detail.json()["case_id"] == body["items"][0]["case_id"]
        assert detail.json()["events"][0]["source_event_id"] == str(
            refs[tenant].source_event_id
        )
        assert detail.json()["enforcement_activated"] is False
        for response in (queue_response, detail):
            assert "credential_ref" not in response.text
            assert "idempotency_ref" not in response.text
            assert "command_ref" not in response.text
    assert ranking.calls == 2
    assert factory.calls == 4
    rows = events(schema)
    assert [row["result"] for row in rows if row["action"] == "case.read"] == [
        "authorized", "succeeded",
    ] * 4
    assert len({row["attempt_ref"] for row in rows}) == 4
    assert all(len(row["attempt_ref"]) == 32 for row in rows)
    assert all(row["tenant_ref"] in {tenant_audit_ref(""), *map(tenant_audit_ref, TENANTS)}
               for row in rows)
    assert all(tenant not in str(rows) for tenant in TENANTS)
    assert "test-only-not-a-bank-credential" not in str(rows)


def test_cross_tenant_revocation_role_and_provider_failure_never_read_data(lab):
    schema, refs, verifier, ranking, factory, _, client = lab
    first, second = TENANTS
    requests = (
        (queue(second), auth(first), 404),
        (history(second, refs[second].case_id), auth(first), 404),
        (queue(first), {}, 401),
    )
    for path, headers, status in requests:
        response = client.get(
            path, headers={**headers, "X-Tenant-Id": second,
                           "X-Role": "admin", "X-Forwarded-Prefix": "/v1"},
        )
        assert response.status_code == status
        assert factory.calls == 0
    verifier.read_denied.add(first)
    assert client.get(queue(first), headers=auth(first)).status_code == 403
    verifier.read_denied.remove(first)
    verifier.revoked.add(first)
    assert client.get(history(first, refs[first].case_id),
                      headers=auth(first)).status_code == 401
    verifier.outage = True
    assert client.get(queue(second), headers=auth(second)).status_code == 503
    assert factory.calls == 0
    assert ranking.calls == 0
    rows = events(schema)
    assert rows
    assert not any(row["result"] == "succeeded" for row in rows)
    assert all(tenant not in str(rows) for tenant in TENANTS)


def test_unverified_cross_tenant_ranking_fails_whole_queue_without_partial_data(lab):
    schema, refs, _, ranking, factory, _, client = lab
    first, second = TENANTS
    ranking.selections[first] = RankedCaseSelection(
        first, "synthetic-unapproved-v1", (refs[first], refs[second]),
    )
    response = client.get(queue(first) + "?limit=2", headers=auth(first))
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert str(refs[first].case_id) not in response.text
    assert str(refs[second].case_id) not in response.text
    assert factory.calls == 2
    case_rows = [row for row in events(schema) if row["action"] == "case.read"]
    assert [row["result"] for row in case_rows] == ["authorized", "failed"]
    assert not any(row["result"] == "succeeded" for row in case_rows)


def test_durable_audit_failure_blocks_both_readers_before_database(lab):
    schema, refs, _, ranking, factory, audit_connection, client = lab
    audit_connection.close()
    for path in (queue(TENANTS[0]), history(TENANTS[0], refs[TENANTS[0]].case_id)):
        response = client.get(path, headers=auth(TENANTS[0]))
        assert response.status_code == 503
        assert response.json() == {"detail": "security audit unavailable"}
    assert factory.calls == 0
    assert ranking.calls == 0
    assert events(schema) == []
