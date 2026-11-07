"""#42/#45 test-only composition: verified reads plus durable redacted audit.

This is deliberately NOT an application entrypoint, Bank IdP/session, approved
ranking service, queue-wide snapshot, production audit configuration or stage
authority. The protected default app stays unwired outside this isolated test.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
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


def test_same_fictional_bearer_reads_queue_history_with_durable_audit(lab):
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
    # The case fixture also writes two separate atomic case.create audit rows.
    # Four HTTP requests must each use one fresh attempt ID across their events.
    read_attempts = {row["attempt_ref"] for row in rows if row["action"] == "case.read"}
    assert len(read_attempts) == 4
    assert len({row["attempt_ref"] for row in rows}) == 6
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
    # Only the two durable case.create fixture audits may remain; a rejected
    # HTTP request must not append an authentication or case-read event.
    assert [row["action"] for row in events(schema)] == ["case.create"] * 2


def test_authorized_tenant_history_foreign_case_is_not_found_and_redacted(lab):
    """An A-authorized history lookup must not enumerate B's real stored case.

    Unlike an A-bearer/B-route denial, this reaches the tenant-qualified SQL
    reader and its durable audit after successful tenant A authorization.
    """
    schema, refs, _, _, factory, _, client = lab
    first, second = TENANTS
    foreign_case = refs[second].case_id
    unknown_case = uuid4()
    before = len(events(schema))

    foreign = client.get(history(first, foreign_case), headers=auth(first))
    unknown = client.get(history(first, unknown_case), headers=auth(first))
    for response in (foreign, unknown):
        assert response.status_code == 404
        assert response.json() == {"detail": "case not found"}
        assert "events" not in response.text
        exposed = response.text + str(dict(response.headers))
        for secret in (
            first, second, str(foreign_case), str(refs[second].source_event_id),
            SOURCE_CONTEXT, "test-only-not-a-bank-credential",
        ):
            assert secret not in exposed
    assert dict(foreign.headers) == dict(unknown.headers)
    # Both requests reached the actual PostgreSQL history reader, not just
    # the authorization middleware, and neither returned a foreign row.
    assert factory.calls == 2

    added = events(schema)[before:]
    read_events = [row for row in added if row["action"] == "case.read"]
    assert [row["result"] for row in read_events] == [
        "authorized", "not_found", "authorized", "not_found",
    ]
    assert [row["reason"] for row in read_events] == [
        "allowed", "case_not_found", "allowed", "case_not_found",
    ]
    assert not any(row["result"] == "succeeded" for row in read_events)
    # Each authorized→not_found pair has a stable, distinct server attempt ID.
    assert read_events[0]["attempt_ref"] == read_events[1]["attempt_ref"]
    assert read_events[2]["attempt_ref"] == read_events[3]["attempt_ref"]
    assert read_events[0]["attempt_ref"] != read_events[2]["attempt_ref"]
    assert all(row["tenant_ref"] == tenant_audit_ref(first) for row in read_events)
    for pair, case_id in ((read_events[:2], foreign_case),
                          (read_events[2:], unknown_case)):
        expected_ref = sha256((first + chr(0) + str(case_id)).encode()).hexdigest()
        assert all(row["event_ref"] == expected_ref for row in pair)
    redacted = str(added)
    for secret in (
        first, second, str(foreign_case), str(refs[second].source_event_id),
        SOURCE_CONTEXT, "test-only-not-a-bank-credential",
    ):
        assert secret not in redacted
