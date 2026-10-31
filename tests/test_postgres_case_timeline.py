"""#45 installed PostgreSQL atomic case history: synthetic identities and events.

These tests use isolated schemas and real PG transactions. They are not bank
credentials, IdP verification, an analyst endpoint, or CBE acceptance.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import (
    AuthorizedAssignee,
    BankExecution,
    CaseCommand,
    CaseConflict,
    CaseDisposition,
    CaseOperation,
    CaseReason,
    VerifiedEvaluation,
)
from gasha.security.access import AuthorizationRejected, Capability, TrustedPrincipal

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
AT = datetime(2026, 10, 31, 19, 0, tzinfo=UTC)
CONTEXT = "c" * 64
CAPS = frozenset({
    Capability.CASE_CREATE, Capability.CASE_TRIAGE, Capability.CASE_ASSIGN,
    Capability.CASE_DISPOSITION, Capability.CASE_CORRECT, Capability.CASE_FEEDBACK,
})


class Source:
    def resolve(self, tenant_id: str, event_id):
        return VerifiedEvaluation(tenant_id, event_id, CONTEXT)


def principal(*, tenant: str = "tenant-a", capabilities=CAPS):
    return TrustedPrincipal(
        subject="synthetic-analyst", issuer="synthetic-test",
        credential_ref="synthetic-credential",
        tenant_ids=frozenset({tenant}), capabilities=capabilities,
        expires_at=AT + timedelta(hours=1),
    )


def cmd(operation, case_id, event_id, revision, **kwargs):
    reasons = {
        CaseOperation.CREATE: CaseReason.SOURCE_EVALUATION,
        CaseOperation.TRIAGE: CaseReason.ANALYST_TRIAGE,
        CaseOperation.ASSIGN: CaseReason.INVESTIGATION_ASSIGNED,
        CaseOperation.DISPOSE: CaseReason.FRAUD_EVIDENCE,
        CaseOperation.CORRECT: CaseReason.CORRECTED_FINDING,
        CaseOperation.RECONCILE: CaseReason.FEEDBACK_RECONCILED,
    }
    return CaseCommand(
        tenant_id="tenant-a", case_id=case_id,
        source_event_id=event_id, operation=operation,
        expected_revision=revision, idempotency_key=uuid4().hex,
        reason_code=reasons[operation], **kwargs,
    )


@pytest.fixture
def schema():
    import psycopg
    from psycopg import sql

    name = "gasha_case_" + uuid4().hex[:14]
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


def connect(schema_name):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
    connection.commit()
    return connection


def apply(service, command, *, identity=None, at=AT):
    return service.apply(
        command, principal=identity if identity is not None else principal(),
        source=Source(), at=at,
    )


def counts(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS n FROM analyst_case_events")
        cases = cursor.fetchone()["n"]
        cursor.execute("SELECT COUNT(*) AS n FROM security_audit_events")
        audits = cursor.fetchone()["n"]
    connection.rollback()
    return cases, audits


def test_installed_six_step_lifecycle_and_atomic_redacted_audit(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        case_id, event_id = uuid4(), uuid4()
        steps = (
            (CaseOperation.CREATE, {}),
            (CaseOperation.TRIAGE, {}),
            (CaseOperation.ASSIGN, {
                "assignee": AuthorizedAssignee("tenant-a", "a" * 64),
            }),
            (CaseOperation.DISPOSE, {"disposition": CaseDisposition.FRAUD}),
            (CaseOperation.CORRECT, {"disposition": CaseDisposition.LEGITIMATE}),
            (CaseOperation.RECONCILE, {}),
        )
        for revision, (operation, args) in enumerate(steps):
            event = apply(service, cmd(operation, case_id, event_id, revision, **args))
            assert event.revision == revision + 1
            assert event.bank_execution is BankExecution.UNKNOWN
            assert counts(connection) == (revision + 1, revision + 1)

        with connection.cursor() as cursor:
            cursor.execute("SELECT action, result, actor_ref, tenant_ref, "
                           "event_ref, context_ref FROM security_audit_events ORDER BY id")
            audit = cursor.fetchall()
            assert [row["action"] for row in audit] == [
                "case.create", "case.triage", "case.assign",
                "case.dispose", "case.correct", "case.reconcile",
            ]
            assert all(row["result"] == "allowed" for row in audit)
            assert all(row["actor_ref"] == principal().audit_actor for row in audit)
            assert all(len(row["tenant_ref"]) == 64 for row in audit)
            assert all(len(row["event_ref"]) == 64 for row in audit)
            assert all(row["context_ref"] == CONTEXT for row in audit)
        connection.rollback()
        assert "synthetic-analyst" not in str(audit)


def test_exact_duplicate_is_noop_but_key_reuse_on_another_case_denied(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        event_id, case_id = uuid4(), uuid4()
        command = cmd(CaseOperation.CREATE, case_id, event_id, 0)
        original = apply(service, command)
        assert apply(service, command, at=AT + timedelta(seconds=1)) == original
        assert counts(connection) == (1, 1)

        with pytest.raises(CaseConflict):
            apply(service, replace(command, case_id=uuid4()))
        assert counts(connection) == (1, 1)


def test_stale_revision_and_tenant_permission_denied_without_write(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        case_id, event_id = uuid4(), uuid4()
        apply(service, cmd(CaseOperation.CREATE, case_id, event_id, 0))
        with pytest.raises(CaseConflict):
            apply(service, cmd(CaseOperation.TRIAGE, case_id, event_id, 0))
        with pytest.raises(AuthorizationRejected):
            apply(
                service, cmd(CaseOperation.TRIAGE, case_id, event_id, 1),
                identity=principal(tenant="tenant-b"),
            )
        with pytest.raises(AuthorizationRejected):
            apply(
                service, cmd(CaseOperation.TRIAGE, case_id, event_id, 1),
                identity=principal(capabilities=frozenset()),
            )
        with pytest.raises(AuthorizationRejected):
            apply(
                service, cmd(CaseOperation.TRIAGE, case_id, event_id, 1),
                identity=principal(), at=AT + timedelta(hours=2),
            )
        assert counts(connection) == (1, 1)


def test_missing_audit_table_fails_closed_with_no_case_mutation(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        connection.execute("DROP TABLE security_audit_events")
        connection.commit()
        with pytest.raises(Exception):
            apply(service, cmd(CaseOperation.CREATE, uuid4(), uuid4(), 0))
        assert counts_without_audit(connection) == 0


def counts_without_audit(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS n FROM analyst_case_events")
        count = cursor.fetchone()["n"]
    connection.rollback()
    return count


def test_failed_audit_insert_rolls_back_case_and_allows_retry(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        case_id, event_id = uuid4(), uuid4()
        command = cmd(CaseOperation.CREATE, case_id, event_id, 0)
        connection.execute("""
            CREATE FUNCTION case_deny_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic audit outage'; END; $$;
            CREATE TRIGGER deny_case_audit BEFORE INSERT ON security_audit_events
            FOR EACH ROW EXECUTE FUNCTION case_deny_audit();
        """)
        connection.commit()
        with pytest.raises(Exception, match="synthetic audit outage"):
            apply(service, command)
        assert counts(connection) == (0, 0)
        connection.execute("DROP TRIGGER deny_case_audit ON security_audit_events")
        connection.commit()
        assert apply(service, command).revision == 1
        assert counts(connection) == (1, 1)


def test_concurrent_stale_create_has_one_winner_and_one_atomic_audit(schema):
    case_id, event_id = uuid4(), uuid4()

    def contender(_):
        with connect(schema) as connection:
            service = PostgresCaseTimelineService(connection)
            try:
                apply(service, cmd(CaseOperation.CREATE, case_id, event_id, 0))
            except CaseConflict:
                return "conflict"
            return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(contender, range(2)))
    assert outcomes == ["conflict", "created"]
    with connect(schema) as connection:
        assert counts(connection) == (1, 1)


def test_case_history_read_requires_separate_tenant_scoped_capability(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        case_id, event_id = uuid4(), uuid4()
        apply(service, cmd(CaseOperation.CREATE, case_id, event_id, 0))
        with pytest.raises(AuthorizationRejected):
            service.history(
                principal=principal(), tenant_id="tenant-a",
                case_id=case_id, at=AT,
            )
        with pytest.raises(AuthorizationRejected):
            service.history(
                principal=principal(
                    capabilities=frozenset({Capability.CASE_READ}),
                    tenant="tenant-b",
                ),
                tenant_id="tenant-a", case_id=case_id, at=AT,
            )
        with pytest.raises(AuthorizationRejected):
            service.history(
                principal=principal(capabilities=frozenset({Capability.CASE_READ})),
                tenant_id="tenant-a", case_id=case_id,
                at=AT + timedelta(hours=2),
            )
        history = service.history(
            principal=principal(capabilities=frozenset({Capability.CASE_READ})),
            tenant_id="tenant-a", case_id=case_id, at=AT,
        )
        assert len(history) == 1
        assert history[0].bank_execution is BankExecution.UNKNOWN
        assert counts(connection) == (1, 1)
