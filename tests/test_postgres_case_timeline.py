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
    CaseRejected,
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
    import psycopg

    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        connection.execute("DROP TABLE security_audit_events")
        connection.commit()
        with pytest.raises(psycopg.errors.UndefinedTable):
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


# Install-time corruption is deliberately injected using the test administrator;
# no application role is allowed to edit existing case rows.
@pytest.mark.parametrize(("change_sql", "params"), [
    ("event_json = jsonb_set(event_json, '{tenant_id}', to_jsonb(%s::text))",
     ("tenant-b",)),
    ("event_json = jsonb_set(event_json, '{case_id}', to_jsonb(%s::text))",
     (str(uuid4()),)),
    ("event_json = jsonb_set(event_json, '{revision}', 'true'::jsonb)", ()),
    ("event_json = jsonb_set(event_json, '{previous_revision}', '0'::jsonb)", ()),
    ("event_json = jsonb_set(event_json, '{source_event_id}', to_jsonb(%s::text))",
     (str(uuid4()),)),
    ("event_json = jsonb_set(event_json, '{source_context_ref}', to_jsonb(%s::text))",
     ("b" * 64,)),
    ("event_json = jsonb_set(event_json, '{actor_ref}', to_jsonb(%s::text))",
     ("b" * 64,)),
    ("event_json = jsonb_set(event_json, '{recorded_at}', to_jsonb(%s::text))",
     ((AT + timedelta(minutes=2)).isoformat(),)),
    ("event_json = jsonb_set(event_json, '{idempotency_ref}', to_jsonb(%s::text))",
     ("b" * 64,)),
    ("event_json = jsonb_set(event_json, '{command_ref}', to_jsonb(%s::text))",
     ("b" * 64,)),
    ("event_json = jsonb_set(event_json, '{bank_execution}', to_jsonb(%s::text))",
     ("executed",)),
    ("event_json = jsonb_set(event_json, '{operation}', to_jsonb(%s::text))",
     ("assign",)),
    ("event_json = event_json - 'actor_ref'", ()),
    ("source_event_id = %s", (uuid4(),)),
    ("source_context_ref = %s", ("b" * 64,)),
    ("actor_ref = %s", ("b" * 64,)),
    ("occurred_at = occurred_at + interval '1 second'", ()),
    ("idempotency_ref = %s", ("b" * 64,)),
    ("command_ref = %s", ("b" * 64,)),
])
def test_corrupt_row_or_json_blocks_history_and_append_without_audit(
    schema, change_sql, params,
):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        case_id, event_id = uuid4(), uuid4()
        apply(service, cmd(CaseOperation.CREATE, case_id, event_id, 0))
        connection.execute(
            "UPDATE analyst_case_events SET " + change_sql
            + " WHERE tenant_id = %s AND case_id = %s",
            (*params, "tenant-a", case_id),
        )
        connection.commit()
        with pytest.raises(CaseRejected):
            service.history(
                principal=principal(capabilities=frozenset({Capability.CASE_READ})),
                tenant_id="tenant-a", case_id=case_id, at=AT,
            )
        with pytest.raises(CaseRejected):
            apply(service, cmd(CaseOperation.TRIAGE, case_id, event_id, 1))
        assert counts(connection) == (1, 1)


def test_missing_first_revision_fails_closed_without_cross_tenant_leak(schema):
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        case_id, event_id = uuid4(), uuid4()
        apply(service, cmd(CaseOperation.CREATE, case_id, event_id, 0))
        apply(service, cmd(CaseOperation.TRIAGE, case_id, event_id, 1))
        connection.execute(
            "DELETE FROM analyst_case_events WHERE tenant_id = %s "
            "AND case_id = %s AND revision = 1", ("tenant-a", case_id),
        )
        connection.commit()
        reader = principal(capabilities=frozenset({Capability.CASE_READ}))
        with pytest.raises(CaseRejected):
            service.history(principal=reader, tenant_id="tenant-a",
                            case_id=case_id, at=AT)
        with pytest.raises(CaseRejected):
            apply(service, cmd(CaseOperation.ASSIGN, case_id, event_id, 2,
                               assignee=AuthorizedAssignee("tenant-a", "a" * 64)))
        assert counts(connection) == (1, 2)
        # No accidental tenant-wide or global query fallback on a nonexistent case.
        assert service.history(
            principal=principal(tenant="tenant-b",
                                capabilities=frozenset({Capability.CASE_READ})),
            tenant_id="tenant-b", case_id=case_id, at=AT,
        ) == ()


def test_uncertain_commit_reply_retry_from_second_connection_is_idempotent(schema):
    case_id, event_id = uuid4(), uuid4()
    command = cmd(CaseOperation.CREATE, case_id, event_id, 0)
    with connect(schema) as first_connection:
        committed = apply(PostgresCaseTimelineService(first_connection), command)
    # Simulate a lost response AFTER commit; the caller has no acknowledgment.
    with connect(schema) as retry_connection:
        service = PostgresCaseTimelineService(retry_connection)
        assert apply(service, command, at=AT + timedelta(seconds=2)) == committed
        with pytest.raises(CaseConflict):
            apply(service, replace(command, case_id=uuid4()))
        assert counts(retry_connection) == (1, 1)


def test_case_runtime_reader_and_audit_roles_are_separate():
    """Real PG role boundary; does NOT establish bank grants or same-schema RLS."""
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    suffix = uuid4().hex[:12]
    schema_a = "gasha_case_acl_a_" + suffix
    schema_b = "gasha_case_acl_b_" + suffix
    migrator, writer, reader, auditor, outsider = (
        "gasha_cm_" + suffix, "gasha_cw_" + suffix,
        "gasha_cr_" + suffix, "gasha_ca_" + suffix,
        "gasha_co_" + suffix,
    )
    password = "synthetic_case_acl_ci_only"
    roles = (migrator, writer, reader, auditor, outsider)
    schemas = (schema_a, schema_b)

    def table(schema_name, name):
        return sql.SQL("{}.{}").format(sql.Identifier(schema_name), sql.Identifier(name))

    def as_role(role, schema_name):
        connection = psycopg.connect(
            DSN, user=role, password=password, row_factory=dict_row,
        )
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
        connection.commit()
        return connection

    with psycopg.connect(DSN, autocommit=True) as admin:
        made_roles = []
        made_schemas = []
        try:
            for role in roles:
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(password),
                ))
                made_roles.append(role)
                assert admin.execute(
                    "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = %s",
                    (role,),
                ).fetchone() == (False, False)
            for location in schemas:
                admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(
                    sql.Identifier(location), sql.Identifier(migrator),
                ))
                made_schemas.append(location)
                with as_role(migrator, location) as connection:
                    for migration in (
                        "010_security_audit_events.sql", "011_analyst_case_events.sql",
                    ):
                        connection.execute((MIGRATIONS / migration).read_text())
                    connection.commit()

            for role in (writer, reader, auditor):
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema_a), sql.Identifier(role),
                ))
            admin.execute(sql.SQL("GRANT SELECT, INSERT ON TABLE {} TO {}").format(
                table(schema_a, "analyst_case_events"), sql.Identifier(writer),
            ))
            admin.execute(sql.SQL("GRANT INSERT ON TABLE {} TO {}").format(
                table(schema_a, "security_audit_events"), sql.Identifier(writer),
            ))
            admin.execute(sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(
                table(schema_a, "analyst_case_events"), sql.Identifier(reader),
            ))
            admin.execute(sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(
                table(schema_a, "security_audit_events"), sql.Identifier(auditor),
            ))

            case_id, event_id = uuid4(), uuid4()
            with as_role(writer, schema_a) as connection:
                assert connection.execute("SELECT current_user").fetchone()["current_user"] == writer
                assert apply(
                    PostgresCaseTimelineService(connection),
                    cmd(CaseOperation.CREATE, case_id, event_id, 0),
                ).revision == 1
                forbidden = (
                    sql.SQL("SELECT * FROM {}").format(
                        table(schema_a, "security_audit_events")),
                    sql.SQL("UPDATE {} SET actor_ref = actor_ref").format(
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("DELETE FROM {}").format(
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("TRUNCATE {}").format(
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("ALTER TABLE {} ADD COLUMN denied TEXT").format(
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("DROP TABLE {}").format(
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("CREATE TABLE {} (id INT)").format(
                        table(schema_a, "denied_table")),
                    sql.SQL("CREATE INDEX {} ON {} (revision)").format(
                        sql.Identifier("case_denied_index"),
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("SET ROLE {}").format(sql.Identifier(migrator)),
                )
                for statement in forbidden:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(statement)
                    connection.rollback()

            with as_role(reader, schema_a) as connection:
                events = PostgresCaseTimelineService(connection).history(
                    principal=principal(capabilities=frozenset({Capability.CASE_READ})),
                    tenant_id="tenant-a", case_id=case_id, at=AT,
                )
                assert len(events) == 1
                for statement in (
                    sql.SQL("SELECT * FROM {}").format(
                        table(schema_a, "security_audit_events")),
                    sql.SQL("DELETE FROM {}").format(
                        table(schema_a, "analyst_case_events")),
                    sql.SQL("INSERT INTO {} (tenant_id) VALUES ('tenant-a')").format(
                        table(schema_a, "analyst_case_events")),
                ):
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(statement)
                    connection.rollback()

            with as_role(auditor, schema_a) as connection:
                assert connection.execute(sql.SQL("SELECT count(*) AS n FROM {}").format(
                    table(schema_a, "security_audit_events"),
                )).fetchone()["n"] == 1
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(sql.SQL("SELECT * FROM {}").format(
                        table(schema_a, "analyst_case_events"),
                    ))
                connection.rollback()

            with as_role(outsider, schema_a) as connection:
                with pytest.raises(psycopg.Error):
                    connection.execute("SELECT * FROM analyst_case_events")
                connection.rollback()
            with as_role(writer, schema_b) as connection:
                with pytest.raises(psycopg.Error):
                    connection.execute("SELECT * FROM analyst_case_events")
                connection.rollback()
            with as_role(migrator, schema_a) as connection:
                assert connection.execute(sql.SQL("SELECT count(*) AS n FROM {}").format(
                    table(schema_a, "analyst_case_events"),
                )).fetchone()["n"] == 1
                assert connection.execute(sql.SQL("SELECT count(*) AS n FROM {}").format(
                    table(schema_b, "analyst_case_events"),
                )).fetchone()["n"] == 0
            print(
                "Case PostgreSQL role matrix: 5 synthetic non-superuser roles, "
                "2 isolated schemas, 1 atomic case/audit append, "
                "9 writer + 3 reader forbidden operations, auditor read-only, "
                "outsider and wrong-environment reads denied"
            )
        finally:
            for location in reversed(made_schemas):
                admin.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(location),
                ))
            for role in reversed(made_roles):
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
