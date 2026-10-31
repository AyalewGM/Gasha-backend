"""Real PostgreSQL privilege boundary for the inert #42 security audit sink.

This test uses ephemeral *synthetic* roles/schemas in CI; it does not create
bank accounts, deploy the sink, or attest any bank-managed database grants.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from gasha.security.access import SecurityAuditEvent, tenant_audit_ref
from gasha.security.postgres_audit import PostgresSecurityAuditSink

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATION = Path(__file__).resolve().parent.parent / "db/migrations/010_security_audit_events.sql"
# No external or bank credentials: test-only ephemeral PostgreSQL logins.
SYNTHETIC_PASSWORD = "synthetic_audit_acl_ci_only"


def test_distinct_migrator_insert_only_runtime_and_cross_environment_denial() -> None:
    import psycopg
    from psycopg import sql

    suffix = uuid4().hex[:12]
    migrator = f"gasha_mig_{suffix}"
    runtime = f"gasha_run_{suffix}"
    outsider = f"gasha_bad_{suffix}"
    primary_schema = f"gasha_audit_a_{suffix}"
    foreign_schema = f"gasha_audit_b_{suffix}"
    roles = (migrator, runtime, outsider)
    schemas = (primary_schema, foreign_schema)

    def table(schema_name: str) -> sql.Composed:
        return sql.SQL("{}.{}").format(
            sql.Identifier(schema_name), sql.Identifier("security_audit_events")
        )

    def connect_as(role: str, schema_name: str) -> psycopg.Connection:
        connection = psycopg.connect(DSN, user=role, password=SYNTHETIC_PASSWORD)
        connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
        connection.commit()
        return connection

    # The CI service's administrative identity provisions role separation;
    # application calls below use separate non-superuser LOGIN connections.
    with psycopg.connect(DSN, autocommit=True) as admin:
        created_roles: list[str] = []
        created_schemas: list[str] = []
        try:
            for role in roles:
                admin.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(SYNTHETIC_PASSWORD)
                    )
                )
                created_roles.append(role)
                assert admin.execute(
                    "SELECT rolsuper FROM pg_roles WHERE rolname = %s", (role,)
                ).fetchone() == (False,)

            for schema_name in schemas:
                admin.execute(
                    sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(
                        sql.Identifier(schema_name), sql.Identifier(migrator)
                    )
                )
                created_schemas.append(schema_name)

            # The non-superuser migrator, not the runtime identity, owns the
            # schema and applies migration 010 in each isolated installation.
            with connect_as(migrator, primary_schema) as migration_connection:
                for schema_name in schemas:
                    migration_connection.execute(
                        sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name))
                    )
                    migration_connection.execute(MIGRATION.read_text())
                    migration_connection.commit()

            for schema_name in schemas:
                assert admin.execute(
                    "SELECT tableowner FROM pg_tables WHERE schemaname = %s "
                    "AND tablename = 'security_audit_events'",
                    (schema_name,),
                ).fetchone() == (migrator,)

            # Only the explicitly provisioned installation may be written.
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(primary_schema), sql.Identifier(runtime)
                )
            )
            admin.execute(
                sql.SQL("GRANT INSERT ON TABLE {} TO {}").format(
                    table(primary_schema), sql.Identifier(runtime)
                )
            )
            # Make the outsider's schema visible: it must still lack INSERT.
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(primary_schema), sql.Identifier(outsider)
                )
            )

            event = SecurityAuditEvent(
                action="authenticate",
                result="denied",
                actor_ref="anonymous",
                tenant_ref=tenant_audit_ref("synthetic-tenant"),
                reason="invalid_credential",
                at=datetime(2026, 10, 31, 16, 0, tzinfo=UTC),
                attempt_ref="a" * 32,
                event_ref="b" * 64,
                context_ref="",
            )
            with connect_as(runtime, primary_schema) as runtime_connection:
                assert runtime_connection.execute("SELECT current_user").fetchone() == (runtime,)
                PostgresSecurityAuditSink(runtime_connection).append(event)

                # These eight independent SQL rights must all be denied even
                # after a successful append. Roll back after each denial.
                forbidden_sql = (
                    sql.SQL("SELECT * FROM {} LIMIT 1").format(table(primary_schema)),
                    sql.SQL("UPDATE {} SET result = 'allowed'").format(table(primary_schema)),
                    sql.SQL("DELETE FROM {}").format(table(primary_schema)),
                    sql.SQL("TRUNCATE {}").format(table(primary_schema)),
                    sql.SQL("ALTER TABLE {} ADD COLUMN forbidden TEXT").format(
                        table(primary_schema)
                    ),
                    sql.SQL("DROP TABLE {}").format(table(primary_schema)),
                    sql.SQL("CREATE TABLE {} (id INT)").format(
                        sql.SQL("{}.{}").format(
                            sql.Identifier(primary_schema), sql.Identifier("migration_forbidden")
                        )
                    ),
                    sql.SQL("CREATE INDEX {} ON {} (occurred_at)").format(
                        sql.Identifier("audit_forbidden_idx"), table(primary_schema)
                    ),
                )
                for denied in forbidden_sql:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        runtime_connection.execute(denied)
                    runtime_connection.rollback()

                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    runtime_connection.execute(
                        sql.SQL("SET ROLE {}").format(sql.Identifier(migrator))
                    )
                runtime_connection.rollback()

            with (
                connect_as(outsider, primary_schema) as outsider_connection,
                pytest.raises(psycopg.errors.InsufficientPrivilege),
            ):
                PostgresSecurityAuditSink(outsider_connection).append(event)

            # A valid role pointed at a second installed environment has no
            # schema/table grants there; it cannot silently write elsewhere.
            with (
                connect_as(runtime, foreign_schema) as wrong_connection,
                pytest.raises(psycopg.Error),
            ):
                PostgresSecurityAuditSink(wrong_connection).append(event)

            # A missing/unprovisioned namespace must fail too.
            with (
                connect_as(runtime, f"gasha_absent_{suffix}") as missing_connection,
                pytest.raises(psycopg.Error),
            ):
                PostgresSecurityAuditSink(missing_connection).append(event)

            with connect_as(migrator, primary_schema) as verify_connection:
                assert verify_connection.execute(
                    sql.SQL("SELECT action, result, actor_ref FROM {}").format(
                        table(primary_schema)
                    )
                ).fetchall() == [("authenticate", "denied", "anonymous")]
                assert verify_connection.execute(
                    sql.SQL("SELECT count(*) FROM {}").format(table(foreign_schema))
                ).fetchone() == (0,)

            print(
                "Security audit DB role matrix: migrator-created 2 isolated schemas; "
                "runtime INSERT 1 permitted; 8 forbidden table/DDL operations denied; "
                "SET ROLE escalation denied; outsider/wrong/missing environment denied; "
                "1 persisted row in authorized environment, 0 in foreign environment"
            )
        finally:
            # Connections have exited before removing ephemeral CI-only roles.
            for schema_name in reversed(created_schemas):
                admin.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name))
                )
            for role in reversed(created_roles):
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
