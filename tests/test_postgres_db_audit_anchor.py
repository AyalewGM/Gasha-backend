"""Opt-in PostgreSQL login-bound audit-anchor negatives (#42/#43).

The anchor is NOT wired to outcome HTTP/atomic writer. It proves only that a
non-owner database login can use a constrained SECURITY DEFINER boundary
without raw audit INSERT, not Bank source/actor truth or terminal auditing.
"""
from __future__ import annotations

import os
import secrets
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db"
AUDIT_MIGRATION = MIGRATIONS / "poc-migrations/015_poc_db_outcome_audit_anchor.sql"


@pytest.fixture
def installed():
    import psycopg
    from psycopg import sql

    schema = "gasha_db_audit_" + uuid4().hex[:14]
    roles = [
        ("gasha_audit_a_" + uuid4().hex[:12], "bank-a", secrets.token_urlsafe(32)),
        ("gasha_audit_b_" + uuid4().hex[:12], "bank-b", secrets.token_urlsafe(32)),
    ]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        try:
            for role, _, password in roles:
                admin.execute(sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOINHERIT NOBYPASSRLS PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(password)))
            try:
                with psycopg.connect(DSN) as owner:
                    owner.execute(
                        sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
                    )
                    owner.commit()
                    owner.execute(
                        "SELECT set_config('gasha.installation_schema', %s, true)",
                        (schema,),
                    )
                    owner.execute(
                        (MIGRATIONS / "migrations/010_security_audit_events.sql")
                        .read_text()
                    )
                    owner.execute(
                        (MIGRATIONS / "poc-migrations/013_poc_atomic_outcomes.sql")
                        .read_text()
                    )
                    owner.commit()
                    for version in ("014_poc_outcomes_login_rls.sql",
                                    "015_poc_db_outcome_audit_anchor.sql"):
                        owner.execute(
                            "SELECT set_config('gasha.installation_schema', %s, true)",
                            (schema,),
                        )
                        owner.execute(
                            (MIGRATIONS / "poc-migrations" / version).read_text()
                        )
                        owner.commit()
                    ids = {}
                    for _, tenant, _ in roles:
                        ids[tenant] = owner.execute(
                            """INSERT INTO poc_atomic_outcomes (
                                tenant_id, event_id, outcome_kind, record_digest,
                                record_json, recorded_at
                            ) VALUES (%s, %s, 'gasha', %s, '{}'::jsonb,
                                      pg_catalog.clock_timestamp())
                            RETURNING id""",
                            (tenant, uuid4(), "sha256:" + "0" * 64),
                        ).fetchone()[0]
                    for role, tenant, _ in roles:
                        owner.execute(
                            "INSERT INTO poc_outcome_runtime_tenants "
                            "(login_role_oid, tenant_id) "
                            "SELECT oid, %s FROM pg_catalog.pg_roles "
                            "WHERE rolname = %s",
                            (tenant, role),
                        )
                    owner.commit()
                for role, _, _ in roles:
                    admin.execute(
                        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                            sql.Identifier(schema), sql.Identifier(role))
                    )
                    admin.execute(
                        sql.SQL("GRANT SELECT ON TABLE {}.poc_atomic_outcomes TO {}")
                        .format(sql.Identifier(schema), sql.Identifier(role))
                    )
                    for signature in (
                        "poc_outcome_bound_tenant()",
                        "poc_append_db_outcome_audit(bigint, text)",
                    ):
                        admin.execute(
                            sql.SQL("GRANT EXECUTE ON FUNCTION {}.{} TO {}").format(
                                sql.Identifier(schema), sql.SQL(signature),
                                sql.Identifier(role))
                        )
                yield schema, roles, ids
            finally:
                for role, _, _ in roles:
                    admin.execute(
                        sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(
                            sql.Identifier(schema), sql.Identifier(role))
                    )
                    admin.execute(
                        sql.SQL("REVOKE ALL ON TABLE {}.poc_atomic_outcomes FROM {}")
                        .format(sql.Identifier(schema), sql.Identifier(role))
                    )
                    for signature in (
                        "poc_outcome_bound_tenant()",
                        "poc_append_db_outcome_audit(bigint, text)",
                    ):
                        admin.execute(
                            sql.SQL("REVOKE ALL ON FUNCTION {}.{} FROM {}").format(
                                sql.Identifier(schema), sql.SQL(signature),
                                sql.Identifier(role))
                        )
                    admin.execute(
                        sql.SQL("DROP ROLE {}").format(sql.Identifier(role))
                    )
        finally:
            admin.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def test_login_bound_audit_anchor_denies_raw_forgery_and_cross_tenant(installed):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    schema, roles, ids = installed
    for role, tenant, password in roles:
        with psycopg.connect(
            make_conninfo(DSN, user=role, password=password),
            row_factory=dict_row,
        ) as runtime:
            authenticated = runtime.execute(
                "SELECT session_user AS login, current_user AS effective"
            ).fetchone()
            assert authenticated == {"login": role, "effective": role}
            # Raw INSERT is forbidden, even with a syntactically valid event.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                runtime.execute(
                    sql.SQL("INSERT INTO {}.security_audit_events "
                            "(occurred_at,action,result,actor_ref,tenant_ref,reason,"
                            "attempt_ref,event_ref,context_ref) "
                            "VALUES (now(),'outcome.submit','succeeded','forged',"
                            "'other','forged','bad','bad','')").format(
                                sql.Identifier(schema))
                )
            runtime.rollback()
            invoke = sql.SQL(
                "SELECT {}.poc_append_db_outcome_audit(%s, %s) AS audit_id"
            ).format(sql.Identifier(schema))
            other = "bank-b" if tenant == "bank-a" else "bank-a"
            for row, attempt in (
                (ids[other], uuid4().hex),
                (99999999, uuid4().hex),
                (ids[tenant], "not-a-valid-attempt"),
            ):
                with pytest.raises(psycopg.errors.RaiseException):
                    runtime.execute(invoke, (row, attempt))
                runtime.rollback()
            attempt = uuid4().hex
            anchor_id = runtime.execute(
                invoke, (ids[tenant], attempt)
            ).fetchone()["audit_id"]
            runtime.commit()
            with psycopg.connect(DSN, row_factory=dict_row) as owner:
                audit = owner.execute(
                    sql.SQL(
                        "SELECT * FROM {}.security_audit_events WHERE id=%s"
                    ).format(sql.Identifier(schema)), (anchor_id,),
                ).fetchone()
                assert audit["action"] == "outcome.audit_anchor"
                assert audit["result"] == "succeeded"
                assert audit["reason"] == "persisted_outcome_exists"
                assert audit["attempt_ref"] == attempt
                assert audit["tenant_ref"] == sha256(tenant.encode()).hexdigest()
                assert audit["actor_ref"].startswith("db-login-oid-sha256:")
                assert len(audit["actor_ref"]) == len("db-login-oid-sha256:") + 64
                event = owner.execute(
                    sql.SQL("SELECT event_id FROM {}.poc_atomic_outcomes "
                            "WHERE id = %s").format(sql.Identifier(schema)),
                    (ids[tenant],),
                ).fetchone()["event_id"]
                assert audit["event_ref"] == sha256(
                    f"{tenant}\0{event}".encode()
                ).hexdigest()
                assert tenant not in str(audit)
                assert role not in str(audit)


def test_anchor_migration_is_transaction_scoped_and_idempotent(installed):
    import psycopg
    from psycopg import sql

    schema, _, _ = installed
    with psycopg.connect(DSN) as owner:
        owner.execute(
            sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
        )
        owner.commit()
        with pytest.raises(psycopg.errors.RaiseException):
            owner.execute(AUDIT_MIGRATION.read_text())
        owner.rollback()
        owner.execute(
            "SELECT set_config('gasha.installation_schema', %s, true)",
            (schema,),
        )
        owner.execute(AUDIT_MIGRATION.read_text())
        owner.commit()
        count = owner.execute(
            "SELECT COUNT(*) FROM security_audit_events"
        ).fetchone()[0]
        assert count == 0
