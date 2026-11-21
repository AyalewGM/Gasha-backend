"""Issue #42 actual PostgreSQL audit persistence (synthetic records only)."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

import pytest

from gasha.security.access import SecurityAuditEvent, tenant_audit_ref
from gasha.security.postgres_audit import PostgresSecurityAuditSink

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATION = (
    Path(__file__).resolve().parent.parent
    / "db/migrations/010_security_audit_events.sql"
)


@pytest.fixture
def pg():
    import psycopg
    connection = psycopg.connect(DSN)
    connection.execute(MIGRATION.read_text())
    connection.commit()
    connection.execute("TRUNCATE security_audit_events RESTART IDENTITY")
    connection.commit()
    yield connection
    connection.execute("TRUNCATE security_audit_events RESTART IDENTITY")
    connection.commit()
    connection.close()


def test_real_postgres_persists_redacted_append_history(pg) -> None:
    base = SecurityAuditEvent(
        action="decision.submit",
        result="denied",
        actor_ref="a" * 64,
        tenant_ref=tenant_audit_ref("synthetic-tenant"),
        reason="authorization_denied",
        at=datetime(2026, 10, 31, 16, 0, tzinfo=UTC),
        attempt_ref="b" * 32,
        event_ref="c" * 64,
        context_ref="",
    )
    sink = PostgresSecurityAuditSink(pg)
    sink.append(base)
    sink.append(replace(base, result="failed", reason="context_unavailable"))
    rows = pg.execute(
        """SELECT action, result, actor_ref, tenant_ref, reason, attempt_ref,
                  event_ref, context_ref, occurred_at
           FROM security_audit_events ORDER BY id"""
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][:8] == (
        base.action, base.result, base.actor_ref, base.tenant_ref,
        base.reason, base.attempt_ref, base.event_ref, "",
    )
    assert rows[0][8] == base.at
    assert rows[1][1] == "failed"
    assert rows[1][4] == "context_unavailable"
    assert "synthetic-tenant" not in str(rows)


def test_real_postgres_invalid_record_does_not_append(pg) -> None:
    event = SecurityAuditEvent(
        action="authenticate", result="denied", actor_ref="anonymous",
        tenant_ref=tenant_audit_ref("synthetic-tenant"), reason="bad\nsecret",
        at=datetime(2026, 10, 31, tzinfo=UTC), attempt_ref="f" * 32,
    )
    with pytest.raises(ValueError):
        PostgresSecurityAuditSink(pg).append(event)
    assert pg.execute("SELECT count(*) FROM security_audit_events").fetchone()[0] == 0


def test_real_postgres_isolated_audit_concurrent_tenants_commit_independently(pg) -> None:
    """Concurrent synthetic callers never share one mutable PG transaction."""
    import psycopg

    owned_connections = []
    lock = Lock()

    def connections():
        connection = psycopg.connect(DSN)
        with lock:
            owned_connections.append(connection)
        return connection

    sink = PostgresSecurityAuditSink(connections=connections)
    assert sink.per_append_connection is True
    base = SecurityAuditEvent(
        action="case.read", result="authorized", actor_ref="a" * 64,
        tenant_ref=tenant_audit_ref("tenant-a"), reason="authorized",
        at=datetime(2026, 11, 21, 12, 0, tzinfo=UTC),
        attempt_ref="0" * 32,
    )
    attempts = tuple(
        replace(
            base,
            tenant_ref=tenant_audit_ref(f"tenant-{i % 2}"),
            actor_ref=f"{i + 1:064x}",
            attempt_ref=f"{i + 1:032x}",
        )
        for i in range(24)
    )
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(sink.append, attempts))

    rows = pg.execute(
        "SELECT tenant_ref, actor_ref, attempt_ref, action, result "
        "FROM security_audit_events"
    ).fetchall()
    assert len(rows) == len(attempts)
    assert set(rows) == {
        (event.tenant_ref, event.actor_ref, event.attempt_ref, "case.read", "authorized")
        for event in attempts
    }
    assert len(owned_connections) == len(attempts)
    assert all(connection.closed for connection in owned_connections)
    assert "tenant-a" not in str(rows) and "tenant-b" not in str(rows)


def test_real_postgres_isolated_audit_rollback_closes_only_failed_connection(pg) -> None:
    """Audit transaction refusal cannot poison the next successful append."""
    import psycopg

    opened = []

    def read_only_connection():
        connection = psycopg.connect(DSN)
        connection.execute("SET TRANSACTION READ ONLY")
        opened.append(connection)
        return connection

    event = SecurityAuditEvent(
        action="case.read", result="denied", actor_ref="a" * 64,
        tenant_ref=tenant_audit_ref("tenant-a"), reason="authorization_denied",
        at=datetime(2026, 11, 21, 12, 0, tzinfo=UTC),
        attempt_ref="f" * 32,
    )
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        PostgresSecurityAuditSink(connections=read_only_connection).append(event)
    assert len(opened) == 1 and opened[0].closed
    assert pg.execute("SELECT count(*) FROM security_audit_events").fetchone()[0] == 0

    success_connections = []

    def working_connection():
        connection = psycopg.connect(DSN)
        success_connections.append(connection)
        return connection

    sink = PostgresSecurityAuditSink(connections=working_connection)
    sink.append(replace(event, result="authorized", reason="authorized"))
    assert len(success_connections) == 1 and success_connections[0].closed
    assert pg.execute("SELECT count(*) FROM security_audit_events").fetchone()[0] == 1

    rejected = replace(event, reason="invalid\\nreason")
    with pytest.raises(ValueError):
        sink.append(rejected)
    assert len(success_connections) == 1  # validation occurs before acquiring a DB lease


def test_audit_connection_modes_require_exactly_one_factory_or_legacy_connection() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        PostgresSecurityAuditSink()
