"""Issue #42 actual PostgreSQL audit persistence (synthetic records only)."""
from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

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
