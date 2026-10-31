"""Isolated #42 audit-port regressions: no database is required."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Self

import pytest

from gasha.security.access import SecurityAuditEvent, SecurityAuditSink, tenant_audit_ref
from gasha.security.postgres_audit import PostgresSecurityAuditSink

EVENT = SecurityAuditEvent(
    action="authenticate",
    result="denied",
    actor_ref="anonymous",
    tenant_ref=tenant_audit_ref("tenant-a"),
    reason="invalid_credential",
    at=datetime(2026, 10, 31, tzinfo=UTC),
    attempt_ref="a" * 32,
    event_ref="b" * 64,
    context_ref="c" * 64,
)


class CursorSpy:
    def __init__(self, connection: ConnectionSpy) -> None:
        self.connection = connection

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        self.connection.executed.append((query, params))
        if self.connection.fail_execute:
            raise RuntimeError("synthetic database insert failure")


class ConnectionSpy:
    def __init__(self, *, fail_execute: bool = False, fail_commit: bool = False) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.fail_execute = fail_execute
        self.fail_commit = fail_commit
        self.commits = 0
        self.rollbacks = 0

    def cursor(self) -> CursorSpy:
        return CursorSpy(self)

    def commit(self) -> None:
        self.commits += 1
        if self.fail_commit:
            raise RuntimeError("synthetic commit failure")

    def rollback(self) -> None:
        self.rollbacks += 1


def test_security_audit_port_is_append_only_and_parameterized() -> None:
    connection = ConnectionSpy()
    sink: SecurityAuditSink = PostgresSecurityAuditSink(connection)
    sink.append(EVENT)
    assert connection.commits == 1 and connection.rollbacks == 0
    assert len(connection.executed) == 1
    query, params = connection.executed[0]
    assert query.lstrip().startswith("INSERT INTO security_audit_events")
    assert query.count("%s") == 9
    assert params[3] == "anonymous"
    assert params[4] == tenant_audit_ref("tenant-a")
    assert "tenant-a" not in query and "tenant-a" not in repr(params)
    assert "invalid_credential" not in query


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor_ref", "raw-subject"),
        ("tenant_ref", "tenant-a"),
        ("action", "authenticate\nsecret"),
        ("result", "ok\r"),
        ("reason", "token@example.com"),
        ("attempt_ref", "from-client"),
        ("event_ref", "raw-event-id"),
        ("context_ref", "not-a-hash"),
        ("at", datetime(2026, 10, 31)),
    ],
)
def test_invalid_or_nonredacted_audit_is_rejected_before_sql(field: str, value: object) -> None:
    connection = ConnectionSpy()
    with pytest.raises(ValueError):
        PostgresSecurityAuditSink(connection).append(replace(EVENT, **{field: value}))
    assert connection.executed == []
    assert connection.commits == 0


@pytest.mark.parametrize(("fail_execute", "fail_commit"), [(True, False), (False, True)])
def test_database_or_commit_failure_propagates_and_rolls_back(
    fail_execute: bool, fail_commit: bool
) -> None:
    connection = ConnectionSpy(fail_execute=fail_execute, fail_commit=fail_commit)
    with pytest.raises(RuntimeError):
        PostgresSecurityAuditSink(connection).append(EVENT)
    assert connection.rollbacks == 1


def test_verified_principal_reference_and_optional_fields_are_accepted() -> None:
    connection = ConnectionSpy()
    event = replace(EVENT, actor_ref="d" * 64, event_ref="", context_ref="")
    PostgresSecurityAuditSink(connection).append(event)
    assert connection.commits == 1
    assert connection.executed[0][1][3] == "d" * 64
