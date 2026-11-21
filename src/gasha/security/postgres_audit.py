"""Opt-in PostgreSQL implementation of the protected API security audit port.

The adapter writes only redacted references/codes. It is deliberately not
composed into the API by default: bank identity, scoped DB roles, retention,
connection lifecycle and independent installation approval remain external.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from gasha.postgres import Connection
from gasha.security.access import SecurityAuditEvent

_CODE = re.compile(r"[a-z][a-z0-9._-]{0,95}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"[0-9a-f]{32}\Z")


def _validate_redacted_event(event: SecurityAuditEvent) -> None:
    """Reject malformed/raw identifiers before writing an audit record."""
    if not isinstance(event, SecurityAuditEvent):
        raise TypeError("typed security audit event required")
    if not isinstance(event.at, datetime) or event.at.utcoffset() is None:
        raise ValueError("timezone-aware security audit time required")
    if any(
        not isinstance(value, str) or _CODE.fullmatch(value) is None
        for value in (event.action, event.result, event.reason)
    ):
        raise ValueError("security audit action/result/reason must be codes")
    if not isinstance(event.actor_ref, str) or (
        event.actor_ref != "anonymous" and _SHA256.fullmatch(event.actor_ref) is None
    ):
        raise ValueError("redacted audit actor reference required")
    if not isinstance(event.tenant_ref, str) or _SHA256.fullmatch(event.tenant_ref) is None:
        raise ValueError("redacted tenant reference required")
    if not isinstance(event.attempt_ref, str) or _ATTEMPT.fullmatch(event.attempt_ref) is None:
        raise ValueError("server-generated attempt reference required")
    if any(
        not isinstance(value, str) or (
            value != "" and _SHA256.fullmatch(value) is None
        )
        for value in (event.event_ref, event.context_ref)
    ):
        raise ValueError("redacted event/context references required")


class ClosableAuditConnection(Connection, Protocol):
    """Connection owned by one append; always closed when the append terminates."""

    def close(self) -> None: ...


class PostgresSecurityAuditSink:
    """Append-only redacted audit with a legacy or an isolated connection mode.

    A shared connection remains supported for historical/internal callers, but
    MUST NOT back the protected case-feature HTTP route. For that route, an
    explicitly installed factory supplies a fresh, owned connection for EACH
    audit event. The sink commits or rolls back that event, then always closes
    its connection before the API may disclose evidence.

    The factory is a trusted installation dependency, never supplied by HTTP.
    This boundary does not certify Bank database privileges or connection pools.
    """

    def __init__(
        self,
        connection: Connection | None = None,
        *,
        connections: Callable[[], ClosableAuditConnection] | None = None,
    ) -> None:
        if (connection is None) == (connections is None):
            raise ValueError("exactly one audit connection mode required")
        self._connection = connection
        self._connections = connections

    @property
    def per_append_connection(self) -> bool:
        """Expose the fail-closed feature-read installation prerequisite."""
        return self._connections is not None

    def append(self, event: SecurityAuditEvent) -> None:
        _validate_redacted_event(event)
        # Each call owns its connection in factory mode; no mutable PG
        # transaction/rollback may be shared between concurrent requests.
        owned = self._connections() if self._connections is not None else None
        connection = owned if owned is not None else self._connection
        if connection is None:
            raise RuntimeError("security audit connection unavailable")
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO security_audit_events (
                        occurred_at, action, result, actor_ref, tenant_ref,
                        reason, attempt_ref, event_ref, context_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event.at,
                        event.action,
                        event.result,
                        event.actor_ref,
                        event.tenant_ref,
                        event.reason,
                        event.attempt_ref,
                        event.event_ref,
                        event.context_ref,
                    ),
                )
            connection.commit()
        except Exception:
            # A failure must not lead to a successful HTTP evidence response.
            # Roll back this call's transaction, never another request's.
            connection.rollback()
            raise
        finally:
            if owned is not None:
                owned.close()
