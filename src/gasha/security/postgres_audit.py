"""Opt-in PostgreSQL implementation of the protected API security audit port.

The adapter writes only redacted references/codes. It is deliberately not
composed into the API by default: bank identity, scoped DB roles, retention,
connection lifecycle and independent installation approval remain external.
"""
from __future__ import annotations

import re
from datetime import datetime

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


class PostgresSecurityAuditSink:
    """Single-connection append-only API adapter; never a bank-ready default.

    A bank installation must supply a dedicated, least-privilege connection
    and manage its lifecycle/concurrency separately. No update/delete API is
    exposed. PostgreSQL durability follows successful transaction commit.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def append(self, event: SecurityAuditEvent) -> None:
        _validate_redacted_event(event)
        try:
            with self._connection.cursor() as cursor:
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
            self._connection.commit()
        except Exception:
            # The protected API converts append errors to a fail-closed 503.
            # Do not suppress commit/insert failure or emit event identifiers.
            self._connection.rollback()
            raise
