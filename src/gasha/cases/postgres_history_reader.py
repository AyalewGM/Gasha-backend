"""Explicit #45 tenant-scoped PostgreSQL case-history reader for protected HTTP.

This opt-in adapter composes the existing append-only case timeline store with
the protected API's TrustedCaseHistoryReader port. It does not install itself on
the FastAPI app or obtain credentials, bank evidence, identity, or authority.
The deployer must inject a fresh, least-privilege connection per request and
a separately approved identity verifier and durable security audit sink.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime, timezone
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import CaseEvent, CaseRejected
from gasha.postgres import Connection
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    TrustedPrincipal,
    authorize,
)


class ExplicitPostgresCaseHistoryReader:
    """Request-scoped read bridge; never installs a Bank/session/queue source.

    Connections must enforce their own PostgreSQL role, schema, and tenant
    isolation. Neither a URL tenant nor a JSON event is trusted as identity.
    The underlying timeline service verifies stored row/JSON agreement and
    the canonical immutable case lifecycle before returning any history.
    """

    def __init__(
        self, *, connections: Callable[[], AbstractContextManager[Connection]],
    ) -> None:
        self._connections = connections

    def history(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        case_id: UUID, at: datetime,
    ) -> tuple[CaseEvent, ...]:
        if type(principal) is not TrustedPrincipal:
            raise AuthorizationRejected("trusted principal required")
        if (
            type(tenant_id) is not str
            or not tenant_id
            or tenant_id != tenant_id.strip()
            or type(case_id) is not UUID
            or type(at) is not datetime
            or type(at.tzinfo) not in (timezone, ZoneInfo)
            or at.utcoffset() is None
        ):
            raise CaseRejected("typed tenant-scoped history selector required")
        # Frozen principal fields can be corrupted by an in-process adapter.
        # Check their concrete clocks before reconstructing/using them.
        if (
            type(principal.expires_at) is not datetime
            or type(principal.expires_at.tzinfo) not in (timezone, ZoneInfo)
        ):
            raise AuthorizationRejected("invalid principal expiry")
        try:
            accepted = replace(principal)
        except (ValueError, TypeError, AttributeError) as exc:
            raise AuthorizationRejected("invalid principal") from exc
        if accepted.expires_at.astimezone(UTC) <= at.astimezone(UTC):
            raise AuthorizationRejected("expired principal")
        authorize(accepted, tenant_id=tenant_id, capability=Capability.CASE_READ)

        # Open only after all authorization checks, use an exclusive
        # transaction/connection for this read, and always release it.
        with self._connections() as connection:
            return PostgresCaseTimelineService(connection).history(
                principal=accepted, tenant_id=tenant_id,
                case_id=case_id, at=at,
            )
