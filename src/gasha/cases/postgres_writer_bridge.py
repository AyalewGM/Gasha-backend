"""Opt-in #45 protected-HTTP to transactional PostgreSQL case-writer bridge.

This module does not install itself on the protected app. The source directory,
assignee directory, DB connection factory and principal verifier must come from
separately reviewed, server-owned deployment composition. A typed directory
response is not proof of Bank provenance or approval.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime
from re import fullmatch
from typing import Protocol
from uuid import UUID

from gasha.api.main import CaseTransitionInput
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import (
    AuthorizedAssignee,
    CaseCommand,
    CaseEvent,
    CaseOperation,
    CaseRejected,
    CaseSourceUnavailable,
    VerifiedEvaluation,
)
from gasha.postgres import Connection
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    TrustedPrincipal,
    authorize,
)


class TrustedEvaluationDirectory(Protocol):
    """Tenant-scoped immutable evaluation lookup supplied by trusted server code."""

    def resolve(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        event_id: UUID, at: datetime,
    ) -> VerifiedEvaluation: ...


class TrustedAssigneeDirectory(Protocol):
    """Server-side check of current tenant assignment eligibility."""

    def resolve(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        selector: UUID, at: datetime,
    ) -> AuthorizedAssignee: ...


_CAPABILITIES: dict[CaseOperation, Capability] = {
    CaseOperation.CREATE: Capability.CASE_CREATE,
    CaseOperation.TRIAGE: Capability.CASE_TRIAGE,
    CaseOperation.ASSIGN: Capability.CASE_ASSIGN,
    CaseOperation.DISPOSE: Capability.CASE_DISPOSITION,
    CaseOperation.CORRECT: Capability.CASE_CORRECT,
    CaseOperation.RECONCILE: Capability.CASE_FEEDBACK,
}


class _ScopedEvaluationLookup:
    """Carry the verified principal into lookup *inside* the PostgreSQL txn."""

    def __init__(
        self, directory: TrustedEvaluationDirectory, *, principal: TrustedPrincipal,
        tenant_id: str, at: datetime,
    ) -> None:
        self._directory = directory
        self._principal = principal
        self._tenant_id = tenant_id
        self._at = at

    def resolve(self, tenant_id: str, event_id: UUID) -> VerifiedEvaluation:
        if tenant_id != self._tenant_id or type(event_id) is not UUID:
            raise CaseSourceUnavailable("invalid tenant-scoped evaluation selector")
        # An installed callback must never receive the principal later used
        # by the case kernel. A callback can defeat frozen dataclasses via
        # object.__setattr__, so check its detached argument before SQL insert.
        delegated = replace(self._principal)
        result = self._directory.resolve(
            principal=delegated, tenant_id=tenant_id,
            event_id=event_id, at=self._at,
        )
        if delegated != self._principal:
            raise CaseSourceUnavailable("evaluation directory changed principal")
        if (
            type(result) is not VerifiedEvaluation
            or type(result.tenant_id) is not str
            or result.tenant_id != tenant_id
            or type(result.event_id) is not UUID
            or result.event_id != event_id
            or type(result.context_ref) is not str
            or fullmatch(r"[0-9a-f]{64}", result.context_ref) is None
        ):
            raise CaseSourceUnavailable("tenant-bound evaluation unavailable")
        return replace(result)


class ExplicitPostgresCaseTransitionWriter:
    """Adapts the existing atomic case/audit store to the protected HTTP port.

    Each invocation gets its own connection/transaction. Never use a shared
    psycopg connection across concurrent HTTP requests; the context manager
    must close/release it. No default constructor or environment flag activates
    this writer, and it cannot attest Bank-origin evaluation/assignee records.
    """

    def __init__(
        self, *,
        connections: Callable[[], AbstractContextManager[Connection]],
        evaluations: TrustedEvaluationDirectory,
        assignees: TrustedAssigneeDirectory | None = None,
    ) -> None:
        self._connections = connections
        self._evaluations = evaluations
        self._assignees = assignees

    def apply(
        self, *, principal: TrustedPrincipal, tenant_id: str, case_id: UUID,
        operation: CaseOperation, proposal: CaseTransitionInput, at: datetime,
    ) -> CaseEvent:
        if (
            type(principal) is not TrustedPrincipal
            or type(operation) is not CaseOperation
            or type(case_id) is not UUID
            or type(proposal) is not CaseTransitionInput
            or type(at) is not datetime
            or at.utcoffset() is None
        ):
            raise CaseRejected("typed protected case transition required")
        # Defend against a stale or damaged principal from a misconfigured
        # in-process verifier, and re-check both expiry and least privilege.
        try:
            # Capture an independent accepted identity before any external
            # directory callback. Only immutable scalar/frozenset/datetime
            # fields are present in this validated TrustedPrincipal.
            accepted_principal = replace(principal)
        except (TypeError, AttributeError, ValueError) as exc:
            raise AuthorizationRejected("invalid principal") from exc
        if accepted_principal.expires_at.astimezone(UTC) <= at.astimezone(UTC):
            raise AuthorizationRejected("expired principal")
        authorize(
            accepted_principal, tenant_id=tenant_id,
            capability=_CAPABILITIES[operation],
        )

        # Keep one detached snapshot: a mutable request object or resolver must
        # not change the accepted command between authorization and SQL commit.
        try:
            snapshot = CaseTransitionInput.model_validate(proposal.model_dump(mode="python"))
        except Exception as exc:
            raise CaseRejected("invalid case transition proposal") from exc
        assignee: AuthorizedAssignee | None = None
        if operation is CaseOperation.ASSIGN:
            if snapshot.assignee_selector is None or self._assignees is None:
                raise CaseRejected("server assignee directory required")
            # Never hand a directory the authoritative identity or the
            # kernel's principal. Detect even an otherwise valid resolver
            # response if the callback mutated its own supplied identity.
            delegated = replace(accepted_principal)
            resolved = self._assignees.resolve(
                principal=delegated, tenant_id=tenant_id,
                selector=snapshot.assignee_selector, at=at,
            )
            if delegated != accepted_principal:
                raise CaseRejected("assignee directory changed principal")
            if (
                type(resolved) is not AuthorizedAssignee
                or type(resolved.tenant_id) is not str
                or resolved.tenant_id != tenant_id
                or type(resolved.actor_ref) is not str
                or fullmatch(r"[0-9a-f]{64}", resolved.actor_ref) is None
            ):
                raise AuthorizationRejected("assignee is not tenant-authorized")
            assignee = replace(resolved)
        elif snapshot.assignee_selector is not None:
            raise CaseRejected("assignee selector allowed only on assignment")
        command = CaseCommand(
            tenant_id=tenant_id, case_id=case_id,
            source_event_id=snapshot.source_event_id,
            operation=operation, expected_revision=snapshot.expected_revision,
            idempotency_key=snapshot.idempotency_key,
            reason_code=snapshot.reason_code,
            disposition=snapshot.disposition, assignee=assignee,
        )
        # Reauthorize at the transactional decision boundary. Callback-
        # specific copies cannot rebind the actor used for event and audit.
        if accepted_principal.expires_at.astimezone(UTC) <= at.astimezone(UTC):
            raise AuthorizationRejected("expired principal")
        authorize(
            accepted_principal, tenant_id=tenant_id,
            capability=_CAPABILITIES[operation],
        )
        kernel_principal = replace(accepted_principal)
        source = _ScopedEvaluationLookup(
            self._evaluations, principal=replace(accepted_principal),
            tenant_id=tenant_id, at=at,
        )
        with self._connections() as connection:
            return PostgresCaseTimelineService(connection).apply(
                command, principal=kernel_principal, source=source, at=at,
            )
