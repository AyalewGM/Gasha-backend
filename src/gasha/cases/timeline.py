"""Inert #45 analyst-case transition kernel; persistence/API wiring is separately gated.

This service accepts only an authenticated principal and a *server-owned* lookup
port. A value returned by the port is not, by itself, bank provenance. An
installed adapter must resolve it from immutable tenant-scoped evaluation data.
No bank action, rule update, database write or outbound effect occurs here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from json import dumps
from re import fullmatch
from typing import Protocol
from uuid import UUID

from gasha.security.access import Capability, TrustedPrincipal, authorize


class CaseOperation(StrEnum):
    CREATE = "create"
    TRIAGE = "triage"
    ASSIGN = "assign"
    DISPOSE = "dispose"
    CORRECT = "correct"
    RECONCILE = "reconcile"


class CaseReason(StrEnum):
    """Finite non-PII reason vocabulary; no free-form analyst text in events."""

    SOURCE_EVALUATION = "source_evaluation"
    ANALYST_TRIAGE = "analyst_triage"
    INVESTIGATION_ASSIGNED = "investigation_assigned"
    FRAUD_EVIDENCE = "fraud_evidence"
    LEGITIMATE_EVIDENCE = "legitimate_evidence"
    NEEDS_REVIEW = "needs_review"
    CORRECTED_FINDING = "corrected_finding"
    FEEDBACK_RECONCILED = "feedback_reconciled"


class CaseDisposition(StrEnum):
    FRAUD = "confirmed_fraud"
    LEGITIMATE = "confirmed_legitimate"
    UNRESOLVED = "unresolved"


class BankExecution(StrEnum):
    """A recommendation cannot establish bank intervention or funds saved."""

    UNKNOWN = "unknown"


class CaseRejected(ValueError):
    """Malformed command, missing trusted source or invalid transition."""


class CaseConflict(CaseRejected):
    """Optimistic-revision or idempotency-key conflict; no write permitted."""


class CaseSourceUnavailable(CaseRejected):
    """Cannot establish tenant/event identity from the installed source lookup."""


@dataclass(frozen=True, slots=True)
class VerifiedEvaluation:
    tenant_id: str
    event_id: UUID
    context_ref: str


class EvaluationLookup(Protocol):
    """Installed adapter MUST look up a durable, trusted tenant/event pair."""

    def resolve(self, tenant_id: str, event_id: UUID) -> VerifiedEvaluation: ...


@dataclass(frozen=True, slots=True)
class AuthorizedAssignee:
    """Server-resolved assignee, not proof from a caller-supplied actor ID."""

    tenant_id: str
    actor_ref: str


@dataclass(frozen=True, slots=True)
class CaseCommand:
    tenant_id: str
    case_id: UUID
    source_event_id: UUID
    operation: CaseOperation
    expected_revision: int
    idempotency_key: str
    reason_code: CaseReason
    disposition: CaseDisposition | None = None
    assignee: AuthorizedAssignee | None = None


@dataclass(frozen=True, slots=True)
class CaseEvent:
    tenant_id: str
    case_id: UUID
    source_event_id: UUID
    source_context_ref: str
    revision: int
    previous_revision: int | None
    operation: CaseOperation
    actor_ref: str
    recorded_at: datetime
    reason_code: CaseReason
    disposition: CaseDisposition | None
    assignee_ref: str | None
    idempotency_ref: str
    command_ref: str
    bank_execution: BankExecution = BankExecution.UNKNOWN


_CAPABILITIES = {
    CaseOperation.CREATE: Capability.CASE_CREATE,
    CaseOperation.TRIAGE: Capability.CASE_TRIAGE,
    CaseOperation.ASSIGN: Capability.CASE_ASSIGN,
    CaseOperation.DISPOSE: Capability.CASE_DISPOSITION,
    CaseOperation.CORRECT: Capability.CASE_CORRECT,
    CaseOperation.RECONCILE: Capability.CASE_FEEDBACK,
}
_REASONS: dict[CaseOperation, frozenset[CaseReason]] = {
    CaseOperation.CREATE: frozenset({CaseReason.SOURCE_EVALUATION}),
    CaseOperation.TRIAGE: frozenset({CaseReason.ANALYST_TRIAGE}),
    CaseOperation.ASSIGN: frozenset({CaseReason.INVESTIGATION_ASSIGNED}),
    CaseOperation.DISPOSE: frozenset({
        CaseReason.FRAUD_EVIDENCE, CaseReason.LEGITIMATE_EVIDENCE,
        CaseReason.NEEDS_REVIEW,
    }),
    CaseOperation.CORRECT: frozenset({CaseReason.CORRECTED_FINDING}),
    CaseOperation.RECONCILE: frozenset({CaseReason.FEEDBACK_RECONCILED}),
}
_ALLOWED_PREVIOUS: dict[CaseOperation, frozenset[CaseOperation | None]] = {
    CaseOperation.CREATE: frozenset({None}),
    CaseOperation.TRIAGE: frozenset({CaseOperation.CREATE}),
    CaseOperation.ASSIGN: frozenset({CaseOperation.TRIAGE}),
    CaseOperation.DISPOSE: frozenset({CaseOperation.ASSIGN}),
    CaseOperation.CORRECT: frozenset({CaseOperation.DISPOSE, CaseOperation.CORRECT}),
    CaseOperation.RECONCILE: frozenset({CaseOperation.DISPOSE, CaseOperation.CORRECT}),
}


def _sha(tag: str, fields: dict[str, object]) -> str:
    return sha256(dumps({"domain": tag, **fields}, sort_keys=True, separators=(",", ":"))
                  .encode("utf-8")).hexdigest()


def _check_command(command: CaseCommand) -> None:
    if not isinstance(command, CaseCommand):
        raise CaseRejected("typed case command required")
    if (not isinstance(command.tenant_id, str) or not command.tenant_id.strip()
            or command.tenant_id != command.tenant_id.strip()
            or not isinstance(command.case_id, UUID)
            or not isinstance(command.source_event_id, UUID)
            or not isinstance(command.operation, CaseOperation)
            or type(command.expected_revision) is not int
            or command.expected_revision < 0
            or not isinstance(command.idempotency_key, str)
            or fullmatch(r"[0-9a-f]{32}", command.idempotency_key) is None
            or not isinstance(command.reason_code, CaseReason)
            or command.reason_code not in _REASONS[command.operation]):
        raise CaseRejected("invalid case command")
    if command.operation in {CaseOperation.DISPOSE, CaseOperation.CORRECT}:
        if not isinstance(command.disposition, CaseDisposition):
            raise CaseRejected("typed disposition required")
    elif command.disposition is not None:
        raise CaseRejected("disposition allowed only for disposition/correction")
    if command.operation is CaseOperation.ASSIGN:
        if (not isinstance(command.assignee, AuthorizedAssignee)
                or command.assignee.tenant_id != command.tenant_id
                or not isinstance(command.assignee.actor_ref, str)
                or fullmatch(r"[0-9a-f]{64}", command.assignee.actor_ref) is None):
            raise CaseRejected("server-resolved tenant assignee required")
    elif command.assignee is not None:
        raise CaseRejected("assignee allowed only on assignment")


def advance_case(
    history: tuple[CaseEvent, ...], command: CaseCommand, *,
    principal: TrustedPrincipal, source: EvaluationLookup, at: datetime,
) -> tuple[tuple[CaseEvent, ...], CaseEvent]:
    """Validate and *propose* an append, without any DB/HTTP/bank side effects.

    Call only from protected #42 ingress. Persistence MUST serialize per case,
    condition on expected revision, and atomically commit this event with audit
    (or use a separately reviewed outbox). Never trust a client-supplied history.
    """
    _check_command(command)
    if not isinstance(principal, TrustedPrincipal):
        raise CaseRejected("trusted authenticated principal required")
    # Authorization precedes even a duplicate replay: revoked scope cannot re-read.
    authorize(principal, tenant_id=command.tenant_id,
              capability=_CAPABILITIES[command.operation])
    if not isinstance(at, datetime) or at.utcoffset() is None:
        raise CaseRejected("trusted timezone-aware time required")
    if not isinstance(history, tuple) or any(not isinstance(e, CaseEvent) for e in history):
        raise CaseRejected("trusted immutable history required")
    try:
        resolved = source.resolve(command.tenant_id, command.source_event_id)
    except Exception as exc:
        raise CaseSourceUnavailable("trusted evaluation lookup unavailable") from exc
    if (not isinstance(resolved, VerifiedEvaluation)
            or resolved.tenant_id != command.tenant_id
            or resolved.event_id != command.source_event_id
            or not isinstance(resolved.context_ref, str)
            or fullmatch(r"[0-9a-f]{64}", resolved.context_ref) is None):
        raise CaseSourceUnavailable("tenant-bound evaluation unavailable")

    for idx, event in enumerate(history, 1):
        if (event.tenant_id != command.tenant_id
                or event.case_id != command.case_id
                or event.source_event_id != command.source_event_id
                or event.source_context_ref != resolved.context_ref
                or event.revision != idx
                or event.previous_revision != (idx - 1 if idx > 1 else None)
                or event.bank_execution is not BankExecution.UNKNOWN):
            raise CaseRejected("invalid tenant/event-bound history")
    actor_ref = principal.audit_actor
    key_ref = _sha("gasha-case-key-v1", {
        "tenant": command.tenant_id, "actor": actor_ref,
        "key": command.idempotency_key,
    })
    payload_ref = _sha("gasha-case-command-v1", {
        "tenant": command.tenant_id, "case": str(command.case_id),
        "source": str(command.source_event_id), "operation": command.operation.value,
        "expected_revision": command.expected_revision, "reason": command.reason_code.value,
        "disposition": command.disposition.value if command.disposition else None,
        "assignee": command.assignee.actor_ref if command.assignee else None,
        "actor": actor_ref,
    })
    for existing in history:
        if existing.idempotency_ref == key_ref:
            if existing.command_ref != payload_ref:
                raise CaseConflict("idempotency key reused with conflicting payload")
            return history, existing
    if command.expected_revision != len(history):
        raise CaseConflict("stale case revision")
    previous = history[-1] if history else None
    if (previous.operation if previous else None) not in _ALLOWED_PREVIOUS[command.operation]:
        raise CaseRejected("invalid case transition")
    if previous and at < previous.recorded_at:
        raise CaseRejected("case timestamp regressed")
    if command.operation is CaseOperation.CORRECT:
        last_disposition = next(
            (event.disposition for event in reversed(history) if event.disposition is not None),
            None,
        )
        if command.disposition is last_disposition:
            raise CaseRejected("correction must change disposition")
    event = CaseEvent(
        tenant_id=command.tenant_id, case_id=command.case_id,
        source_event_id=command.source_event_id, source_context_ref=resolved.context_ref,
        revision=len(history) + 1, previous_revision=len(history) if history else None,
        operation=command.operation, actor_ref=actor_ref, recorded_at=at.astimezone(UTC),
        reason_code=command.reason_code, disposition=command.disposition,
        assignee_ref=command.assignee.actor_ref if command.assignee else None,
        idempotency_ref=key_ref, command_ref=payload_ref,
    )
    return (*history, event), event
