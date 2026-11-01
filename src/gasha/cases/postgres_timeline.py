"""Opt-in #45 PostgreSQL case transition + redacted audit atomic append.

No API routes or worker composition use this adapter. Each caller must supply a
fresh, server-verified #42 principal, trusted clock and server-owned event and
assignee lookups. Only a dedicated connection per transaction is supported;
bank role grants and evidence provenance are NOT established by this module.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from re import fullmatch
from typing import Any
from uuid import UUID, uuid4

from gasha.cases.timeline import (
    BankExecution,
    CaseCommand,
    CaseConflict,
    CaseDisposition,
    CaseEvent,
    CaseOperation,
    CaseReason,
    CaseRejected,
    EvaluationLookup,
    advance_case,
)
from gasha.postgres import Connection
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    TrustedPrincipal,
    authorize,
    tenant_audit_ref,
)

_CAPABILITY = {
    CaseOperation.CREATE: Capability.CASE_CREATE,
    CaseOperation.TRIAGE: Capability.CASE_TRIAGE,
    CaseOperation.ASSIGN: Capability.CASE_ASSIGN,
    CaseOperation.DISPOSE: Capability.CASE_DISPOSITION,
    CaseOperation.CORRECT: Capability.CASE_CORRECT,
    CaseOperation.RECONCILE: Capability.CASE_FEEDBACK,
}


def _serialize(event: CaseEvent) -> str:
    return dumps({
        "tenant_id": event.tenant_id,
        "case_id": str(event.case_id),
        "source_event_id": str(event.source_event_id),
        "source_context_ref": event.source_context_ref,
        "revision": event.revision,
        "previous_revision": event.previous_revision,
        "operation": event.operation.value,
        "actor_ref": event.actor_ref,
        "recorded_at": event.recorded_at.isoformat(),
        "reason_code": event.reason_code.value,
        "disposition": event.disposition.value if event.disposition else None,
        "assignee_ref": event.assignee_ref,
        "idempotency_ref": event.idempotency_ref,
        "command_ref": event.command_ref,
        "bank_execution": event.bank_execution.value,
    }, sort_keys=True, separators=(",", ":"))


def _deserialize(payload: Any) -> CaseEvent:
    """Fail closed on stored values that cannot be used as an immutable history."""
    if not isinstance(payload, dict):
        raise CaseRejected("stored case event is not an object")
    try:
        if set(payload) != {
            "tenant_id", "case_id", "source_event_id", "source_context_ref",
            "revision", "previous_revision", "operation", "actor_ref",
            "recorded_at", "reason_code", "disposition", "assignee_ref",
            "idempotency_ref", "command_ref", "bank_execution",
        }:
            raise CaseRejected("stored event schema mismatch")
        if (
            any(type(payload[key]) is not str for key in (
                "tenant_id", "case_id", "source_event_id", "source_context_ref",
                "operation", "actor_ref", "recorded_at", "reason_code",
                "idempotency_ref", "command_ref", "bank_execution",
            ))
            or type(payload["revision"]) is not int
            or (payload["previous_revision"] is not None
                and type(payload["previous_revision"]) is not int)
            or (payload["disposition"] is not None
                and type(payload["disposition"]) is not str)
            or (payload["assignee_ref"] is not None
                and type(payload["assignee_ref"]) is not str)
        ):
            raise CaseRejected("stored case event field type mismatch")
        return CaseEvent(
            tenant_id=payload["tenant_id"],
            case_id=UUID(payload["case_id"]),
            source_event_id=UUID(payload["source_event_id"]),
            source_context_ref=payload["source_context_ref"],
            revision=payload["revision"],
            previous_revision=payload["previous_revision"],
            operation=CaseOperation(payload["operation"]),
            actor_ref=payload["actor_ref"],
            recorded_at=datetime.fromisoformat(payload["recorded_at"]),
            reason_code=CaseReason(payload["reason_code"]),
            disposition=(CaseDisposition(payload["disposition"])
                         if payload["disposition"] is not None else None),
            assignee_ref=payload["assignee_ref"],
            idempotency_ref=payload["idempotency_ref"],
            command_ref=payload["command_ref"],
            bank_execution=BankExecution(payload["bank_execution"]),
        )
    except (TypeError, ValueError, KeyError, OverflowError) as exc:
        raise CaseRejected("invalid stored case history") from exc


_HISTORY_SQL = (
    "SELECT tenant_id, case_id, revision, previous_revision, "
    "source_event_id, source_context_ref, actor_ref, occurred_at, "
    "idempotency_ref, command_ref, event_json, bank_execution "
    "FROM analyst_case_events WHERE tenant_id = %s AND case_id = %s "
    "ORDER BY revision"
)
_PREVIOUS: dict[CaseOperation, frozenset[CaseOperation | None]] = {
    CaseOperation.CREATE: frozenset({None}),
    CaseOperation.TRIAGE: frozenset({CaseOperation.CREATE}),
    CaseOperation.ASSIGN: frozenset({CaseOperation.TRIAGE}),
    CaseOperation.DISPOSE: frozenset({CaseOperation.ASSIGN}),
    CaseOperation.CORRECT: frozenset({CaseOperation.DISPOSE, CaseOperation.CORRECT}),
    CaseOperation.RECONCILE: frozenset({CaseOperation.DISPOSE, CaseOperation.CORRECT}),
}
_REASON: dict[CaseOperation, CaseReason] = {
    CaseOperation.CREATE: CaseReason.SOURCE_EVALUATION,
    CaseOperation.TRIAGE: CaseReason.ANALYST_TRIAGE,
    CaseOperation.ASSIGN: CaseReason.INVESTIGATION_ASSIGNED,
    CaseOperation.CORRECT: CaseReason.CORRECTED_FINDING,
    CaseOperation.RECONCILE: CaseReason.FEEDBACK_RECONCILED,
}
_DISPOSITION_REASON: dict[CaseDisposition, CaseReason] = {
    CaseDisposition.FRAUD: CaseReason.FRAUD_EVIDENCE,
    CaseDisposition.LEGITIMATE: CaseReason.LEGITIMATE_EVIDENCE,
    CaseDisposition.UNRESOLVED: CaseReason.NEEDS_REVIEW,
}


def _verified_history(
    rows: list[Mapping[str, object]], *, tenant_id: str, case_id: UUID,
) -> tuple[CaseEvent, ...]:
    """Fail closed on corrupt metadata, JSON, revision or source lineage.

    This local consistency check does not attest bank origin or DB tamper-proofing.
    """
    history: list[CaseEvent] = []
    for row in rows:
        event = _deserialize(row["event_json"])
        revision = len(history) + 1
        previous = history[-1] if history else None
        if (
            event.tenant_id != tenant_id
            or event.case_id != case_id
            or row["tenant_id"] != event.tenant_id
            or row["case_id"] != event.case_id
            or event.revision != revision
            or row["revision"] != revision
            or event.previous_revision != (revision - 1 if previous else None)
            or row["previous_revision"] != event.previous_revision
            or row["source_event_id"] != event.source_event_id
            or row["source_context_ref"] != event.source_context_ref
            or row["actor_ref"] != event.actor_ref
            or row["occurred_at"] != event.recorded_at
            or row["idempotency_ref"] != event.idempotency_ref
            or row["command_ref"] != event.command_ref
            or row["bank_execution"] != BankExecution.UNKNOWN.value
            or event.bank_execution is not BankExecution.UNKNOWN
            or event.recorded_at.utcoffset() is None
            or any(fullmatch(r"[0-9a-f]{64}", field) is None for field in (
                event.source_context_ref, event.actor_ref,
                event.idempotency_ref, event.command_ref,
            ))
            or (event.assignee_ref is not None
                and fullmatch(r"[0-9a-f]{64}", event.assignee_ref) is None)
            or (previous and (
                event.source_event_id != previous.source_event_id
                or event.source_context_ref != previous.source_context_ref
                or event.recorded_at < previous.recorded_at
            ))
            or (previous.operation if previous else None)
            not in _PREVIOUS[event.operation]
        ):
            raise CaseRejected("stored case history/row integrity mismatch")
        if event.operation is CaseOperation.DISPOSE:
            if (event.disposition is None
                    or event.reason_code is not _DISPOSITION_REASON[event.disposition]):
                raise CaseRejected("stored disposition/reason mismatch")
        elif event.reason_code is not _REASON[event.operation]:
            raise CaseRejected("stored transition reason mismatch")
        if (event.operation in {CaseOperation.DISPOSE, CaseOperation.CORRECT}
                and event.disposition is None):
            raise CaseRejected("stored disposition missing")
        if (event.operation not in {CaseOperation.DISPOSE, CaseOperation.CORRECT}
                and event.disposition is not None):
            raise CaseRejected("stored disposition on wrong operation")
        if (event.assignee_ref is None) == (event.operation is CaseOperation.ASSIGN):
            raise CaseRejected("stored assignee/operation mismatch")
        if event.operation is CaseOperation.CORRECT:
            last = next(
                (e.disposition for e in reversed(history) if e.disposition is not None),
                None,
            )
            if event.disposition is last:
                raise CaseRejected("stored correction did not change disposition")
        history.append(event)
    return tuple(history)


class PostgresCaseTimelineService:
    """Transactional synthetic case timeline, deliberately not API-connected.

    PG advisory transaction locks serialize both initial creation and revisions
    for a tenant/case. A database uniqueness constraint rejects the same
    tenant/actor/idempotency key across *other* cases. The mandatory redacted
    audit and transition row use ONE connection and ONE commit; the separately
    committing PostgresSecurityAuditSink must not be called here.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def history(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        case_id: UUID, at: datetime,
    ) -> tuple[CaseEvent, ...]:
        """Authorize the internal read; no unguarded history-reader shortcut."""
        if not isinstance(principal, TrustedPrincipal):
            raise AuthorizationRejected("trusted authenticated principal required")
        if not isinstance(at, datetime) or at.utcoffset() is None:
            raise CaseRejected("trusted aware clock required")
        # Same-zone aware datetime comparison ignores DST fold; compare UTC.
        if principal.expires_at.astimezone(UTC) <= at.astimezone(UTC):
            raise AuthorizationRejected("expired principal")
        authorize(principal, tenant_id=tenant_id, capability=Capability.CASE_READ)
        if not isinstance(case_id, UUID):
            raise CaseRejected("typed case ID required")
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    _HISTORY_SQL,
                    (tenant_id, case_id),
                )
                rows = cursor.fetchall()
        finally:
            # Terminate the read transaction even after SQL failure.
            self._connection.rollback()
        return _verified_history(rows, tenant_id=tenant_id, case_id=case_id)

    def apply(
        self, command: CaseCommand, *, principal: TrustedPrincipal,
        source: EvaluationLookup, at: datetime,
    ) -> CaseEvent:
        """Authorize, serialize, validate, append + audit, or roll back all writes.

        Source/assignee authority is the *caller's* trusted composition concern.
        This inert adapter must never accept request JSON as principal/source.
        """
        if not isinstance(command, CaseCommand) or not isinstance(
            command.operation, CaseOperation
        ):
            raise CaseRejected("typed case command and operation required")
        if not isinstance(principal, TrustedPrincipal):
            raise AuthorizationRejected("trusted authenticated principal required")
        if not isinstance(at, datetime) or at.utcoffset() is None:
            raise CaseRejected("trusted aware clock required")
        # Same-zone aware datetime comparison ignores DST fold; compare UTC.
        if principal.expires_at.astimezone(UTC) <= at.astimezone(UTC):
            raise AuthorizationRejected("expired principal")
        # Security boundary before DB access, event lookup, or idempotent replay.
        authorize(
            principal, tenant_id=command.tenant_id,
            capability=_CAPABILITY[command.operation],
        )
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (dumps(
                        ["gasha-case-v1", command.tenant_id, str(command.case_id)],
                        separators=(",", ":"),
                    ),),
                )
                cursor.execute(
                    _HISTORY_SQL,
                    (command.tenant_id, command.case_id),
                )
                history = _verified_history(
                    cursor.fetchall(), tenant_id=command.tenant_id,
                    case_id=command.case_id,
                )
                proposed, event = advance_case(
                    history, command, principal=principal, source=source, at=at,
                )
                if len(proposed) == len(history):
                    # Identical replay: no duplicate event and no second audit.
                    self._connection.rollback()
                    return event
                cursor.execute(
                    """INSERT INTO analyst_case_events (
                        tenant_id, case_id, revision, previous_revision,
                        source_event_id, source_context_ref, actor_ref, occurred_at,
                        idempotency_ref, command_ref, event_json, bank_execution
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s
                    )""",
                    (
                        event.tenant_id, event.case_id, event.revision,
                        event.previous_revision, event.source_event_id,
                        event.source_context_ref, event.actor_ref,
                        event.recorded_at, event.idempotency_ref,
                        event.command_ref, _serialize(event),
                        BankExecution.UNKNOWN.value,
                    ),
                )
                # Audit is in the SAME SQL transaction; a separate sink which
                # auto-commits would violate the #45 Security contract.
                cursor.execute(
                    """INSERT INTO security_audit_events (
                        occurred_at, action, result, actor_ref, tenant_ref,
                        reason, attempt_ref, event_ref, context_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        event.recorded_at, "case." + event.operation.value,
                        "allowed", event.actor_ref,
                        tenant_audit_ref(event.tenant_id),
                        "case_transition_committed", uuid4().hex,
                        sha256(dumps(
                            ["gasha-case-event-v1", event.tenant_id,
                             str(event.case_id), event.revision],
                            separators=(",", ":"),
                        ).encode()).hexdigest(),
                        event.source_context_ref,
                    ),
                )
            self._connection.commit()
            return event
        except Exception as exc:
            self._connection.rollback()
            if getattr(exc, "sqlstate", None) == "23505":
                raise CaseConflict("case revision or idempotency key conflict") from exc
            raise
