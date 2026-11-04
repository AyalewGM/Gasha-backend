"""Bank-facing API boundary. All non-health operations fail closed without trusted wiring.

The synthetic scoring interface lives in gasha.api.synthetic and MUST NOT be
deployed in bank environments. No caller policy, score, role or mode is trusted
by this app. This is a bounded #42 foundation, not bank deployment approval.
"""
from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from hashlib import sha256
from typing import Annotated, NoReturn, Protocol
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette._utils import get_route_path

from gasha.cases.timeline import (
    AuthorizedAssignee,
    BankExecution,
    CaseCommand,
    CaseConflict,
    CaseDisposition,
    CaseEvent,
    CaseOperation,
    CaseReason,
    case_command_fingerprints,
    validate_case_history,
)
from gasha.decision.mode import DecisionEnvelope, ModeAwareDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.outcome_ingestion import (
    IncumbentOutcomeRecord,
    OutcomeSubmission,
)
from gasha.poc.outcomes import OutcomeRecord
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    CredentialRejected,
    CredentialVerifier,
    IdentityUnavailable,
    SecurityAuditEvent,
    SecurityAuditSink,
    TrustedPrincipal,
    authenticate,
    authorize,
    tenant_audit_ref,
    utcnow,
)


def _safe_version_metadata(value: object) -> bool:
    """Require printable ASCII before server provenance reaches HTTP headers.

    This is a transport-safety check, not a provider identity or attestation.
    Reject control bytes, DEL, non-ASCII and empty/whitespace-only values.
    """
    return (
        isinstance(value, str)
        and bool(value.strip())
        and all(0x20 <= ord(char) <= 0x7e for char in value)
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedDecisionContext:
    """Immutable server-selected, event-bound policy and signal snapshot.

    Pydantic policy and intelligence models are mutable. Persist canonical JSON
    internally and return fresh parsed copies so a provider cannot mutate an
    already-issued decision context after construction.
    """

    tenant_id: str
    event_id: UUID
    signal_source_version: str
    signal_version: str
    collected_at: datetime
    expires_at: datetime
    _policy_snapshot: str = field(repr=False)
    _signal_snapshot: str = field(repr=False)
    _signal_digest: str = field(repr=False)

    def __init__(
        self,
        *,
        tenant_id: str,
        event_id: UUID,
        policy: DecisionPolicy,
        intelligence: IntelligenceSnapshot,
        signal_source_version: str,
        signal_version: str,
        collected_at: datetime,
        expires_at: datetime,
    ) -> None:
        if (
            not isinstance(tenant_id, str) or not tenant_id.strip()
            or not isinstance(event_id, UUID)
            or not isinstance(policy, DecisionPolicy)
            or not isinstance(intelligence, IntelligenceSnapshot)
            or not _safe_version_metadata(signal_source_version)
            or not _safe_version_metadata(signal_version)
            or not isinstance(collected_at, datetime)
            or collected_at.utcoffset() is None
            or not isinstance(expires_at, datetime)
            or expires_at.utcoffset() is None
            # Compare absolute instants: equal-zone ZoneInfo folds otherwise
            # compare local wall time and can admit an expired validity window.
            or expires_at.astimezone(UTC) <= collected_at.astimezone(UTC)
        ):
            raise ValueError("trusted event-bound decision provenance required")
        policy_snapshot = policy.model_dump_json()
        signal_snapshot = intelligence.model_dump_json()
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "signal_source_version", signal_source_version)
        object.__setattr__(self, "signal_version", signal_version)
        object.__setattr__(self, "collected_at", collected_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "_policy_snapshot", policy_snapshot)
        object.__setattr__(self, "_signal_snapshot", signal_snapshot)
        object.__setattr__(
            self, "_signal_digest", sha256(signal_snapshot.encode()).hexdigest()
        )

    @property
    def policy(self) -> DecisionPolicy:
        return DecisionPolicy.model_validate_json(self._policy_snapshot)

    @property
    def intelligence(self) -> IntelligenceSnapshot:
        return IntelligenceSnapshot.model_validate_json(self._signal_snapshot)

    @property
    def context_ref(self) -> str:
        """Field-tagged, unambiguous internal provenance digest (not attestation)."""
        # NUL-joining arbitrary provider strings lets distinct (source, version)
        # tuples have identical preimages. Canonical JSON binds names and types,
        # with a domain/schema tag and normalized UTC instants.
        preimage = {
            "schema": "gasha-context-ref-v2",
            "tenant_id": self.tenant_id,
            "event_id": str(self.event_id),
            "signal_source_version": self.signal_source_version,
            "signal_version": self.signal_version,
            "collected_at": self.collected_at.astimezone(UTC).isoformat(),
            "expires_at": self.expires_at.astimezone(UTC).isoformat(),
            "signal_sha256": self._signal_digest,
            "policy_json": self._policy_snapshot,
        }
        return sha256(
            json.dumps(
                preimage, sort_keys=True, ensure_ascii=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()


class TrustedDecisionContextProvider(Protocol):
    """Bank-approved adapter resolves policy/signals without using request assertions."""

    def resolve(
        self, transaction: CanonicalTransaction, principal: TrustedPrincipal
    ) -> TrustedDecisionContext: ...


class TrustedCaseHistoryReader(Protocol):
    """Server-installed, principal-scoped, immutable #45 history reader.

    A Bank installation must supply a tenant-isolating durable adapter; neither
    request JSON nor a caller-selected DB connection is a trusted reader.
    """

    def history(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        case_id: UUID, at: datetime,
    ) -> tuple[CaseEvent, ...]: ...



class TrustedCaseTransitionWriter(Protocol):
    """Explicitly installed #45 atomic case + terminal-audit writer.

    Must resolve a tenant-bound, immutable evaluation and any proposed assignee
    through server-owned authority, revalidate the principal at the transaction
    boundary, serialize expected revisions, and commit the case event and
    redacted terminal audit atomically. Request selectors confer no authority.
    The default bank-facing app deliberately installs no writer.
    """

    def apply(
        self, *, principal: TrustedPrincipal, tenant_id: str, case_id: UUID,
        operation: CaseOperation, proposal: CaseTransitionInput, at: datetime,
    ) -> CaseEvent: ...


class TrustedDecisionRequest(BaseModel):
    """Only transaction facts are accepted; policy, risk and mode are forbidden."""

    model_config = ConfigDict(extra="forbid")
    transaction: CanonicalTransaction



class CaseTransitionInput(BaseModel):
    """Only proposed state, never trusted principal, tenant, source or assignee.

    All fields are immutable primitives/enums/UUIDs; freeze after validation.
    The installed writer receives a separate copy, not the HTTP guard snapshot.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    source_event_id: UUID
    expected_revision: int = Field(ge=0, strict=True)
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{32}$")
    reason_code: CaseReason
    disposition: CaseDisposition | None = None
    # A request selector: the installed writer must independently resolve it
    # to an authorized tenant-scoped assignee before constructing CaseCommand.
    assignee_selector: UUID | None = None


_CASE_TRANSITION_CAPABILITIES: dict[CaseOperation, Capability] = {
    CaseOperation.CREATE: Capability.CASE_CREATE,
    CaseOperation.TRIAGE: Capability.CASE_TRIAGE,
    CaseOperation.ASSIGN: Capability.CASE_ASSIGN,
    CaseOperation.DISPOSE: Capability.CASE_DISPOSITION,
    CaseOperation.CORRECT: Capability.CASE_CORRECT,
    CaseOperation.RECONCILE: Capability.CASE_FEEDBACK,
}

_CASE_TRANSITION_REASONS: dict[CaseOperation, frozenset[CaseReason]] = {
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
_CASE_DISPOSITION_REASONS: dict[CaseDisposition, CaseReason] = {
    CaseDisposition.FRAUD: CaseReason.FRAUD_EVIDENCE,
    CaseDisposition.LEGITIMATE: CaseReason.LEGITIMATE_EVIDENCE,
    CaseDisposition.UNRESOLVED: CaseReason.NEEDS_REVIEW,
}


# Only /health/live and /health/ready are intentionally public. The default
# FastAPI documentation/schema URLs otherwise expose non-health API metadata
# without authentication; leave developer documentation to isolated tooling.
app = FastAPI(
    title="Gasha Protected Fraud Decision API",
    version="0.3.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
# These are intentionally absent until bank-approved wiring is supplied.
app.state.identity_verifier = None
app.state.security_audit = None
app.state.decision_context_provider = None
# Legacy reference service remains injectable for negative tests, never bank writes.
app.state.outcome_ingestion = None
# No bank case reader is installed by default; the endpoint fails closed.
app.state.case_history_reader = None
# No case mutation can be enabled by request flags or a frontend role.
app.state.case_transition_writer = None


@app.middleware("http")
async def assign_attempt_ref(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    # Do not accept request-supplied correlation/role headers as audit authority.
    request.state.attempt_ref = uuid4().hex
    # FastAPI parses malformed JSON before executing Depends(get_principal).
    # Authenticate at ingress so bad JSON cannot skip credential verification
    # or the redacted authentication audit on protected endpoints.
    # Use the same trusted ASGI scope/root_path resolution as Starlette routing.
    # request.url.path includes deployment prefixes and can miss routed /v1/ endpoints.
    # Client-provided X-Forwarded-Prefix/role/tenant headers are not route authority.
    if get_route_path(request.scope).startswith("/v1/"):
        try:
            request.state.authenticated_principal = get_principal(
                request, request.headers.get("authorization")
            )
        except HTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers,
            )
    return await call_next(request)


def _audit(
    request: Request,
    action: str,
    result: str,
    actor_ref: str,
    tenant_id: str,
    reason: str,
    *,
    event_id: UUID | None = None,
    context_ref: str = "",
) -> None:
    sink: SecurityAuditSink | None = getattr(request.app.state, "security_audit", None)
    if sink is None:
        raise HTTPException(status_code=503, detail="security audit unavailable")
    attempt_ref: str = getattr(request.state, "attempt_ref", "")
    if not attempt_ref:
        raise HTTPException(status_code=503, detail="security audit unavailable")
    event_ref = (
        sha256(f"{tenant_id}\0{event_id}".encode()).hexdigest()
        if event_id is not None else ""
    )
    try:
        sink.append(
            SecurityAuditEvent(
                action=action,
                result=result,
                actor_ref=actor_ref,
                tenant_ref=tenant_audit_ref(tenant_id),
                reason=reason,
                at=utcnow(),
                attempt_ref=attempt_ref,
                event_ref=event_ref,
                context_ref=context_ref,
            )
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="security audit unavailable") from exc


def get_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> TrustedPrincipal:
    # The ingress verifier runs before JSON parsing. Reuse its exact trusted
    # principal in route dependencies; never verify twice or accept a forged
    # principal returned from a dependency override.
    ingress_principal = getattr(request.state, "authenticated_principal", None)
    if isinstance(ingress_principal, TrustedPrincipal):
        return ingress_principal
    verifier: CredentialVerifier | None = getattr(
        request.app.state, "identity_verifier", None
    )
    try:
        principal = authenticate(authorization, verifier, now=utcnow())
    except CredentialRejected as exc:
        _audit(request, "authenticate", "denied", "anonymous", "", "invalid_credential")
        raise HTTPException(
            status_code=401,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except IdentityUnavailable as exc:
        _audit(request, "authenticate", "denied", "anonymous", "", "identity_unavailable")
        raise HTTPException(status_code=503, detail="identity unavailable") from exc
    _audit(request, "authenticate", "verified", principal.audit_actor, "", "verified")
    return principal


def _require_action(
    request: Request,
    principal: TrustedPrincipal,
    tenant_id: str,
    capability: Capability,
    *,
    event_id: UUID,
) -> None:
    # Test/deployment dependency overrides must not replace the authenticated
    # principal with a stronger caller-controlled identity after ingress.
    ingress_principal = getattr(request.state, "authenticated_principal", None)
    if not isinstance(ingress_principal, TrustedPrincipal) or principal is not ingress_principal:
        _audit(
            request, capability.value, "denied",
            ingress_principal.audit_actor if isinstance(ingress_principal, TrustedPrincipal)
            else "anonymous",
            tenant_id, "principal_context_mismatch", event_id=event_id,
        )
        raise HTTPException(status_code=403, detail="not authorized")
    try:
        authorize(principal, tenant_id=tenant_id, capability=capability)
    except AuthorizationRejected as exc:
        _audit(
            request, capability.value, "denied", principal.audit_actor, tenant_id,
            "authorization_denied", event_id=event_id,
        )
        status = 404 if tenant_id not in principal.tenant_ids else 403
        raise HTTPException(status_code=status, detail="not authorized") from exc
    _audit(
        request, capability.value, "authorized", principal.audit_actor, tenant_id,
        "allowed", event_id=event_id,
    )


def _operation_audit(
    request: Request, principal: TrustedPrincipal, tenant_id: str,
    event_id: UUID, capability: Capability, result: str, reason: str,
    *, context_ref: str = "",
) -> None:
    _audit(
        request, capability.value, result, principal.audit_actor,
        tenant_id, reason, event_id=event_id, context_ref=context_ref,
    )


def _trusted_context(
    request: Request, tx: CanonicalTransaction, principal: TrustedPrincipal
) -> TrustedDecisionContext:
    provider: TrustedDecisionContextProvider | None = getattr(
        request.app.state, "decision_context_provider", None
    )
    if provider is None:
        raise HTTPException(status_code=503, detail="trusted decision context unavailable")
    try:
        context = provider.resolve(tx, principal)
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="trusted decision context unavailable"
        ) from exc
    now = utcnow().astimezone(UTC)
    if (
        not isinstance(context, TrustedDecisionContext)
        or context.tenant_id != tx.tenant_id
        or context.event_id != tx.event_id
        or not _safe_version_metadata(context.signal_source_version)
        or not _safe_version_metadata(context.signal_version)
        or not isinstance(context.collected_at, datetime)
        or context.collected_at.utcoffset() is None
        or not isinstance(context.expires_at, datetime)
        or context.expires_at.utcoffset() is None
        # ZoneInfo repeated local time in a DST fold compares by wall clock
        # when both operands share tzinfo. Enforce freshness by UTC instants.
        or context.collected_at.astimezone(UTC) > now
        or context.expires_at.astimezone(UTC) <= now
    ):
        raise HTTPException(status_code=503, detail="trusted decision context unavailable")
    return context



def _case_history_view(
    history: tuple[CaseEvent, ...], *, tenant_id: str, case_id: UUID,
) -> list[dict[str, object]]:
    """Defensive projection of a trusted reader result; no raw case notes/PII."""
    if type(history) is not tuple:
        raise ValueError("immutable case history required")
    validate_case_history(history, tenant_id=tenant_id, case_id=case_id)
    projection: list[dict[str, object]] = []
    first_event: UUID | None = None
    first_context: str | None = None
    previous_at: datetime | None = None
    for revision, event in enumerate(history, 1):
        if (
            type(event) is not CaseEvent
            or event.tenant_id != tenant_id
            or event.case_id != case_id
            or type(event.source_event_id) is not UUID
            or type(event.source_context_ref) is not str
            or re.fullmatch(r"[0-9a-f]{64}", event.source_context_ref) is None
            or type(event.actor_ref) is not str
            or re.fullmatch(r"[0-9a-f]{64}", event.actor_ref) is None
            or event.revision != revision
            or type(event.revision) is not int
            or event.previous_revision != (revision - 1 if revision > 1 else None)
            or (event.previous_revision is not None
                and type(event.previous_revision) is not int)
            or type(event.operation) is not CaseOperation
            or type(event.reason_code) is not CaseReason
            or (event.disposition is not None
                and type(event.disposition) is not CaseDisposition)
            or (event.assignee_ref is not None
                and (type(event.assignee_ref) is not str
                     or re.fullmatch(r"[0-9a-f]{64}", event.assignee_ref) is None))
            or event.bank_execution is not BankExecution.UNKNOWN
            or not isinstance(event.recorded_at, datetime)
            or event.recorded_at.utcoffset() is None
        ):
            raise ValueError("malformed tenant-scoped case history")
        if first_event is None:
            first_event = event.source_event_id
            first_context = event.source_context_ref
        elif event.source_event_id != first_event or event.source_context_ref != first_context:
            raise ValueError("case history source identity changed")
        at = event.recorded_at.astimezone(UTC)
        if previous_at is not None and at < previous_at:
            raise ValueError("case history clock regressed")
        previous_at = at
        projection.append({
            "revision": revision,
            "previous_revision": event.previous_revision,
            "operation": event.operation.value,
            "recorded_at": at.isoformat(),
            "reason_code": event.reason_code.value,
            "disposition": event.disposition.value if event.disposition else None,
            "actor_ref": event.actor_ref,
            "assignee_ref": event.assignee_ref,
            "source_event_id": str(event.source_event_id),
            "source_context_ref": event.source_context_ref,
            "bank_execution": "unknown",
        })
    return projection


@app.get("/v1/tenants/{tenant_id}/cases/{case_id}/history")
def get_case_history(
    tenant_id: str,
    case_id: UUID,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> dict[str, object]:
    """Authenticated read-only #45 integration; no case/outcome mutation.

    The default app has no reader. In a controlled installation, an explicitly
    wired durable adapter must independently recheck identity, tenancy and
    credential expiry immediately before the read. Never trust frontend roles.
    """
    action = Capability.CASE_READ
    _require_action(request, principal, tenant_id, action, event_id=case_id)
    reader: TrustedCaseHistoryReader | None = getattr(
        request.app.state, "case_history_reader", None
    )
    try:
        if reader is None:
            raise RuntimeError("trusted case history reader not configured")
        history = reader.history(
            principal=principal, tenant_id=tenant_id, case_id=case_id, at=utcnow(),
        )
        events = _case_history_view(history, tenant_id=tenant_id, case_id=case_id)
    except Exception as exc:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "failed", "case_history_unavailable",
        )
        raise HTTPException(status_code=503, detail="case history unavailable") from exc
    if not events:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "not_found", "case_not_found",
        )
        raise HTTPException(status_code=404, detail="case not found")
    _operation_audit(
        request, principal, tenant_id, case_id, action,
        "succeeded", "case_history_read",
    )
    return {
        "case_id": str(case_id),
        "events": events,
        "enforcement_activated": False,
    }



def _validated_case_transition_result(
    event: object, *, tenant_id: str, case_id: UUID,
    selected: CaseOperation, proposal: CaseTransitionInput,
    accepted_actor_ref: str,
) -> CaseEvent:
    """Bounded defense against malformed writer success claims.

    This checks the full event *shape* and the proposal-bound fingerprints,
    matching the single-event invariants of validate_case_history. It cannot
    prove preexisting-case history, immutable Bank provenance, authorized
    assignee resolution or atomic DB + terminal-audit commit: those remain the
    separately accepted responsibilities of the server-installed writer.
    """
    if type(event) is not CaseEvent:
        raise ValueError("typed case event required")
    # Accessing any deleted attribute raises; the caller must map all invalid
    # writer responses to a redacted 503, never an uncontrolled exception.
    if (
        type(event.tenant_id) is not str
        or event.tenant_id != tenant_id
        or type(event.case_id) is not UUID
        or event.case_id != case_id
        or type(event.source_event_id) is not UUID
        or event.source_event_id != proposal.source_event_id
        or type(event.source_context_ref) is not str
        or re.fullmatch(r"[0-9a-f]{64}", event.source_context_ref) is None
        or type(event.revision) is not int
        or event.revision != proposal.expected_revision + 1
        or (event.previous_revision is not None
            and type(event.previous_revision) is not int)
        or event.previous_revision != (
            proposal.expected_revision if proposal.expected_revision else None
        )
        or type(event.operation) is not CaseOperation
        or event.operation is not selected
        or type(event.actor_ref) is not str
        or re.fullmatch(r"[0-9a-f]{64}", event.actor_ref) is None
        or event.actor_ref != accepted_actor_ref
        or type(event.recorded_at) is not datetime
        or event.recorded_at.utcoffset() is None
        or type(event.reason_code) is not CaseReason
        or event.reason_code not in _CASE_TRANSITION_REASONS[selected]
        or event.reason_code is not proposal.reason_code
        or (event.disposition is not None
            and type(event.disposition) is not CaseDisposition)
        or event.disposition is not proposal.disposition
        or ((event.disposition is not None)
            != (selected in {CaseOperation.DISPOSE, CaseOperation.CORRECT}))
        or (selected is CaseOperation.DISPOSE and (
            event.disposition is None
            or _CASE_DISPOSITION_REASONS[event.disposition] is not event.reason_code
        ))
        or (event.assignee_ref is not None
            and (type(event.assignee_ref) is not str
                or re.fullmatch(r"[0-9a-f]{64}", event.assignee_ref) is None))
        or (event.assignee_ref is None) == (selected is CaseOperation.ASSIGN)
        or type(event.idempotency_ref) is not str
        or re.fullmatch(r"[0-9a-f]{64}", event.idempotency_ref) is None
        or type(event.command_ref) is not str
        or re.fullmatch(r"[0-9a-f]{64}", event.command_ref) is None
        or event.bank_execution is not BankExecution.UNKNOWN
    ):
        raise ValueError("malformed case transition result")
    # The assignee reference comes from the writer's result, not the request.
    # This verifies hash consistency but does not attest assignee authority.
    assignee = (
        AuthorizedAssignee(tenant_id, event.assignee_ref)
        if selected is CaseOperation.ASSIGN and event.assignee_ref is not None
        else None
    )
    command = CaseCommand(
        tenant_id=tenant_id, case_id=case_id,
        source_event_id=proposal.source_event_id,
        operation=selected, expected_revision=proposal.expected_revision,
        idempotency_key=proposal.idempotency_key,
        reason_code=proposal.reason_code,
        disposition=proposal.disposition, assignee=assignee,
    )
    key_ref, command_ref = case_command_fingerprints(
        command, actor_ref=accepted_actor_ref,
    )
    if event.idempotency_ref != key_ref or event.command_ref != command_ref:
        raise ValueError("case transition fingerprint mismatch")
    return event


@app.post("/v1/tenants/{tenant_id}/cases/{case_id}/transitions/{operation}")
def submit_case_transition(
    tenant_id: str,
    case_id: UUID,
    operation: str,
    proposal: CaseTransitionInput,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> dict[str, object]:
    """Bounded protected #45 ingress; no writer or Bank mutation by default.

    The installed writer, not this HTTP function, owns the atomic transition +
    redacted terminal audit. We MUST NOT append a nontransactional success audit
    after a commit: if that audit failed, a successful write could return 503.
    The ingress authorization audit executes before the writer is consulted.
    """
    try:
        selected = CaseOperation(operation)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="case operation not found") from exc
    action = _CASE_TRANSITION_CAPABILITIES[selected]
    _require_action(request, principal, tenant_id, action, event_id=case_id)
    valid_shape = (
        proposal.reason_code in _CASE_TRANSITION_REASONS[selected]
        and (proposal.assignee_selector is not None) == (selected is CaseOperation.ASSIGN)
        and (proposal.disposition is not None)
        == (selected in {CaseOperation.DISPOSE, CaseOperation.CORRECT})
        and (
            selected is not CaseOperation.DISPOSE
            or (proposal.disposition is not None and _CASE_DISPOSITION_REASONS[proposal.disposition] is proposal.reason_code)
        )
    )
    if not valid_shape:
        _operation_audit(
            request, principal, tenant_id, case_id, action, "denied",
            "invalid_case_transition",
        )
        raise HTTPException(status_code=422, detail="invalid case transition")
    # Preserve an immutable, detached copy of the exact validated HTTP command.
    # An installed writer may be misconfigured or bypass model immutability;
    # neither its argument nor any returned hash may rewrite this reference.
    accepted_proposal = proposal.model_copy(deep=True)
    # Bind response validation to the actor authenticated before writer entry.
    accepted_actor_ref = principal.audit_actor
    writer: TrustedCaseTransitionWriter | None = getattr(
        request.app.state, "case_transition_writer", None
    )
    if writer is None:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "failed", "case_transition_unavailable",
        )
        raise HTTPException(status_code=503, detail="case transition unavailable")
    try:
        event = writer.apply(
            principal=replace(principal), tenant_id=tenant_id, case_id=case_id,
            operation=selected, proposal=proposal.model_copy(deep=True), at=utcnow(),
        )
    except CaseConflict as exc:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "rejected", "case_revision_conflict",
        )
        raise HTTPException(status_code=409, detail="case revision conflict") from exc
    except AuthorizationRejected as exc:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "denied", "case_reference_denied",
        )
        raise HTTPException(status_code=404, detail="case not found") from exc
    except Exception as exc:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "failed", "case_transition_unavailable",
        )
        raise HTTPException(status_code=503, detail="case transition unavailable") from exc
    # A malformed/missing writer event must never return HTTP 200.
    try:
        event = _validated_case_transition_result(
            event, tenant_id=tenant_id, case_id=case_id,
            selected=selected, proposal=accepted_proposal,
            accepted_actor_ref=accepted_actor_ref,
        )
    except Exception as exc:
        _operation_audit(
            request, principal, tenant_id, case_id, action,
            "failed", "case_transition_unavailable",
        )
        raise HTTPException(
            status_code=503, detail="case transition unavailable",
        ) from exc
    # The writer owns the terminal success audit in the *same transaction*.
    return {
        "case_id": str(event.case_id),
        "source_event_id": str(event.source_event_id),
        "revision": event.revision,
        "operation": event.operation.value,
        "disposition": event.disposition.value if event.disposition else None,
        "bank_execution": BankExecution.UNKNOWN.value,
        "enforcement_activated": False,
    }


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness(request: Request) -> JSONResponse:
    """Non-sensitive wiring check only. #46 still requires dependency probes."""
    checks = {
        "identity_verifier": getattr(request.app.state, "identity_verifier", None) is not None,
        "security_audit": getattr(request.app.state, "security_audit", None) is not None,
        "decision_context_provider": (
            getattr(request.app.state, "decision_context_provider", None) is not None
        ),
        # No durable outcome+terminal-audit atomic adapter is implemented.
        # Legacy/in-memory dependency injection cannot turn this gate green.
        "outcome_atomic_commit": False,
    }
    ready = all(checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not_ready", "checks": checks},
    )


@app.post("/v1/decisions", response_model=FraudDecision)
def create_decision(
    payload: TrustedDecisionRequest,
    request: Request,
    response: Response,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> FraudDecision:
    tx = payload.transaction
    action = Capability.DECISION_SUBMIT
    _require_action(request, principal, tx.tenant_id, action, event_id=tx.event_id)
    try:
        context = _trusted_context(request, tx, principal)
        decision = DecisionService(context.policy).decide(tx, context.intelligence)
    except Exception as exc:
        _operation_audit(
            request, principal, tx.tenant_id, tx.event_id, action,
            "failed", "decision_unavailable",
        )
        raise HTTPException(status_code=503, detail="decision unavailable") from exc
    _operation_audit(
        request, principal, tx.tenant_id, tx.event_id, action,
        "succeeded", "recommendation_computed", context_ref=context.context_ref,
    )
    # A recommendation is not proof of a bank-executed intervention.
    response.headers["X-Gasha-Context-Ref"] = context.context_ref
    response.headers["X-Gasha-Signal-Version"] = context.signal_version
    response.headers["X-Gasha-Source-Version"] = context.signal_source_version
    return decision


@app.post("/v1/evaluations", response_model=DecisionEnvelope)
def create_evaluation(
    payload: TrustedDecisionRequest,
    request: Request,
    response: Response,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> DecisionEnvelope:
    tx = payload.transaction
    action = Capability.DECISION_SUBMIT
    _require_action(request, principal, tx.tenant_id, action, event_id=tx.event_id)
    try:
        context = _trusted_context(request, tx, principal)
        result = ModeAwareDecisionService(
            context.policy, operating_mode=OperatingMode.SHADOW
        ).decide(tx, context.intelligence)
    except Exception as exc:
        _operation_audit(
            request, principal, tx.tenant_id, tx.event_id, action,
            "failed", "evaluation_unavailable",
        )
        raise HTTPException(status_code=503, detail="evaluation unavailable") from exc
    _operation_audit(
        request, principal, tx.tenant_id, tx.event_id, action,
        "succeeded", "shadow_recommendation_computed", context_ref=context.context_ref,
    )
    response.headers["X-Gasha-Context-Ref"] = context.context_ref
    response.headers["X-Gasha-Signal-Version"] = context.signal_version
    response.headers["X-Gasha-Source-Version"] = context.signal_source_version
    return result


def _reject_untransactional_outcome(
    request: Request,
    principal: TrustedPrincipal,
    tenant_id: str,
    event_id: UUID,
    capability: Capability,
) -> NoReturn:
    """Fail closed until outcome and terminal audit can commit atomically.

    The legacy OutcomeIngestionService reads then appends without a transaction;
    accepting it here risks a changed outcome and HTTP 503 if terminal auditing
    fails after the write. No injected in-memory service or request-controlled
    switch is permitted to enable protected outcome mutation.
    """
    _require_action(request, principal, tenant_id, capability, event_id=event_id)
    _operation_audit(
        request, principal, tenant_id, event_id, capability,
        "failed", "transactional_outcome_unavailable",
    )
    raise HTTPException(
        status_code=503, detail="transactional outcome ingestion unavailable",
    )


@app.post("/v1/outcomes", response_model=OutcomeSubmission)
def submit_outcome(
    record: OutcomeRecord,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> OutcomeSubmission:
    """Bank-facing mutation disabled pending a trusted atomic outcome/audit port."""
    _reject_untransactional_outcome(
        request, principal, record.tenant_id, record.event_id, Capability.OUTCOME_SUBMIT,
    )


@app.post("/v1/incumbent-outcomes", response_model=OutcomeSubmission)
def submit_incumbent_outcome(
    record: IncumbentOutcomeRecord,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> OutcomeSubmission:
    """Same fail-closed boundary for incumbent-control outcome evidence."""
    _reject_untransactional_outcome(
        request, principal, record.tenant_id, record.event_id,
        Capability.INCUMBENT_OUTCOME_SUBMIT,
    )
