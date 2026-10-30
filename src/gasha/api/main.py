"""Bank-facing API boundary. All non-health operations fail closed without trusted wiring.

The synthetic scoring interface lives in gasha.api.synthetic and MUST NOT be
deployed in bank environments. No caller policy, score, role or mode is trusted
by this app. This is a bounded #42 foundation, not bank deployment approval.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from typing import Annotated, Protocol
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

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
    OutcomeIngestionService,
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
            or not isinstance(signal_source_version, str)
            or not signal_source_version.strip()
            or not isinstance(signal_version, str)
            or not signal_version.strip()
            or not isinstance(collected_at, datetime)
            or collected_at.utcoffset() is None
            or not isinstance(expires_at, datetime)
            or expires_at.utcoffset() is None
            or expires_at <= collected_at
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
        """Stable digest of server-provided signal and policy provenance."""
        return sha256(
            ("\0".join((
                self.tenant_id,
                str(self.event_id),
                self.signal_source_version,
                self.signal_version,
                self._signal_digest,
                self._policy_snapshot,
            ))).encode()
        ).hexdigest()


class TrustedDecisionContextProvider(Protocol):
    """Bank-approved adapter resolves policy/signals without using request assertions."""

    def resolve(
        self, transaction: CanonicalTransaction, principal: TrustedPrincipal
    ) -> TrustedDecisionContext: ...


class TrustedDecisionRequest(BaseModel):
    """Only transaction facts are accepted; policy, risk and mode are forbidden."""

    model_config = ConfigDict(extra="forbid")
    transaction: CanonicalTransaction


app = FastAPI(title="Gasha Protected Fraud Decision API", version="0.3.0")
# These are intentionally absent until bank-approved wiring is supplied.
app.state.identity_verifier = None
app.state.security_audit = None
app.state.decision_context_provider = None
app.state.outcome_ingestion = None


@app.middleware("http")
async def assign_attempt_ref(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    # Do not accept request-supplied correlation/role headers as audit authority.
    request.state.attempt_ref = uuid4().hex
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
    now = utcnow()
    if (
        not isinstance(context, TrustedDecisionContext)
        or context.tenant_id != tx.tenant_id
        or context.event_id != tx.event_id
        or context.collected_at > now
        or context.expires_at <= now
    ):
        raise HTTPException(status_code=503, detail="trusted decision context unavailable")
    return context


def get_outcome_ingestion(request: Request) -> OutcomeIngestionService:
    service = getattr(request.app.state, "outcome_ingestion", None)
    if not isinstance(service, OutcomeIngestionService):
        raise HTTPException(status_code=503, detail="outcome store unavailable")
    return service


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
        "outcome_ingestion": isinstance(
            getattr(request.app.state, "outcome_ingestion", None), OutcomeIngestionService
        ),
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
    return decision


@app.post("/v1/evaluations", response_model=DecisionEnvelope)
def create_evaluation(
    payload: TrustedDecisionRequest,
    request: Request,
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
    return result


@app.post("/v1/outcomes", response_model=OutcomeSubmission)
def submit_outcome(
    record: OutcomeRecord,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
    service: Annotated[OutcomeIngestionService, Depends(get_outcome_ingestion)],
) -> OutcomeSubmission:
    action = Capability.OUTCOME_SUBMIT
    _require_action(request, principal, record.tenant_id, action, event_id=record.event_id)
    try:
        result = service.submit(record)
    except Exception as exc:
        _operation_audit(
            request, principal, record.tenant_id, record.event_id,
            action, "failed", "outcome_store_unavailable",
        )
        raise HTTPException(status_code=503, detail="outcome store unavailable") from exc
    _operation_audit(
        request, principal, record.tenant_id, record.event_id,
        action, "succeeded", "outcome_submitted",
    )
    return result


@app.post("/v1/incumbent-outcomes", response_model=OutcomeSubmission)
def submit_incumbent_outcome(
    record: IncumbentOutcomeRecord,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
    service: Annotated[OutcomeIngestionService, Depends(get_outcome_ingestion)],
) -> OutcomeSubmission:
    action = Capability.INCUMBENT_OUTCOME_SUBMIT
    _require_action(request, principal, record.tenant_id, action, event_id=record.event_id)
    try:
        result = service.submit_incumbent(record)
    except Exception as exc:
        _operation_audit(
            request, principal, record.tenant_id, record.event_id,
            action, "failed", "outcome_store_unavailable",
        )
        raise HTTPException(status_code=503, detail="outcome store unavailable") from exc
    _operation_audit(
        request, principal, record.tenant_id, record.event_id,
        action, "succeeded", "incumbent_outcome_submitted",
    )
    return result
