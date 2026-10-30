"""Bank-facing API boundary. All non-health operations fail closed without trusted wiring.

The synthetic scoring interface lives in gasha.api.synthetic and MUST NOT be
deployed in bank environments. No caller policy, score, role or mode is trusted
by this app. This is a bounded #42 foundation, not bank deployment approval.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Protocol

from fastapi import Depends, FastAPI, Header, HTTPException, Request
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


@dataclass(frozen=True, slots=True)
class TrustedDecisionContext:
    """Server-assembled, tenant-bound policy and signals with version provenance."""

    tenant_id: str
    policy: DecisionPolicy
    intelligence: IntelligenceSnapshot


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


def _audit(
    request: Request,
    action: str,
    result: str,
    actor_ref: str,
    tenant_id: str,
    reason: str,
) -> None:
    sink: SecurityAuditSink | None = getattr(request.app.state, "security_audit", None)
    if sink is None:
        raise HTTPException(status_code=503, detail="security audit unavailable")
    try:
        sink.append(
            SecurityAuditEvent(
                action=action,
                result=result,
                actor_ref=actor_ref,
                tenant_ref=tenant_audit_ref(tenant_id),
                reason=reason,
                at=utcnow(),
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
    _audit(request, "authenticate", "accepted", principal.audit_actor, "", "verified")
    return principal


def _require_action(
    request: Request,
    principal: TrustedPrincipal,
    tenant_id: str,
    capability: Capability,
) -> None:
    try:
        authorize(principal, tenant_id=tenant_id, capability=capability)
    except AuthorizationRejected as exc:
        _audit(
            request, capability.value, "denied", principal.audit_actor, tenant_id,
            "authorization_denied",
        )
        status = 404 if tenant_id not in principal.tenant_ids else 403
        raise HTTPException(status_code=status, detail="not authorized") from exc
    _audit(request, capability.value, "accepted", principal.audit_actor, tenant_id, "allowed")


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
    if (
        not isinstance(context, TrustedDecisionContext)
        or context.tenant_id != tx.tenant_id
        or not isinstance(context.policy, DecisionPolicy)
        or not isinstance(context.intelligence, IntelligenceSnapshot)
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
def readiness(request: Request) -> dict[str, object]:
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
    return {
        "status": "ready" if all(checks.values()) else "not_ready",
        "checks": checks,
    }


@app.post("/v1/decisions", response_model=FraudDecision)
def create_decision(
    payload: TrustedDecisionRequest,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> FraudDecision:
    tx = payload.transaction
    _require_action(request, principal, tx.tenant_id, Capability.DECISION_SUBMIT)
    context = _trusted_context(request, tx, principal)
    # A decision is a recommendation, not proof of a bank-executed block.
    return DecisionService(context.policy).decide(tx, context.intelligence)


@app.post("/v1/evaluations", response_model=DecisionEnvelope)
def create_evaluation(
    payload: TrustedDecisionRequest,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
) -> DecisionEnvelope:
    tx = payload.transaction
    _require_action(request, principal, tx.tenant_id, Capability.DECISION_SUBMIT)
    context = _trusted_context(request, tx, principal)
    # #41: No caller-selected enforcing mode; SHADOW has no intervention effect.
    return ModeAwareDecisionService(
        context.policy, operating_mode=OperatingMode.SHADOW
    ).decide(tx, context.intelligence)


@app.post("/v1/outcomes", response_model=OutcomeSubmission)
def submit_outcome(
    record: OutcomeRecord,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
    service: Annotated[OutcomeIngestionService, Depends(get_outcome_ingestion)],
) -> OutcomeSubmission:
    _require_action(request, principal, record.tenant_id, Capability.OUTCOME_SUBMIT)
    return service.submit(record)


@app.post("/v1/incumbent-outcomes", response_model=OutcomeSubmission)
def submit_incumbent_outcome(
    record: IncumbentOutcomeRecord,
    request: Request,
    principal: Annotated[TrustedPrincipal, Depends(get_principal)],
    service: Annotated[OutcomeIngestionService, Depends(get_outcome_ingestion)],
) -> OutcomeSubmission:
    _require_action(
        request, principal, record.tenant_id, Capability.INCUMBENT_OUTCOME_SUBMIT
    )
    return service.submit_incumbent(record)
