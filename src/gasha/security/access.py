"""Provider-neutral authentication and tenant/action authorization contracts.

This module does not implement a bank IdP. A trusted deployment must inject a
credential verifier, an append-only audit sink and a server-side policy provider.
No header, JSON claim or frontend role is accepted as a principal by itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Protocol


class Capability(StrEnum):
    DECISION_SUBMIT = "decision.submit"
    OUTCOME_SUBMIT = "outcome.submit"
    INCUMBENT_OUTCOME_SUBMIT = "incumbent_outcome.submit"
    DECISION_READ = "decision.read"
    ANALYST_DISPOSITION = "analyst.disposition"
    POLICY_ADMIN = "policy.admin"
    EVIDENCE_CREATE = "evidence.create"
    EVIDENCE_VERIFY = "evidence.verify"
    EVIDENCE_APPROVE = "evidence.approve"
    EVIDENCE_REVOKE = "evidence.revoke"


@dataclass(frozen=True, slots=True)
class TrustedPrincipal:
    """Trusted output of a bank-approved verifier, never constructed from request JSON."""

    subject: str
    issuer: str
    credential_ref: str
    tenant_ids: frozenset[str]
    capabilities: frozenset[Capability]
    expires_at: datetime

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (
            self.subject, self.issuer, self.credential_ref,
        )):
            raise ValueError("principal provenance is required")
        if not isinstance(self.tenant_ids, frozenset) or not self.tenant_ids or any(
            not isinstance(tenant, str) or not tenant.strip() for tenant in self.tenant_ids
        ):
            raise ValueError("nonempty trusted tenant scope is required")
        if not isinstance(self.capabilities, frozenset) or any(
            not isinstance(capability, Capability) for capability in self.capabilities
        ):
            raise ValueError("typed immutable capabilities are required")
        if not isinstance(self.expires_at, datetime) or self.expires_at.utcoffset() is None:
            raise ValueError("timezone-aware credential expiry is required")

    @property
    def audit_actor(self) -> str:
        """Non-reversible reference; never records a token or raw subject."""
        return sha256(f"{self.issuer}\0{self.subject}".encode()).hexdigest()


class CredentialRejected(Exception):
    """Verifier rejects invalid, revoked or otherwise untrusted credentials."""


class IdentityUnavailable(Exception):
    """Identity verification cannot be completed; always fail closed."""


class AuthorizationRejected(Exception):
    """Tenant/action rejected; no data mutation may occur."""


class CredentialVerifier(Protocol):
    """Validate cryptography, issuer/audience, rotation and revocation externally."""

    def verify(self, bearer: str) -> TrustedPrincipal: ...


@dataclass(frozen=True, slots=True)
class SecurityAuditEvent:
    action: str
    result: str
    actor_ref: str
    tenant_ref: str
    reason: str
    at: datetime


class SecurityAuditSink(Protocol):
    """Must be append-only and durable for bank use."""

    def append(self, event: SecurityAuditEvent) -> None: ...


def authenticate(
    bearer_header: str | None, verifier: CredentialVerifier | None, *, now: datetime
) -> TrustedPrincipal:
    """Reject missing, malformed, expired, revoked or unverifiable identity."""
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise IdentityUnavailable("trusted UTC clock required")
    if bearer_header is None or not bearer_header.startswith("Bearer "):
        raise CredentialRejected("bearer credential required")
    token = bearer_header[len("Bearer "):]
    if not token or token != token.strip() or any(char.isspace() for char in token):
        raise CredentialRejected("malformed bearer credential")
    if verifier is None:
        raise IdentityUnavailable("identity verifier unavailable")
    try:
        principal = verifier.verify(token)
    except CredentialRejected:
        raise
    except Exception as exc:
        raise IdentityUnavailable("identity verifier unavailable") from exc
    if not isinstance(principal, TrustedPrincipal):
        raise IdentityUnavailable("invalid verifier result")
    if principal.expires_at <= now:
        raise CredentialRejected("credential expired")
    return principal


def authorize(
    principal: TrustedPrincipal, *, tenant_id: str, capability: Capability
) -> None:
    """Default deny; tenant mismatch is not evidence of tenant existence."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise AuthorizationRejected("invalid tenant scope")
    if not isinstance(capability, Capability):
        raise AuthorizationRejected("invalid capability")
    if tenant_id not in principal.tenant_ids:
        raise AuthorizationRejected("tenant scope denied")
    if capability not in principal.capabilities:
        raise AuthorizationRejected("capability denied")


def tenant_audit_ref(tenant_id: str) -> str:
    """Hash tenant reference to avoid echoing untrusted request identifiers."""
    return sha256(tenant_id.encode()).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
