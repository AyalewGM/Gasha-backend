"""#42 trusted identity/capability seam; synthetic identities only."""
from datetime import datetime, timedelta, timezone

import pytest

from gasha.security.access import (
    AuthorizationRejected, Capability, CredentialRejected, IdentityUnavailable,
    TrustedPrincipal, authenticate, authorize, tenant_audit_ref,
)

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


def principal(**changes: object) -> TrustedPrincipal:
    values = {
        "subject": "synthetic-service-a", "issuer": "synthetic-verifier",
        "credential_ref": "synthetic-key-v1",
        "tenant_ids": frozenset({"tenant-a"}),
        "capabilities": frozenset({Capability.DECISION_SUBMIT, Capability.OUTCOME_SUBMIT}),
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return TrustedPrincipal(**values)  # type: ignore[arg-type]


class Verifier:
    def __init__(self, result: TrustedPrincipal | Exception) -> None:
        self.result = result

    def verify(self, bearer: str) -> TrustedPrincipal:
        assert bearer != ""
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_authorized_issued_credential_and_capability() -> None:
    identity = authenticate("Bearer synthetic-token", Verifier(principal()), now=NOW)
    authorize(identity, tenant_id="tenant-a", capability=Capability.DECISION_SUBMIT)
    assert len(identity.audit_actor) == 64
    assert "synthetic-service-a" not in identity.audit_actor
    assert tenant_audit_ref("tenant-a") != tenant_audit_ref("tenant-b")


@pytest.mark.parametrize("header", [None, "", "Basic token", "Bearer ", "Bearer a b", "Bearer  token"])
def test_missing_or_malformed_credentials_fail_closed(header: str | None) -> None:
    with pytest.raises(CredentialRejected):
        authenticate(header, Verifier(principal()), now=NOW)


@pytest.mark.parametrize("error", [CredentialRejected(), RuntimeError("offline")])
def test_revocation_or_provider_failure_fails_closed(error: Exception) -> None:
    expected = CredentialRejected if isinstance(error, CredentialRejected) else IdentityUnavailable
    with pytest.raises(expected):
        authenticate("Bearer synthetic", Verifier(error), now=NOW)


def test_missing_verifier_and_expired_credential_fail_closed() -> None:
    with pytest.raises(IdentityUnavailable):
        authenticate("Bearer token", None, now=NOW)
    with pytest.raises(CredentialRejected):
        authenticate("Bearer token", Verifier(principal(expires_at=NOW)), now=NOW)


@pytest.mark.parametrize(("tenant", "capability"), [
    ("tenant-b", Capability.DECISION_SUBMIT),
    ("tenant-a", Capability.POLICY_ADMIN),
    ("tenant-a", Capability.EVIDENCE_APPROVE),
    ("", Capability.DECISION_SUBMIT),
])
def test_tenant_and_least_privilege_denials(tenant: str, capability: Capability) -> None:
    with pytest.raises(AuthorizationRejected):
        authorize(principal(), tenant_id=tenant, capability=capability)


@pytest.mark.parametrize("scope", [frozenset(), frozenset({""}), {"tenant-a"}])
def test_principal_scope_cannot_be_empty_or_mutable(scope: object) -> None:
    with pytest.raises(ValueError):
        principal(tenant_ids=scope)


def test_untyped_capability_and_naive_expiry_rejected() -> None:
    with pytest.raises(ValueError):
        principal(capabilities=frozenset({"policy.admin"}))
    with pytest.raises(ValueError):
        principal(expires_at=NOW.replace(tzinfo=None))
