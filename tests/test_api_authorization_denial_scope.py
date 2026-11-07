"""Issue #42: authorization denials cannot re-enter forged tenant callbacks.

All principals and tenants are fictional. The protected HTTP path stays
unwired for Bank credentials, ranking, database writes and enforcement.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.security.access import Capability, SecurityAuditEvent, TrustedPrincipal


class HostileTenantScope(frozenset[str]):
    def __contains__(self, value: object) -> bool:
        raise AssertionError("forged scope membership callback invoked")

    def __iter__(self):  # type: ignore[no-untyped-def]
        raise AssertionError("forged scope iterator invoked")


class HostileCapabilityScope(frozenset[Capability]):
    def __contains__(self, value: object) -> bool:
        raise AssertionError("forged capability callback invoked")

    def __iter__(self):  # type: ignore[no-untyped-def]
        raise AssertionError("forged capability iterator invoked")


class ForeignEqualTenant(str):
    def __hash__(self) -> int:
        return hash("fictional-a")

    def __eq__(self, other: object) -> bool:
        raise AssertionError("forged tenant equality callback invoked")


class Verifier:
    def __init__(self, actor: TrustedPrincipal) -> None:
        self.actor = actor

    def verify(self, bearer: str) -> TrustedPrincipal:
        assert bearer == "synthetic"
        return self.actor


class Audit:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    def append(self, record: SecurityAuditEvent) -> None:
        self.events.append(record)


class Reader:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, **kwargs: object) -> None:
        self.calls += 1
        raise AssertionError("unauthorized reader invoked")


def actor(*, tenant: str = "fictional-a", read: bool = True) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-actor-secret",
        issuer="synthetic-verifier-secret",
        credential_ref="synthetic-credential-secret",
        tenant_ids=frozenset({tenant}),
        capabilities=frozenset({Capability.CASE_READ} if read else set()),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def request(actor_value: TrustedPrincipal, tenant: str) -> tuple[int, dict[str, str], Audit, Reader]:
    keys = ("identity_verifier", "security_audit", "case_queue_reader")
    saved = tuple(getattr(app.state, key) for key in keys)
    audit, reader = Audit(), Reader()
    app.state.identity_verifier = Verifier(actor_value)
    app.state.security_audit = audit
    app.state.case_queue_reader = reader
    try:
        with TestClient(app) as client:
            response = client.get(
                f"/v1/tenants/{tenant}/cases/queue",
                headers={"Authorization": "Bearer synthetic"},
            )
            return response.status_code, response.json(), audit, reader
    finally:
        for key, value in zip(keys, saved, strict=True):
            setattr(app.state, key, value)


@pytest.mark.parametrize("tamper", [
    "subclassed-tenant-scope",
    "foreign-equal-tenant",
    "missing-tenant-scope",
    "subclassed-capabilities",
    "invalid-tenant-element",
])
def test_mutated_verifier_principal_denied_without_callback_or_reader(tamper: str) -> None:
    principal = actor()
    if tamper == "subclassed-tenant-scope":
        object.__setattr__(principal, "tenant_ids", HostileTenantScope({"fictional-a"}))
    elif tamper == "foreign-equal-tenant":
        object.__setattr__(principal, "tenant_ids", frozenset({ForeignEqualTenant("foreign")}))
    elif tamper == "missing-tenant-scope":
        object.__setattr__(principal, "tenant_ids", None)
    elif tamper == "subclassed-capabilities":
        object.__setattr__(
            principal, "capabilities",
            HostileCapabilityScope({Capability.CASE_READ}),
        )
    else:
        object.__setattr__(principal, "tenant_ids", frozenset({ForeignEqualTenant("fictional-a")}))

    status, payload, audit, reader = request(principal, "fictional-a")
    assert status == 403
    assert payload == {"detail": "not authorized"}
    assert reader.calls == 0
    assert audit.events[-1].action == Capability.CASE_READ.value
    assert audit.events[-1].result == "denied"
    assert audit.events[-1].reason == "authorization_denied"
    assert not any(event.result == "authorized" for event in audit.events)
    assert "fictional-a" not in str(audit.events)
    assert "synthetic-actor-secret" not in str(audit.events)
    assert "synthetic-credential-secret" not in str(audit.events)


@pytest.mark.parametrize(("principal", "tenant", "expected"), [
    (actor(tenant="fictional-b"), "fictional-a", 404),
    (actor(read=False), "fictional-a", 403),
])
def test_valid_scopes_preserve_cross_tenant_concealment_and_capability_denial(
    principal: TrustedPrincipal, tenant: str, expected: int,
) -> None:
    status, payload, audit, reader = request(principal, tenant)
    assert status == expected
    assert payload == {"detail": "not authorized"}
    assert reader.calls == 0
    assert audit.events[-1].reason == "authorization_denied"
