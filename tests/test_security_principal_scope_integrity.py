"""#42 regression: forged provider scope containers must never grant tenant RBAC.

All identities are synthetic; no Bank verifier, secrets, or live requests.
"""
from datetime import UTC, datetime, timedelta

import pytest

from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    TrustedPrincipal,
    authorize,
)


def principal(**overrides: object) -> TrustedPrincipal:
    values = {
        "subject": "synthetic-analyst",
        "issuer": "synthetic-provider",
        "credential_ref": "synthetic-credential",
        "tenant_ids": frozenset({"fictional-a"}),
        "capabilities": frozenset({Capability.CASE_READ}),
        "expires_at": datetime(2026, 11, 6, tzinfo=UTC) + timedelta(days=1),
    }
    values.update(overrides)
    return TrustedPrincipal(**values)  # type: ignore[arg-type]


class _FalseTenantSet(frozenset[str]):
    def __contains__(self, value: object) -> bool:
        raise AssertionError("untrusted container membership executed")

    def __iter__(self):  # type: ignore[no-untyped-def]
        raise AssertionError("untrusted scope iteration executed")


class _FalseCapabilitySet(frozenset[Capability]):
    def __contains__(self, value: object) -> bool:
        raise AssertionError("untrusted capability membership executed")

    def __iter__(self):  # type: ignore[no-untyped-def]
        raise AssertionError("untrusted capability iteration executed")


class _ForeignEqualTenant(str):
    def __hash__(self) -> int:
        return hash("fictional-b")

    def __eq__(self, other: object) -> bool:
        raise AssertionError("forged tenant equality executed")


class _CallbackText(str):
    def strip(self, chars: str | None = None) -> str:
        raise AssertionError("untrusted principal field callback executed")


@pytest.mark.parametrize("field", ["subject", "issuer", "credential_ref"])
def test_constructor_rejects_subclassed_provenance_without_callback(field: str) -> None:
    with pytest.raises(ValueError, match="principal provenance"):
        principal(**{field: _CallbackText("synthetic")})


def test_constructor_rejects_forged_scopes_before_iteration() -> None:
    with pytest.raises(ValueError, match="tenant scope"):
        principal(tenant_ids=_FalseTenantSet({"fictional-a"}))
    with pytest.raises(ValueError, match="capabilities"):
        principal(capabilities=_FalseCapabilitySet({Capability.CASE_READ}))
    with pytest.raises(ValueError, match="tenant scope"):
        principal(tenant_ids=frozenset({_CallbackText("fictional-a")}))


def test_mutated_principal_cannot_use_custom_contains_for_foreign_tenant() -> None:
    actor = principal()
    object.__setattr__(actor, "tenant_ids", _FalseTenantSet({"fictional-a"}))
    with pytest.raises(AuthorizationRejected, match="invalid principal scope"):
        authorize(actor, tenant_id="fictional-b", capability=Capability.CASE_READ)


def test_mutated_principal_cannot_use_custom_equality_for_foreign_tenant() -> None:
    actor = principal()
    object.__setattr__(actor, "tenant_ids", frozenset({_ForeignEqualTenant("fictional-a")}))
    with pytest.raises(AuthorizationRejected, match="invalid principal scope"):
        authorize(actor, tenant_id="fictional-b", capability=Capability.CASE_READ)


def test_mutated_capability_container_cannot_bypass_permission() -> None:
    actor = principal(capabilities=frozenset())
    object.__setattr__(
        actor, "capabilities", _FalseCapabilitySet({Capability.CASE_READ}),
    )
    with pytest.raises(AuthorizationRejected, match="invalid principal scope"):
        authorize(actor, tenant_id="fictional-a", capability=Capability.CASE_READ)


def test_callback_subclass_selector_rejected_before_membership() -> None:
    with pytest.raises(AuthorizationRejected, match="invalid tenant scope"):
        authorize(
            principal(), tenant_id=_CallbackText("fictional-a"),
            capability=Capability.CASE_READ,
        )


def test_standard_exact_scope_still_authorizes_only_its_own_tenant() -> None:
    actor = principal()
    authorize(actor, tenant_id="fictional-a", capability=Capability.CASE_READ)
    with pytest.raises(AuthorizationRejected, match="tenant scope denied"):
        authorize(actor, tenant_id="fictional-b", capability=Capability.CASE_READ)
    with pytest.raises(AuthorizationRejected, match="capability denied"):
        authorize(actor, tenant_id="fictional-a", capability=Capability.CASE_TRIAGE)
