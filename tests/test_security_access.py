"""#42 trusted identity/capability seam; synthetic identities only."""
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo

import pytest

from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    CredentialRejected,
    IdentityUnavailable,
    TrustedPrincipal,
    authenticate,
    authorize,
    tenant_audit_ref,
)

NOW = datetime(2026, 10, 30, tzinfo=UTC)


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


# The two local 01:xx hours on 2026-11-01 are distinct UTC instants.
_NY = ZoneInfo("America/New_York")


@pytest.mark.parametrize(
    ("expires_at", "now", "should_reject"),
    [
        # Expired in actual time, although the later wall clock looks earlier.
        (datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=0),
         datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1), True),
        # Valid in actual time, although the earlier wall clock looks later.
        (datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=1),
         datetime(2026, 11, 1, 1, 45, tzinfo=_NY, fold=0), False),
        # Equality must reject even when the clock uses a different timezone.
        (datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=0),
         datetime(2026, 11, 1, 8, 30, tzinfo=timezone(timedelta(hours=3))), True),
        (datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=1),
         datetime(2026, 11, 1, 6, 29, 59, tzinfo=UTC), False),
        (datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=1),
         datetime(2026, 11, 1, 6, 30, tzinfo=UTC), True),
    ],
)
def test_authenticate_credential_expiry_dst_fold(
    expires_at: datetime, now: datetime, should_reject: bool,
) -> None:
    trusted = principal(expires_at=expires_at)
    verifier = Verifier(trusted)
    if should_reject:
        with pytest.raises(CredentialRejected, match="credential expired"):
            authenticate("Bearer synthetic-token", verifier, now=now)
    else:
        assert authenticate("Bearer synthetic-token", verifier, now=now) is trusted


class _CallbackTimezone(tzinfo):
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self.calls.append("utcoffset")
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta:
        self.calls.append("dst")
        return timedelta(0)


def test_principal_constructor_rejects_custom_timezone_before_callback() -> None:
    calls: list[str] = []
    hostile = datetime(2026, 11, 5, tzinfo=_CallbackTimezone(calls))
    with pytest.raises(ValueError, match="credential expiry"):
        principal(expires_at=hostile)
    assert calls == []


def test_principal_constructor_rejects_datetime_subclass_before_callback() -> None:
    calls: list[str] = []

    class CallbackDatetime(datetime):
        def utcoffset(self) -> timedelta:
            calls.append("utcoffset")
            return timedelta(0)

        def astimezone(self, tz=None):  # type: ignore[no-untyped-def]
            calls.append("astimezone")
            return super().astimezone(tz)

    hostile = CallbackDatetime(2026, 11, 5, tzinfo=UTC)
    with pytest.raises(ValueError, match="credential expiry"):
        principal(expires_at=hostile)
    assert calls == []


def test_authenticate_rejects_custom_clock_before_verifier_or_callback() -> None:
    calls: list[str] = []
    hostile = datetime(2026, 11, 5, tzinfo=_CallbackTimezone(calls))

    class UnexpectedVerifier:
        def verify(self, bearer: str) -> TrustedPrincipal:
            pytest.fail("verifier must not be reached with an unsafe clock")

    with pytest.raises(IdentityUnavailable, match="trusted UTC clock"):
        authenticate("Bearer synthetic", UnexpectedVerifier(), now=hostile)
    assert calls == []


@pytest.mark.parametrize("corruption", ["custom_timezone", "datetime_subclass", "missing"])
def test_authenticate_revalidates_mutated_principal_expiry_before_callback(
    corruption: str,
) -> None:
    calls: list[str] = []
    trusted = principal()
    if corruption == "custom_timezone":
        object.__setattr__(
            trusted, "expires_at", datetime(2026, 11, 5, tzinfo=_CallbackTimezone(calls))
        )
    elif corruption == "datetime_subclass":
        class CallbackDatetime(datetime):
            def astimezone(self, tz=None):  # type: ignore[no-untyped-def]
                calls.append("astimezone")
                return super().astimezone(tz)
        object.__setattr__(trusted, "expires_at", CallbackDatetime(2026, 11, 5, tzinfo=UTC))
    else:
        object.__delattr__(trusted, "expires_at")
    with pytest.raises(IdentityUnavailable, match="invalid verifier"):
        authenticate("Bearer synthetic", Verifier(trusted), now=NOW)
    assert calls == []


class _ForgedDatetimeClass:
    """Non-datetime object that executes a getter when isinstance checks __class__."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    @property
    def __class__(self) -> type[datetime]:
        self.calls.append("__class__")
        return datetime


def test_principal_constructor_rejects_forged_datetime_class_without_getter() -> None:
    calls: list[str] = []
    forged = _ForgedDatetimeClass(calls)
    with pytest.raises(ValueError, match="credential expiry"):
        principal(expires_at=forged)
    assert calls == []


def test_authenticate_rejects_forged_now_before_verifier_or_getter() -> None:
    calls: list[str] = []
    forged = _ForgedDatetimeClass(calls)

    class UnexpectedVerifier:
        def verify(self, bearer: str) -> TrustedPrincipal:
            pytest.fail("unsafe clock must be denied before verifier invocation")

    with pytest.raises(IdentityUnavailable, match="trusted UTC clock"):
        authenticate("Bearer synthetic", UnexpectedVerifier(), now=forged)  # type: ignore[arg-type]
    assert calls == []


def test_authenticate_rejects_forged_mutated_expiry_without_getter() -> None:
    calls: list[str] = []
    trusted = principal()
    object.__setattr__(trusted, "expires_at", _ForgedDatetimeClass(calls))
    with pytest.raises(IdentityUnavailable, match="invalid verifier expiry"):
        authenticate("Bearer synthetic", Verifier(trusted), now=NOW)
    assert calls == []
