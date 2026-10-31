"""Regression for provider-neutral, unambiguous pseudonymous audit identity (#42)."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from gasha.security.access import Capability, TrustedPrincipal


def _principal(issuer: str, subject: str) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject=subject,
        issuer=issuer,
        credential_ref="synthetic-credential-v1",
        tenant_ids=frozenset({"synthetic-tenant"}),
        capabilities=frozenset({Capability.DECISION_SUBMIT}),
        expires_at=datetime(2030, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("issuer_a", "subject_a", "issuer_b", "subject_b"),
    [
        ("bank\x00app", "user", "bank", "app\x00user"),
        ("bank\x00a\x00b", "user", "bank\x00a", "b\x00user"),
        ("bank\x00x", "subject", "bank", "x\x00subject"),
        ("issuer\nservice", "subject", "issuer", "service\nsubject"),
    ],
)
def test_distinct_issuer_subject_tuples_cannot_share_actor_reference(
    issuer_a: str, subject_a: str, issuer_b: str, subject_b: str
) -> None:
    left = _principal(issuer_a, subject_a)
    right = _principal(issuer_b, subject_b)
    # The old NUL-delimited encoding could collapse these distinct tuples.
    assert (left.issuer, left.subject) != (right.issuer, right.subject)
    assert left.audit_actor != right.audit_actor
    assert len(left.audit_actor) == len(right.audit_actor) == 64
    assert left.audit_actor == _principal(issuer_a, subject_a).audit_actor


def test_audit_actor_stable_across_token_rotation_scope_and_expiration() -> None:
    original = _principal("synthetic-issuer", "synthetic-subject")
    rotated = replace(
        original,
        credential_ref="synthetic-credential-v2",
        expires_at=original.expires_at + timedelta(days=1),
        tenant_ids=frozenset({"synthetic-other-tenant"}),
        capabilities=frozenset({Capability.DECISION_READ}),
    )
    assert rotated.audit_actor == original.audit_actor
    assert replace(original, issuer="other-issuer").audit_actor != original.audit_actor
    assert replace(original, subject="other-subject").audit_actor != original.audit_actor


def test_actor_reference_is_redacted_and_domain_separated() -> None:
    original = _principal("private-synthetic-issuer", "private-synthetic-subject")
    assert original.issuer not in original.audit_actor
    assert original.subject not in original.audit_actor
    assert original.credential_ref not in original.audit_actor
    assert original.audit_actor != _principal("gasha-audit-actor-v2", "private-synthetic-subject").audit_actor
