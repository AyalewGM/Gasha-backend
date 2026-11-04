"""#42/#45 opt-in protected analyst transition ingress: synthetic adapter only.

The app never installs this writer. These tests prove the HTTP trust boundary,
not a Bank principal, PostgreSQL role grant or atomic installed deployment.
"""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app, get_principal
from gasha.cases.timeline import (
    AuthorizedAssignee,
    BankExecution,
    CaseDisposition,
    CaseCommand,
    CaseEvent,
    CaseOperation,
    VerifiedEvaluation,
    advance_case,
)
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    CredentialRejected,
    TrustedPrincipal,
)

CASE = uuid4()
SOURCE = uuid4()
ASSIGNEE = uuid4()
NOW = datetime.now(UTC)
CAPS = frozenset({
    Capability.CASE_CREATE, Capability.CASE_TRIAGE, Capability.CASE_ASSIGN,
    Capability.CASE_DISPOSITION, Capability.CASE_CORRECT, Capability.CASE_FEEDBACK,
})


def identity(*, tenant="tenant-a", caps=CAPS, expires=None):
    return TrustedPrincipal(
        subject="synthetic-analyst", issuer="synthetic-only",
        credential_ref="synthetic-credential", tenant_ids=frozenset({tenant}),
        capabilities=caps,
        expires_at=expires if expires is not None else NOW + timedelta(hours=1),
    )


class Verifier:
    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer == "valid":
            return identity()
        if bearer == "read-only":
            return identity(caps=frozenset({Capability.CASE_READ}))
        if bearer == "no-assign":
            return identity(caps=CAPS - {Capability.CASE_ASSIGN})
        if bearer == "wrong-tenant":
            return identity(tenant="tenant-b")
        if bearer == "expired":
            return identity(expires=NOW - timedelta(seconds=1))
        if bearer == "outage":
            raise RuntimeError("synthetic identity outage")
        raise CredentialRejected("revoked or invalid")


class Audit:
    def __init__(self):
        self.events = []
        self.fail = False

    def append(self, event):
        if self.fail:
            raise RuntimeError("synthetic audit outage")
        self.events.append(event)


class SourceLookup:
    def resolve(self, tenant_id: str, event_id: UUID) -> VerifiedEvaluation:
        if tenant_id != "tenant-a" or event_id != SOURCE:
            raise RuntimeError("source not found")
        return VerifiedEvaluation("tenant-a", SOURCE, "c" * 64)


class SyntheticAtomicWriter:
    """An in-memory *test double*, not an authorized Bank case writer."""

    def __init__(self):
        self.history: dict[UUID, tuple[CaseEvent, ...]] = {}
        self.calls = 0
        self.fail = False
        self.forge: str | None = None

    def apply(self, *, principal, tenant_id, case_id, operation, proposal, at):
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic store outage")
        assignee = None
        if proposal.assignee_selector is not None:
            if proposal.assignee_selector != ASSIGNEE:
                raise AuthorizationRejected("assignee not tenant-authorized")
            assignee = AuthorizedAssignee(tenant_id, "a" * 64)
        command = CaseCommand(
            tenant_id=tenant_id, case_id=case_id,
            source_event_id=proposal.source_event_id,
            operation=operation, expected_revision=proposal.expected_revision,
            idempotency_key=proposal.idempotency_key,
            reason_code=proposal.reason_code,
            disposition=proposal.disposition,
            assignee=assignee,
        )
        original = self.history.get(case_id, ())
        history, event = advance_case(
            original, command, principal=principal, source=SourceLookup(), at=at,
        )
        if self.forge == "tenant":
            return replace(event, tenant_id="tenant-b")
        if self.forge == "execution":
            return replace(event, bank_execution="executed")
        if self.forge == "revision":
            return replace(event, revision=999)
        if self.forge == "missing_clock":
            object.__delattr__(event, "recorded_at")
            return event
        if self.forge == "missing_context":
            object.__delattr__(event, "source_context_ref")
            return event
        if self.forge is not None:
            mutation = {
                "context": {"source_context_ref": "BAD"},
                "previous_revision": {"previous_revision": 999},
                "boolean_revision": {"revision": True},
                "actor": {"actor_ref": "invalid"},
                "idempotency": {"idempotency_ref": "not-hex"},
                "command": {"command_ref": "not-hex"},
                "wrong_key_digest": {"idempotency_ref": "d" * 64},
                "wrong_command_digest": {"command_ref": "d" * 64},
                "naive_clock": {"recorded_at": datetime(2026, 11, 4)},
                "wrong_clock_type": {"recorded_at": "2026-11-04T00:00:00Z"},
                "assignee_on_create": {"assignee_ref": "a" * 64},
                "disposition_on_create": {"disposition": CaseDisposition.FRAUD},
                "operation_type": {"operation": "create"},
                "source_type": {"source_event_id": str(SOURCE)},
            }[self.forge]
            return replace(event, **mutation)
        self.history[case_id] = history
        return event


@pytest.fixture
def wired():
    names = ("identity_verifier", "security_audit", "case_transition_writer")
    saved = tuple(getattr(app.state, name) for name in names)
    audit, writer = Audit(), SyntheticAtomicWriter()
    app.state.identity_verifier = Verifier()
    app.state.security_audit = audit
    app.state.case_transition_writer = writer
    try:
        yield TestClient(app), audit, writer
    finally:
        for name, value in zip(names, saved, strict=True):
            setattr(app.state, name, value)


def url(op: str, *, tenant="tenant-a", case_id=CASE):
    return f"/v1/tenants/{tenant}/cases/{case_id}/transitions/{op}"


def token(value="valid"):
    return {"Authorization": f"Bearer {value}"}


def body(reason="source_evaluation", *, rev=0, source=SOURCE, disposition=None,
         assignee=None, key=None):
    result = {
        "source_event_id": str(source), "expected_revision": rev,
        "idempotency_key": key if key is not None else uuid4().hex,
        "reason_code": reason,
    }
    if disposition is not None:
        result["disposition"] = disposition
    if assignee is not None:
        result["assignee_selector"] = str(assignee)
    return result


def test_synthetic_six_step_http_lifecycle_is_tenant_scoped_and_nonexecuting(wired):
    client, audit, writer = wired
    transitions = (
        ("create", body()),
        ("triage", body("analyst_triage", rev=1)),
        ("assign", body("investigation_assigned", rev=2, assignee=ASSIGNEE)),
        ("dispose", body("fraud_evidence", rev=3, disposition="confirmed_fraud")),
        ("correct", body("corrected_finding", rev=4, disposition="confirmed_legitimate")),
        ("reconcile", body("feedback_reconciled", rev=5)),
    )
    for revision, (op, payload) in enumerate(transitions, start=1):
        result = client.post(url(op), json=payload, headers=token())
        assert result.status_code == 200, result.text
        assert result.json() == {
            "case_id": str(CASE), "source_event_id": str(SOURCE),
            "revision": revision, "operation": op,
            "disposition": payload.get("disposition"),
            "bank_execution": "unknown", "enforcement_activated": False,
        }
    assert len(writer.history[CASE]) == 6
    assert [event.operation for event in writer.history[CASE]] == list(CaseOperation)
    assert all(event.bank_execution is BankExecution.UNKNOWN
               for event in writer.history[CASE])
    assert all(event.actor_ref == identity().audit_actor for event in writer.history[CASE])
    assert len([e for e in audit.events if e.result == "authorized"]) == 6
    # The test double does not claim a durable terminal audit. The API must not
    # append an out-of-transaction terminal "succeeded" audit after the write.
    assert not any(e.result == "succeeded" for e in audit.events)


def test_same_request_replay_returns_original_revision_without_extra_event(wired):
    client, _, writer = wired
    payload = body(key="a" * 32)
    assert client.post(url("create"), json=payload, headers=token()).status_code == 200
    response = client.post(url("create"), json=payload, headers=token())
    assert response.status_code == 200 and response.json()["revision"] == 1
    assert len(writer.history[CASE]) == 1
    changed = {**payload, "idempotency_key": "a" * 32, "expected_revision": 1}
    denied = client.post(url("create"), json=changed, headers=token())
    assert denied.status_code == 409
    assert len(writer.history[CASE]) == 1


@pytest.mark.parametrize("value,expected", [
    (None, 401), ("revoked", 401), ("expired", 401),
    ("outage", 503), ("read-only", 403), ("wrong-tenant", 404),
])
def test_credentials_scope_and_role_fail_before_writer(wired, value, expected):
    client, audit, writer = wired
    response = client.post(
        url("create"), json=body(),
        headers={} if value is None else token(value),
    )
    assert response.status_code == expected
    assert writer.calls == 0 and writer.history == {}
    assert any(e.result == "denied" for e in audit.events)


def test_assign_requires_its_own_capability_not_just_analyst_role(wired):
    client, _, writer = wired
    response = client.post(
        url("assign"), json=body("investigation_assigned", rev=2, assignee=ASSIGNEE),
        headers={**token("no-assign"), "X-Role": "admin"},
    )
    assert response.status_code == 403 and writer.calls == 0


@pytest.mark.parametrize("value", [
    {"policy": {"mode": "enforcing"}},
    {"operating_mode": "enforcing"},
    {"tenant_id": "tenant-b"},
    {"principal": "admin"},
    {"assignee_ref": "a" * 64},
    {"bank_execution": "executed"},
    {"expected_revision": True},
    {"idempotency_key": "not-opaque"},
    {"reason_code": "free text"},
])
def test_untrusted_or_malformed_fields_never_reach_writer(wired, value):
    client, _, writer = wired
    assert client.post(url("create"), json={**body(), **value},
                       headers=token()).status_code == 422
    assert writer.calls == 0 and writer.history == {}


@pytest.mark.parametrize("operation,payload", [
    ("assign", body("investigation_assigned")),
    ("triage", body("analyst_triage", assignee=ASSIGNEE)),
    ("create", body("source_evaluation", disposition="confirmed_fraud")),
    ("dispose", body("fraud_evidence", disposition="confirmed_legitimate")),
    ("correct", body("corrected_finding")),
    ("dispose", body("fraud_evidence")),
    ("create", body("analyst_triage")),
])
def test_semantically_invalid_commands_fail_before_writer(wired, operation, payload):
    client, audit, writer = wired
    assert client.post(url(operation), json=payload, headers=token()).status_code == 422
    assert writer.calls == 0
    assert any(e.reason == "invalid_case_transition" for e in audit.events)


def test_invalid_operation_does_not_invoke_writer(wired):
    client, _, writer = wired
    assert client.post(url("promote"), json=body(), headers=token()).status_code == 404
    assert writer.calls == 0


def test_missing_writer_fails_closed_with_redacted_terminal_denial(wired):
    client, audit, writer = wired
    app.state.case_transition_writer = None
    result = client.post(url("create"), json=body(), headers=token())
    assert result.status_code == 503
    assert result.json() == {"detail": "case transition unavailable"}
    assert writer.calls == 0
    assert any(e.reason == "case_transition_unavailable" for e in audit.events)


def test_auth_audit_outage_prevents_writer_side_effects(wired):
    client, audit, writer = wired
    audit.fail = True
    assert client.post(url("create"), json=body(), headers=token()).status_code == 503
    assert writer.calls == 0 and writer.history == {}


def test_writer_failure_is_redacted_and_does_not_claim_success(wired):
    client, audit, writer = wired
    writer.fail = True
    response = client.post(url("create"), json=body(), headers=token())
    assert response.status_code == 503
    assert response.json() == {"detail": "case transition unavailable"}
    assert writer.history == {}
    assert any(e.reason == "case_transition_unavailable" for e in audit.events)


def test_cross_tenant_event_and_unauthorized_assignee_do_not_mutate(wired):
    client, audit, writer = wired
    assert client.post(url("create"), json=body(source=uuid4()),
                       headers=token()).status_code == 503
    assert client.post(
        url("assign"), json=body("investigation_assigned", rev=2, assignee=uuid4()),
        headers=token(),
    ).status_code == 404
    assert writer.history == {}
    assert all("synthetic-analyst" not in repr(e) for e in audit.events)


@pytest.mark.parametrize("forged", [
    "tenant", "execution", "revision", "context", "previous_revision",
    "boolean_revision", "actor", "idempotency", "command",
    "wrong_key_digest", "wrong_command_digest", "naive_clock",
    "wrong_clock_type", "missing_clock", "missing_context",
    "assignee_on_create", "disposition_on_create", "operation_type", "source_type",
])
def test_malformed_writer_response_never_grants_execution_authority(wired, forged):
    client, audit, writer = wired
    writer.forge = forged
    response = client.post(url("create"), json=body(), headers=token())
    assert response.status_code == 503
    assert response.json() == {"detail": "case transition unavailable"}
    assert writer.history == {}
    assert any(e.reason == "case_transition_unavailable" for e in audit.events)


def test_writer_missing_assignee_response_does_not_claim_success(wired):
    client, audit, writer = wired
    assert client.post(url("create"), json=body(), headers=token()).status_code == 200
    assert client.post(
        url("triage"), json=body("analyst_triage", rev=1),
        headers=token(),
    ).status_code == 200
    before = writer.history[CASE]
    original = writer.apply

    def invalid_assignee(**kwargs):
        event = original(**kwargs)
        return replace(event, assignee_ref=None)

    writer.apply = invalid_assignee
    response = client.post(
        url("assign"),
        json=body("investigation_assigned", rev=2, assignee=ASSIGNEE),
        headers=token(),
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "case transition unavailable"}
    # The normal synthetic writer appended before our wrapper changed its
    # response; HTTP validation cannot roll back a writer's side effects.
    assert len(before) == 2
    assert any(e.reason == "case_transition_unavailable" for e in audit.events)


def test_writer_missing_disposition_response_does_not_claim_success(wired):
    client, audit, writer = wired
    for op, payload in (
        ("create", body()),
        ("triage", body("analyst_triage", rev=1)),
        ("assign", body("investigation_assigned", rev=2, assignee=ASSIGNEE)),
    ):
        assert client.post(url(op), json=payload, headers=token()).status_code == 200
    original = writer.apply

    def invalid_disposition(**kwargs):
        event = original(**kwargs)
        return replace(event, disposition=None)

    writer.apply = invalid_disposition
    response = client.post(
        url("dispose"),
        json=body("fraud_evidence", rev=3, disposition="confirmed_fraud"),
        headers=token(),
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "case transition unavailable"}
    assert any(e.reason == "case_transition_unavailable" for e in audit.events)


@pytest.mark.parametrize("root_path,prefixed", [
    ("", False), ("/bank", False), ("/bank", True),
    ("/gateway/bank", True),
])
def test_proxy_prefix_protects_each_case_mutation(wired, root_path, prefixed):
    _, audit, writer = wired
    client = TestClient(app, root_path=root_path)
    prefix = root_path if prefixed else ""
    target = prefix + url("create")
    assert client.post(target, json=body(), headers=token()).status_code == 200
    assert client.post(target, json=body()).status_code == 401
    assert client.post(target, json=body(), headers=token("read-only")).status_code == 403
    assert client.post(
        prefix + url("create", tenant="tenant-b"), json=body(),
        headers={**token(), "X-Tenant-Id": "tenant-b", "X-Role": "admin",
                 "X-Forwarded-Prefix": "/untrusted"},
    ).status_code == 404
    assert writer.calls == 1 and len(writer.history[CASE]) == 1
    assert "tenant-b" not in str(audit.events)


def test_dependency_override_cannot_escalate_writer_scope(wired):
    client, _, writer = wired
    saved = dict(app.dependency_overrides)
    app.dependency_overrides[get_principal] = lambda: identity()
    try:
        assert client.post(url("create"), json=body()).status_code == 401
        assert client.post(url("create"), json=body(),
                           headers=token("read-only")).status_code == 403
        assert writer.calls == 0
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)


def test_malformed_json_is_authenticated_before_parser_disclosure(wired):
    client, audit, writer = wired
    response = client.post(
        url("create"), data="{", headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert writer.calls == 0
    assert any(e.action == "authenticate" and e.result == "denied"
               for e in audit.events)
