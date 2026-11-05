"""#42/#45 protected, read-only analyst case history: no Bank wiring or action."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app, get_principal
from gasha.cases.timeline import (
    BankExecution,
    CaseDisposition,
    CaseEvent,
    CaseOperation,
    CaseReason,
)
from gasha.security.access import (
    Capability,
    CredentialRejected,
    TrustedPrincipal,
)

NOW = datetime.now(UTC)
CASE_ID = uuid4()
EVENT_ID = uuid4()
ACTOR = "a" * 64
CONTEXT = "c" * 64


class Audit:
    def __init__(self) -> None:
        self.events: list[object] = []
        self.fail = False

    def append(self, event: object) -> None:
        if self.fail:
            raise RuntimeError("synthetic security audit outage")
        self.events.append(event)


def identity(*, tenant: str = "tenant-a",
             caps: frozenset[Capability] = frozenset({Capability.CASE_READ}),
             expires: datetime = NOW + timedelta(hours=1)) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-analyst-secret", issuer="synthetic-only",
        credential_ref="synthetic-credential-secret",
        tenant_ids=frozenset({tenant}), capabilities=caps, expires_at=expires,
    )


class Verifier:
    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer == "outage":
            raise RuntimeError("synthetic IdP outage")
        if bearer == "valid":
            return identity()
        if bearer == "no-read":
            return identity(caps=frozenset({Capability.CASE_TRIAGE}))
        if bearer == "expired":
            return identity(expires=NOW - timedelta(seconds=1))
        if bearer == "wrong-tenant":
            return identity(tenant="tenant-b")
        raise CredentialRejected("revoked or malformed synthetic token")


def synthetic_event() -> CaseEvent:
    return CaseEvent(
        tenant_id="tenant-a", case_id=CASE_ID, source_event_id=EVENT_ID,
        source_context_ref=CONTEXT, revision=1, previous_revision=None,
        operation=CaseOperation.CREATE, actor_ref=ACTOR,
        recorded_at=datetime(2026, 11, 1, 12, tzinfo=UTC),
        reason_code=CaseReason.SOURCE_EVALUATION, disposition=None,
        assignee_ref=None, idempotency_ref="d" * 64, command_ref="e" * 64,
        bank_execution=BankExecution.UNKNOWN,
    )


class Reader:
    def __init__(self) -> None:
        self.calls: list[tuple[str, UUID]] = []
        self.events: object = (synthetic_event(),)
        self.outage = False
        self.principal_mutation: tuple[str, str] | None = None
        self.fail_after_mutation = False

    def history(self, *, principal: TrustedPrincipal, tenant_id: str,
                case_id: UUID, at: datetime) -> object:
        self.calls.append((tenant_id, case_id))
        assert isinstance(principal, TrustedPrincipal)
        assert at.tzinfo is not None
        if self.principal_mutation is not None:
            field, replacement = self.principal_mutation
            object.__setattr__(principal, field, replacement)
            if self.fail_after_mutation:
                raise RuntimeError("synthetic reader mutated principal then failed")
        if self.outage:
            raise RuntimeError("synthetic storage outage")
        return self.events


@pytest.fixture
def wired_case_history():
    names = ("identity_verifier", "security_audit", "case_history_reader")
    saved = tuple(getattr(app.state, name) for name in names)
    audit, reader = Audit(), Reader()
    app.state.identity_verifier = Verifier()
    app.state.security_audit = audit
    app.state.case_history_reader = reader
    try:
        yield TestClient(app), audit, reader
    finally:
        for name, value in zip(names, saved, strict=True):
            setattr(app.state, name, value)


def path(*, tenant: str = "tenant-a", case_id: UUID = CASE_ID) -> str:
    return f"/v1/tenants/{tenant}/cases/{case_id}/history"


def token(value: str = "valid") -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def test_case_history_read_is_authenticated_pseudonymous_and_never_executes(wired_case_history):
    client, audit, reader = wired_case_history
    result = client.get(path(), headers=token())
    assert result.status_code == 200
    payload = result.json()
    assert payload["case_id"] == str(CASE_ID)
    assert payload["enforcement_activated"] is False
    assert len(payload["events"]) == 1
    event = payload["events"][0]
    assert event["operation"] == "create"
    assert event["reason_code"] == "source_evaluation"
    assert event["actor_ref"] == ACTOR
    assert event["source_event_id"] == str(EVENT_ID)
    assert event["source_context_ref"] == CONTEXT
    assert event["bank_execution"] == "unknown"
    assert "idempotency_ref" not in event and "command_ref" not in event
    assert "synthetic-analyst-secret" not in str(payload)
    assert reader.calls == [("tenant-a", CASE_ID)]
    assert any(
        e.action == Capability.CASE_READ.value and e.result == "succeeded"
        for e in audit.events
    )
    assert "tenant-a" not in str(audit.events)
    assert "synthetic-credential-secret" not in str(audit.events)


@pytest.mark.parametrize(("credential", "status"), [
    (None, 401), ("revoked", 401), ("expired", 401),
    ("outage", 503), ("no-read", 403),
])
def test_denied_credentials_and_capability_do_not_read(wired_case_history, credential, status):
    client, audit, reader = wired_case_history
    headers = {} if credential is None else token(credential)
    result = client.get(path(), headers=headers)
    assert result.status_code == status
    assert reader.calls == []
    assert any(e.result == "denied" for e in audit.events)


def test_cross_tenant_and_spoofed_proxy_claims_cannot_read(wired_case_history):
    client, audit, reader = wired_case_history
    result = client.get(
        path(tenant="tenant-b"),
        headers={**token(), "X-Tenant-Id": "tenant-b",
                 "X-Role": "admin", "X-Forwarded-Prefix": "/v1"},
    )
    assert result.status_code == 404
    assert reader.calls == []
    assert "tenant-b" not in str(audit.events)


def test_missing_reader_fails_closed_and_audits_failure(wired_case_history):
    client, audit, reader = wired_case_history
    app.state.case_history_reader = None
    result = client.get(path(), headers=token())
    assert result.status_code == 503
    assert result.json()["detail"] == "case history unavailable"
    assert reader.calls == []
    assert any(
        e.action == Capability.CASE_READ.value
        and e.result == "failed" and e.reason == "case_history_unavailable"
        for e in audit.events
    )


def test_audit_outage_prevents_case_reader_access(wired_case_history):
    client, audit, reader = wired_case_history
    audit.fail = True
    assert client.get(path(), headers=token()).status_code == 503
    assert reader.calls == []


def test_storage_outage_fails_closed_without_exposing_internal_details(wired_case_history):
    client, audit, reader = wired_case_history
    reader.outage = True
    response = client.get(path(), headers=token())
    assert response.status_code == 503
    assert "synthetic storage outage" not in response.text
    assert reader.calls == [("tenant-a", CASE_ID)]
    assert any(e.result == "failed" and e.reason == "case_history_unavailable"
               for e in audit.events)


@pytest.mark.parametrize("tamper", [
    {"tenant_id": "tenant-b"},
    {"case_id": uuid4()},
    {"source_context_ref": "invalid-context"},
    {"actor_ref": "raw-analyst"},
    {"recorded_at": datetime(2026, 11, 1)},
    {"bank_execution": "executed"},
])
def test_untrusted_reader_payload_fails_closed(wired_case_history, tamper):
    client, audit, reader = wired_case_history
    reader.events = (replace(synthetic_event(), **tamper),)
    response = client.get(path(), headers=token())
    assert response.status_code == 503
    assert "tenant-b" not in response.text
    assert "raw-analyst" not in response.text
    assert any(e.result == "failed" and e.reason == "case_history_unavailable"
               for e in audit.events)


def test_history_clock_uses_absolute_utc_not_dst_wall_time(wired_case_history):
    client, _, reader = wired_case_history
    zone = ZoneInfo("America/New_York")
    later_real = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    earlier_real = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    first = replace(synthetic_event(), recorded_at=later_real)
    second = replace(
        synthetic_event(), revision=2, previous_revision=1,
        operation=CaseOperation.TRIAGE, reason_code=CaseReason.ANALYST_TRIAGE,
        recorded_at=earlier_real,
    )
    reader.events = (first, second)
    response = client.get(path(), headers=token())
    assert response.status_code == 503



@pytest.mark.parametrize("change", [
    {"assignee_ref": "b" * 64},
    {"operation": CaseOperation.RECONCILE, "reason_code": CaseReason.FEEDBACK_RECONCILED},
    {"operation": CaseOperation.DISPOSE, "disposition": CaseDisposition.FRAUD,
     "reason_code": CaseReason.LEGITIMATE_EVIDENCE},
    {"operation": CaseOperation.CREATE, "reason_code": CaseReason.ANALYST_TRIAGE},
    {"operation": CaseOperation.CREATE, "disposition": CaseDisposition.FRAUD},
])
def test_invalid_initial_case_lifecycle_is_denied(wired_case_history, change):
    client, audit, reader = wired_case_history
    reader.events = (replace(synthetic_event(), **change),)
    response = client.get(path(), headers=token())
    assert response.status_code == 503
    assert response.json() == {"detail": "case history unavailable"}
    assert reader.calls == [("tenant-a", CASE_ID)]
    assert any(e.result == "failed" and e.reason == "case_history_unavailable"
               for e in audit.events)
    assert not any(e.result == "succeeded" and e.reason == "case_history_read"
                   for e in audit.events)


@pytest.mark.parametrize("change", [
    {"operation": CaseOperation.CREATE, "reason_code": CaseReason.SOURCE_EVALUATION},
    {"operation": CaseOperation.ASSIGN, "reason_code": CaseReason.INVESTIGATION_ASSIGNED,
     "assignee_ref": "b" * 64},
    {"operation": CaseOperation.DISPOSE, "reason_code": CaseReason.FRAUD_EVIDENCE,
     "disposition": CaseDisposition.FRAUD},
    {"operation": CaseOperation.CORRECT, "reason_code": CaseReason.CORRECTED_FINDING,
     "disposition": CaseDisposition.LEGITIMATE},
    {"operation": CaseOperation.RECONCILE, "reason_code": CaseReason.FEEDBACK_RECONCILED},
    {"operation": CaseOperation.TRIAGE, "reason_code": CaseReason.SOURCE_EVALUATION},
    {"operation": CaseOperation.TRIAGE, "reason_code": CaseReason.ANALYST_TRIAGE,
     "assignee_ref": "b" * 64},
    {"operation": CaseOperation.TRIAGE, "reason_code": CaseReason.ANALYST_TRIAGE,
     "disposition": CaseDisposition.FRAUD},
])
def test_invalid_subsequent_case_lifecycle_is_denied(wired_case_history, change):
    client, audit, reader = wired_case_history
    first = synthetic_event()
    next_event = replace(
        first, revision=2, previous_revision=1,
        recorded_at=first.recorded_at + timedelta(seconds=1),
        idempotency_ref="f" * 64, command_ref="1" * 64,
        **change,
    )
    reader.events = (first, next_event)
    response = client.get(path(), headers=token())
    assert response.status_code == 503
    assert response.json() == {"detail": "case history unavailable"}
    assert reader.calls == [("tenant-a", CASE_ID)]
    assert any(e.result == "failed" and e.reason == "case_history_unavailable"
               for e in audit.events)
    assert not any(e.result == "succeeded" and e.reason == "case_history_read"
                   for e in audit.events)


def test_case_history_correction_requires_changed_disposition(wired_case_history):
    client, audit, reader = wired_case_history
    first = synthetic_event()
    steps = (
        (CaseOperation.TRIAGE, CaseReason.ANALYST_TRIAGE, None, None),
        (CaseOperation.ASSIGN, CaseReason.INVESTIGATION_ASSIGNED, None, "b" * 64),
        (CaseOperation.DISPOSE, CaseReason.FRAUD_EVIDENCE, CaseDisposition.FRAUD, None),
        (CaseOperation.CORRECT, CaseReason.CORRECTED_FINDING, CaseDisposition.FRAUD, None),
    )
    history = [first]
    for index, (operation, reason, disposition, assignee) in enumerate(steps, 2):
        history.append(replace(
            first, revision=index, previous_revision=index - 1,
            operation=operation, reason_code=reason, disposition=disposition,
            assignee_ref=assignee, recorded_at=first.recorded_at + timedelta(seconds=index),
            idempotency_ref=f"{index:064x}", command_ref=f"{index + 10:064x}",
        ))
    reader.events = tuple(history)
    response = client.get(path(), headers=token())
    assert response.status_code == 503
    assert response.json() == {"detail": "case history unavailable"}
    assert any(e.result == "failed" and e.reason == "case_history_unavailable"
               for e in audit.events)


def test_empty_case_is_not_found_and_has_redacted_audit(wired_case_history):
    client, audit, reader = wired_case_history
    reader.events = ()
    response = client.get(path(), headers=token())
    assert response.status_code == 404
    assert any(e.action == Capability.CASE_READ.value and e.result == "not_found"
               for e in audit.events)


def test_ingress_auth_precedes_malformed_path_validation(wired_case_history):
    client, audit, reader = wired_case_history
    bad_path = "/v1/tenants/tenant-a/cases/not-a-uuid/history"
    assert client.get(bad_path).status_code == 401
    assert reader.calls == []
    assert any(e.action == "authenticate" and e.result == "denied" for e in audit.events)


@pytest.mark.parametrize(("root_path", "prefixed"), [
    ("", False), ("/bank", False), ("/bank", True),
    ("/gateway/bank", True),
])
def test_case_read_root_path_auth_and_tenant_scope(
    wired_case_history, root_path: str, prefixed: bool,
):
    _, audit, reader = wired_case_history
    client = TestClient(app, root_path=root_path)
    prefix = root_path if prefixed else ""
    url = f"{prefix}{path()}"
    assert client.get(url, headers=token()).status_code == 200
    assert client.get(url).status_code == 401
    assert client.get(url, headers=token("no-read")).status_code == 403
    assert client.get(
        f"{prefix}{path(tenant='tenant-b')}",
        headers={**token(), "X-Forwarded-Prefix": "/forged",
                 "X-Role": "administrator", "X-Tenant-Id": "tenant-b"},
    ).status_code == 404
    assert reader.calls == [("tenant-a", CASE_ID)]
    assert "tenant-b" not in str(audit.events)


def test_dependency_override_cannot_upgrade_case_read_role(wired_case_history):
    client, audit, reader = wired_case_history
    saved = dict(app.dependency_overrides)
    app.dependency_overrides[get_principal] = lambda: identity()
    try:
        assert client.get(path()).status_code == 401
        assert client.get(path(), headers=token("no-read")).status_code == 403
        assert reader.calls == []
        assert any(e.action == Capability.CASE_READ.value and e.result == "denied"
                   for e in audit.events)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)


def test_case_history_multiple_transitions_are_immutable_and_nonexecuting(
    wired_case_history,
):
    client, _, reader = wired_case_history
    first = synthetic_event()
    second = replace(
        first, revision=2, previous_revision=1, operation=CaseOperation.TRIAGE,
        reason_code=CaseReason.ANALYST_TRIAGE,
        recorded_at=first.recorded_at + timedelta(seconds=1),
        idempotency_ref="f" * 64, command_ref="1" * 64,
    )
    reader.events = (first, second)
    response = client.get(path(), headers=token())
    assert response.status_code == 200
    events = response.json()["events"]
    assert [e["revision"] for e in events] == [1, 2]
    assert [e["previous_revision"] for e in events] == [None, 1]
    assert all(e["bank_execution"] == "unknown" for e in events)
    assert response.json()["enforcement_activated"] is False


def test_boolean_previous_revision_is_rejected_without_read_disclosure(wired_case_history):
    client, audit, reader = wired_case_history
    first = synthetic_event()
    corrupted = replace(
        first, revision=2, previous_revision=True, operation=CaseOperation.TRIAGE,
        reason_code=CaseReason.ANALYST_TRIAGE,
        recorded_at=first.recorded_at + timedelta(seconds=1),
    )
    reader.events = (first, corrupted)
    response = client.get(path(), headers=token())
    assert response.status_code == 503
    assert response.json() == {"detail": "case history unavailable"}
    assert any(e.result == "failed" and e.reason == "case_history_unavailable"
               for e in audit.events)


@pytest.mark.parametrize(("field", "replacement"), [
    ("subject", "synthetic-forged-actor-secret"),
    ("issuer", "synthetic-forged-issuer-secret"),
])
@pytest.mark.parametrize("fail_after_mutation", [False, True])
def test_case_reader_cannot_rewrite_authenticated_audit_actor(
    wired_case_history, field: str, replacement: str, fail_after_mutation: bool,
) -> None:
    """A lower-trust callback must not mutate request identity used by audit.

    Frozen verifier output is not deep in-process immutability. Without an
    isolated callback copy, object.__setattr__ could make authorization and
    terminal read records attribute different actors to the same request.
    """
    client, audit, reader = wired_case_history
    expected_actor = identity().audit_actor
    reader.principal_mutation = (field, replacement)
    reader.fail_after_mutation = fail_after_mutation

    response = client.get(path(), headers=token())
    assert response.status_code == (503 if fail_after_mutation else 200)
    if fail_after_mutation:
        assert response.json() == {"detail": "case history unavailable"}
    else:
        assert response.json()["enforcement_activated"] is False
    records = [
        event for event in audit.events
        if event.action == Capability.CASE_READ.value
    ]
    assert [event.result for event in records] == [
        "authorized", "failed" if fail_after_mutation else "succeeded",
    ]
    assert {event.actor_ref for event in records} == {expected_actor}
    assert reader.calls == [("tenant-a", CASE_ID)]
    assert replacement not in response.text
    assert replacement not in str(audit.events)
