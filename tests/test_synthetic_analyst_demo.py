"""#45/#46: test-only authenticated analyst queue -> history demonstration.

Entirely synthetic, in-memory, and excluded from the bank-targeted image.
Credentials are random, per test, short-lived and revocable; no fixed token
or browser-owned tenant/role. No TLS/IdP/proxy installation, durable audit,
Bank source attestation, grouping approval or #49 authority is implied.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.cases.queue import CaseQueueSnapshot, RankedCase
from gasha.cases.timeline import BankExecution, CaseEvent, CaseOperation, CaseReason
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    CredentialRejected,
    IdentityUnavailable,
    SecurityAuditEvent,
    TrustedPrincipal,
)

TENANTS = ("fictional-install-a", "fictional-install-b")
ISSUER = "synthetic-analyst-harness-v1"
POLICY = "synthetic-analyst-reader-v1"


class DemoVerifier:
    """Runtime-only fictional verifier; NOT a bank IdP or credential service."""

    def __init__(self) -> None:
        self.issued: dict[str, TrustedPrincipal] = {}
        self.revoked: set[str] = set()
        self.offline = False

    def issue(
        self, tenant: str, *, read: bool = True,
        lifetime: timedelta = timedelta(minutes=5),
    ) -> str:
        if tenant not in TENANTS:
            raise ValueError("unknown fictional installation")
        token = token_urlsafe(32)
        self.issued[token] = TrustedPrincipal(
            subject=f"fictional-analyst-{uuid4().hex}",
            issuer=ISSUER, credential_ref=sha256(token.encode()).hexdigest(),
            tenant_ids=frozenset({tenant}),
            capabilities=frozenset({
                Capability.CASE_READ if read else Capability.CASE_TRIAGE
            }),
            expires_at=datetime.now(UTC) + lifetime,
        )
        return token

    def verify(self, bearer: str) -> TrustedPrincipal:
        if self.offline:
            raise IdentityUnavailable("synthetic verifier unavailable")
        if bearer in self.revoked or bearer not in self.issued:
            raise CredentialRejected("synthetic credential revoked or unknown")
        return self.issued[bearer]


class DemoAudit:
    """Redacted test audit, in memory only; not evidence of Bank durability."""

    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []
        self.offline = False

    def append(self, event: SecurityAuditEvent) -> None:
        if self.offline:
            raise RuntimeError("synthetic audit unavailable")
        self.events.append(event)


class DemoReader:
    """Server-installed, fixed fictional cases; no client-selected source/policy."""

    def __init__(self) -> None:
        self.cases: dict[str, RankedCase] = {}
        self.calls: list[tuple[str, str]] = []
        self.offline = False
        self.invalid_snapshot = False
        for tenant in TENANTS:
            case_id, source_id = uuid4(), uuid4()
            context = sha256(f"synthetic:{tenant}:{uuid4().hex}".encode()).hexdigest()
            event = CaseEvent(
                tenant_id=tenant, case_id=case_id, source_event_id=source_id,
                source_context_ref=context, revision=1, previous_revision=None,
                operation=CaseOperation.CREATE, actor_ref="a" * 64,
                recorded_at=datetime.now(UTC) - timedelta(minutes=10),
                reason_code=CaseReason.SOURCE_EVALUATION, disposition=None,
                assignee_ref=None, idempotency_ref="d" * 64, command_ref="e" * 64,
                bank_execution=BankExecution.UNKNOWN,
            )
            scenarios = ("APP-01", "ATO-02") if tenant == TENANTS[0] else ("MM-01", "MM-05")
            self.cases[tenant] = RankedCase(
                rank=1, case_id=case_id, source_event_id=source_id,
                source_context_ref=context, scenario_ids=scenarios, history=(event,),
            )

    def _check(self, principal: TrustedPrincipal, tenant_id: str, at: datetime) -> None:
        if (
            type(principal) is not TrustedPrincipal
            or principal.issuer != ISSUER
            or tenant_id not in TENANTS
            or tenant_id not in principal.tenant_ids
            or Capability.CASE_READ not in principal.capabilities
            or principal.expires_at.astimezone(UTC) <= at.astimezone(UTC)
        ):
            raise AuthorizationRejected("synthetic reader denied")
        if self.offline:
            raise RuntimeError("synthetic reader unavailable")

    def read(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        limit: int, at: datetime,
    ) -> CaseQueueSnapshot:
        self.calls.append(("queue", tenant_id))
        self._check(principal, tenant_id, at)
        return CaseQueueSnapshot(
            tenant_id=(
                TENANTS[1] if tenant_id == TENANTS[0] else TENANTS[0]
            ) if self.invalid_snapshot else tenant_id,
            ranking_policy_version=POLICY, generated_at=at,
            items=(self.cases[tenant_id],)[:limit],
        )

    def history(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        case_id: UUID, at: datetime,
    ) -> tuple[CaseEvent, ...]:
        self.calls.append(("history", tenant_id))
        self._check(principal, tenant_id, at)
        case = self.cases[tenant_id]
        return case.history if case.case_id == case_id else ()


@pytest.fixture
def analyst_demo():  # Test fixture, never included in protected deployment.
    keys = (
        "identity_verifier", "security_audit", "case_queue_reader",
        "case_history_reader", "case_transition_writer", "outcome_ingestion",
    )
    original = {key: getattr(app.state, key) for key in keys}
    verifier, audit, reader = DemoVerifier(), DemoAudit(), DemoReader()
    app.state.identity_verifier = verifier
    app.state.security_audit = audit
    app.state.case_queue_reader = reader
    app.state.case_history_reader = reader
    app.state.case_transition_writer = None
    app.state.outcome_ingestion = None
    try:
        yield verifier, audit, reader
    finally:
        for key, value in original.items():
            setattr(app.state, key, value)


def url(tenant: str, case_id: UUID | None = None) -> str:
    if case_id is None:
        return f"/v1/tenants/{tenant}/cases/queue"
    return f"/v1/tenants/{tenant}/cases/{case_id}/history"


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("tenant", TENANTS)
def test_queue_to_history_preserves_lineage_and_no_bank_authority(
    analyst_demo, tenant: str,
) -> None:
    verifier, audit, reader = analyst_demo
    token = verifier.issue(tenant)
    client = TestClient(app)
    queue = client.get(url(tenant), headers=auth(token))
    assert queue.status_code == 200, queue.text
    data = queue.json()
    assert data["ranking_policy_version"] == POLICY
    assert data["bank_ranking_approved"] is False
    assert data["enforcement_activated"] is False
    item = data["items"][0]
    assert item["scenario_ids"] == (
        ["APP-01", "ATO-02"] if tenant == TENANTS[0] else ["MM-01", "MM-05"]
    )
    assert item["bank_execution"] == "unknown"
    history = client.get(url(tenant, UUID(item["case_id"])), headers=auth(token))
    assert history.status_code == 200, history.text
    event = history.json()["events"][0]
    assert event["source_event_id"] == item["source_event_id"]
    assert event["source_context_ref"] == item["source_context_ref"]
    assert event["bank_execution"] == "unknown"
    assert history.json()["enforcement_activated"] is False
    assert reader.calls == [("queue", tenant), ("history", tenant)]
    assert [e.result for e in audit.events if e.action == "case.read"] == [
        "authorized", "succeeded", "authorized", "succeeded",
    ]
    assert token not in queue.text + history.text + str(audit.events)
    assert tenant not in str(audit.events)
    assert "idempotency_ref" not in history.text


def test_second_fictional_tenant_and_cross_scope_are_isolated(analyst_demo) -> None:
    verifier, audit, reader = analyst_demo
    first, second = verifier.issue(TENANTS[0]), verifier.issue(TENANTS[1])
    client = TestClient(app)
    a = client.get(url(TENANTS[0]), headers=auth(first))
    b = client.get(url(TENANTS[1]), headers=auth(second))
    assert a.status_code == b.status_code == 200
    assert a.json()["items"][0]["case_id"] != b.json()["items"][0]["case_id"]
    assert a.json()["items"][0]["source_event_id"] != b.json()["items"][0]["source_event_id"]
    assert a.json()["items"][0]["source_context_ref"] != b.json()["items"][0]["source_context_ref"]
    assert b.json()["items"][0]["scenario_ids"] == ["MM-01", "MM-05"]
    # Wrong-tenant URL is hidden, and a foreign case ID cannot be read via B.
    assert client.get(url(TENANTS[0]), headers={
        **auth(second), "X-Tenant-Id": TENANTS[0], "X-Role": "admin",
        "X-Forwarded-Prefix": "/forged",
    }).status_code == 404
    assert client.get(
        url(TENANTS[1], reader.cases[TENANTS[0]].case_id), headers=auth(second),
    ).status_code == 404
    assert client.get(url(TENANTS[1]), headers={
        **auth(first), "X-Tenant-Id": TENANTS[1], "X-Role": "admin",
        "X-Forwarded-Prefix": "/forged",
    }).status_code == 404
    assert client.get(
        url(TENANTS[0], reader.cases[TENANTS[1]].case_id), headers=auth(first),
    ).status_code == 404
    assert first not in str(audit.events) and second not in str(audit.events)
    assert all(e.bank_execution is BankExecution.UNKNOWN
               for case in reader.cases.values() for e in case.history)


@pytest.mark.parametrize("history", [False, True])
@pytest.mark.parametrize("kind,code", [
    ("missing", 401), ("malformed", 401), ("revoked", 401),
    ("expired", 401), ("no-read", 403), ("idp-outage", 503),
])
def test_auth_negatives_never_read(analyst_demo, history: bool, kind: str, code: int) -> None:
    verifier, audit, reader = analyst_demo
    token = verifier.issue(
        TENANTS[0], read=kind != "no-read",
        lifetime=timedelta(seconds=-1) if kind == "expired" else timedelta(minutes=5),
    )
    if kind == "revoked":
        verifier.revoked.add(token)
    if kind == "idp-outage":
        verifier.offline = True
    path = url(TENANTS[0], reader.cases[TENANTS[0]].case_id if history else None)
    headers = {} if kind == "missing" else (
        {"Authorization": "malformed"} if kind == "malformed" else auth(token)
    )
    response = TestClient(app).get(path, headers=headers)
    assert response.status_code == code
    assert reader.calls == []
    assert token not in response.text + str(audit.events)
    assert any(e.result == "denied" for e in audit.events)


@pytest.mark.parametrize("prefix,prefixed", [
    ("", False), ("/bank", False), ("/bank", True), ("/gateway/bank", True),
])
@pytest.mark.parametrize("history", [False, True])
def test_asgi_path_modes_do_not_trust_forwarded_role_or_tenant(
    analyst_demo, prefix: str, prefixed: bool, history: bool,
) -> None:
    verifier, audit, reader = analyst_demo
    good, no_read = verifier.issue(TENANTS[0]), verifier.issue(TENANTS[0], read=False)
    path = url(TENANTS[0], reader.cases[TENANTS[0]].case_id if history else None)
    request_url = (prefix if prefixed else "") + path
    client = TestClient(app, root_path=prefix)
    assert client.get(request_url, headers=auth(good)).status_code == 200
    assert client.get(request_url).status_code == 401
    assert client.get(request_url, headers=auth(no_read)).status_code == 403
    assert client.get(
        request_url.replace(TENANTS[0], TENANTS[1]),
        headers={**auth(good), "X-Tenant-Id": TENANTS[1],
                 "X-Role": "admin", "X-Forwarded-Prefix": "/spoofed"},
    ).status_code == 404
    assert len(reader.calls) == 1
    assert good not in str(audit.events)


def test_revocation_after_success_never_serves_cached_history(analyst_demo) -> None:
    verifier, _, reader = analyst_demo
    token = verifier.issue(TENANTS[0])
    client = TestClient(app)
    assert client.get(url(TENANTS[0]), headers=auth(token)).status_code == 200
    verifier.revoked.add(token)
    assert client.get(url(TENANTS[0]), headers=auth(token)).status_code == 401
    assert client.get(
        url(TENANTS[0], reader.cases[TENANTS[0]].case_id), headers=auth(token),
    ).status_code == 401
    assert reader.calls == [("queue", TENANTS[0])]


@pytest.mark.parametrize("tenant", TENANTS)
@pytest.mark.parametrize("broken", ["audit", "reader", "wrong-tenant", "bad-lineage"])
def test_server_dependency_or_evidence_failures_never_return_queue_data(
    analyst_demo, tenant: str, broken: str,
) -> None:
    verifier, audit, reader = analyst_demo
    other = TENANTS[1] if tenant == TENANTS[0] else TENANTS[0]
    token = verifier.issue(tenant)
    audit.offline = broken == "audit"
    reader.offline = broken == "reader"
    reader.invalid_snapshot = broken == "wrong-tenant"
    if broken == "bad-lineage":
        case = reader.cases[tenant]
        reader.cases[tenant] = replace(
            case, history=(replace(case.history[0], tenant_id=other),),
        )
    response = TestClient(app).get(url(tenant), headers=auth(token))
    assert response.status_code == 503
    assert "items" not in response.json()
    assert reader.calls == ([] if broken == "audit" else [("queue", tenant)])
    assert token not in response.text + str(audit.events)


def test_history_outage_and_unknown_case_do_not_leak_evidence(analyst_demo) -> None:
    verifier, audit, reader = analyst_demo
    token = verifier.issue(TENANTS[0])
    client = TestClient(app)
    assert client.get(url(TENANTS[0], uuid4()), headers=auth(token)).status_code == 404
    reader.offline = True
    denied = client.get(
        url(TENANTS[0], reader.cases[TENANTS[0]].case_id), headers=auth(token),
    )
    assert denied.status_code == 503
    assert "events" not in denied.json()
    assert any(e.result == "failed" for e in audit.events)


@pytest.mark.parametrize("tenant", TENANTS)
def test_malformed_history_is_denied_for_either_tenant(
    analyst_demo, tenant: str,
) -> None:
    verifier, audit, reader = analyst_demo
    other = TENANTS[1] if tenant == TENANTS[0] else TENANTS[0]
    original = reader.cases[tenant]
    reader.cases[tenant] = replace(
        original, history=(replace(original.history[0], tenant_id=other),),
    )
    token = verifier.issue(tenant)
    response = TestClient(app).get(
        url(tenant, original.case_id), headers=auth(token),
    )
    assert response.status_code == 503
    assert "events" not in response.json()
    assert reader.calls == [("history", tenant)]
    assert any(e.result == "failed" for e in audit.events)
    assert token not in response.text + str(audit.events)


def test_read_only_demo_has_no_authorized_case_mutation(analyst_demo) -> None:
    verifier, _, reader = analyst_demo
    token = verifier.issue(TENANTS[0])
    case = reader.cases[TENANTS[0]]
    response = TestClient(app).post(
        f"/v1/tenants/{TENANTS[0]}/cases/{case.case_id}/transitions/create",
        headers=auth(token),
        json={
            "source_event_id": str(case.source_event_id), "expected_revision": 0,
            "idempotency_key": "a" * 32, "reason_code": "source_evaluation",
        },
    )
    assert response.status_code == 403
    assert reader.cases[TENANTS[0]] == case
    assert reader.calls == []
