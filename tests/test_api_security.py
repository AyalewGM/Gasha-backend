"""#42 HTTP-level negative and positive tests, using only synthetic credentials."""
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import TrustedDecisionContext, app, get_principal
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ingestion.outcome_ingestion import OutcomeIngestionService
from gasha.security.access import (
    Capability,
    CredentialRejected,
    TrustedPrincipal,
)

NOW = datetime.now(UTC)


class Audit:
    def __init__(self) -> None:
        self.events = []

    def append(self, event) -> None:
        self.events.append(event)


class Verifier:
    def __init__(self, identities) -> None:
        self.identities = identities

    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer == "outage":
            raise RuntimeError("synthetic outage")
        result = self.identities.get(bearer)
        if result is None:
            raise CredentialRejected("unrecognized or revoked")
        return result


class ContextProvider:
    def resolve(self, transaction, principal) -> TrustedDecisionContext:
        assert transaction.tenant_id in principal.tenant_ids
        return TrustedDecisionContext(
            tenant_id=transaction.tenant_id,
            event_id=transaction.event_id,
            signal_source_version="synthetic-source-1",
            signal_version="synthetic-signal-v1",
            collected_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            policy=DecisionPolicy(
                configuration_version="synthetic-config-1",
                policy_version="synthetic-policy-1",
                rule_version="synthetic-rules-1",
            ),
            intelligence=IntelligenceSnapshot(network_risk=0.98),
        )


def identity(
    tenants=frozenset({"tenant-a"}),
    caps=frozenset({
        Capability.DECISION_SUBMIT,
        Capability.OUTCOME_SUBMIT,
        Capability.INCUMBENT_OUTCOME_SUBMIT,
    }),
    expires=NOW + timedelta(hours=1),
) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-api-client",
        issuer="synthetic-only-test",
        credential_ref="synthetic-rotation-v1",
        tenant_ids=tenants,
        capabilities=caps,
        expires_at=expires,
    )


def tx(tenant: str = "tenant-a") -> dict[str, object]:
    return CanonicalTransaction(
        tenant_id=tenant,
        event_id=uuid4(),
        occurred_at=NOW,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("100.00"),
        currency="ETB",
        sender_customer_id="synthetic-customer",
        sender_account_id="synthetic-account",
        beneficiary_id="synthetic-beneficiary",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="synthetic-destination",
        correlation_id="synthetic-correlation",
    ).model_dump(mode="json")


@pytest.fixture
def wired():
    saved = tuple(getattr(app.state, key) for key in (
        "identity_verifier", "security_audit", "decision_context_provider",
        "outcome_ingestion",
    ))
    audit = Audit()
    store = OutcomeIngestionService()
    app.state.security_audit = audit
    app.state.identity_verifier = Verifier({
        "valid": identity(),
        "wrong-capability": identity(caps=frozenset({Capability.DECISION_READ})),
        "expired": identity(expires=NOW - timedelta(days=1)),
    })
    app.state.decision_context_provider = ContextProvider()
    app.state.outcome_ingestion = store
    try:
        yield TestClient(app), audit, store
    finally:
        (
            app.state.identity_verifier,
            app.state.security_audit,
            app.state.decision_context_provider,
            app.state.outcome_ingestion,
        ) = saved


def headers(token: str = "valid") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_trusted_decision_and_shadow_mode_never_execute_bank_action(wired) -> None:
    client, audit, _ = wired
    payload = {"transaction": tx()}
    decision = client.post("/v1/decisions", json=payload, headers=headers())
    assert decision.status_code == 200
    assert decision.json()["action"] == "block"
    assert decision.json()["policy_version"] == "synthetic-policy-1"
    assert len(decision.headers["X-Gasha-Context-Ref"]) == 64
    assert decision.headers["X-Gasha-Signal-Version"] == "synthetic-signal-v1"
    assert decision.headers["X-Gasha-Source-Version"] == "synthetic-source-1"
    evaluation = client.post("/v1/evaluations", json=payload, headers=headers())
    assert evaluation.status_code == 200
    assert evaluation.json()["decision"]["action"] == "block"
    assert evaluation.json()["operating_mode"] == "shadow"
    assert evaluation.json()["effective_action"] == "no_action_shadow"
    assert evaluation.headers["X-Gasha-Context-Ref"] == decision.headers["X-Gasha-Context-Ref"]
    assert any(
        e.context_ref == decision.headers["X-Gasha-Context-Ref"]
        for e in audit.events if e.result == "succeeded"
    )
    assert any(e.action == Capability.DECISION_SUBMIT.value for e in audit.events)


@pytest.mark.parametrize(("token", "status"), [
    (None, 401), ("bad", 401), ("expired", 401),
    ("outage", 503), ("wrong-capability", 403),
])
def test_identity_and_role_denied_without_evaluation(wired, token, status) -> None:
    client, audit, _ = wired
    hdr = {} if token is None else headers(token)
    response = client.post("/v1/decisions", json={"transaction": tx()}, headers=hdr)
    assert response.status_code == status
    assert any(e.result == "denied" for e in audit.events)


def test_cross_tenant_denial_no_existence_leak(wired) -> None:
    client, audit, _ = wired
    response = client.post(
        "/v1/decisions", json={"transaction": tx("tenant-b")},
        headers={"Authorization": "Bearer valid", "X-Tenant-Id": "tenant-b", "X-Role": "admin"},
    )
    assert response.status_code == 404
    assert "tenant-b" not in str(audit.events)


@pytest.mark.parametrize("extra", [
    {"policy": {"configuration_version": "forged", "policy_version": "x", "rule_version": "x"}},
    {"network_risk": 1.0},
    {"operating_mode": "enforcing"},
    {"tenant_id": "tenant-b"},
])
def test_body_policy_scores_mode_and_claims_cannot_override_server(wired, extra) -> None:
    client, _, _ = wired
    response = client.post(
        "/v1/evaluations", json={"transaction": tx(), **extra}, headers=headers(),
    )
    assert response.status_code == 422


def test_outcome_write_is_unavailable_even_with_legacy_store_injected(wired) -> None:
    client, audit, store = wired
    eid = uuid4()
    body = {
        "tenant_id": "tenant-a", "event_id": str(eid),
        "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
        "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat(),
    }
    denied = client.post("/v1/outcomes", json=body, headers=headers("wrong-capability"))
    assert denied.status_code == 403
    assert store.store.outcomes("tenant-a", eid) == ()
    cross_tenant = client.post(
        "/v1/outcomes", json={**body, "tenant_id": "tenant-b"}, headers=headers(),
    )
    assert cross_tenant.status_code == 404
    assert store.store.outcomes("tenant-b", eid) == ()
    for _ in range(2):
        response = client.post("/v1/outcomes", json=body, headers=headers())
        assert response.status_code == 503
        assert response.json()["detail"] == "transactional outcome ingestion unavailable"
        assert store.store.outcomes("tenant-a", eid) == ()
    records = [e for e in audit.events if e.action == Capability.OUTCOME_SUBMIT.value
               and e.reason == "transactional_outcome_unavailable"]
    assert len(records) == 2
    assert all(e.result == "failed" for e in records)
    assert len({e.attempt_ref for e in records}) == 2
    assert len({e.event_ref for e in records}) == 1


def test_incumbent_outcome_has_separate_capability(wired) -> None:
    client, audit, store = wired
    eid = uuid4()
    body = {
        "tenant_id": "tenant-a", "event_id": str(eid),
        "outcome": "review", "source_system": "synthetic-incumbent",
    }
    allowed = client.post("/v1/incumbent-outcomes", json=body, headers=headers())
    assert allowed.status_code == 503
    assert client.post(
        "/v1/incumbent-outcomes", json=body, headers=headers("wrong-capability"),
    ).status_code == 403
    assert store.store.incumbent_outcomes("tenant-a", eid) == ()
    assert any(
        e.action == Capability.INCUMBENT_OUTCOME_SUBMIT.value
        and e.reason == "transactional_outcome_unavailable" and e.result == "failed"
        for e in audit.events
    )


def test_missing_context_or_audit_fails_closed(wired) -> None:
    client, _, _ = wired
    app.state.decision_context_provider = None
    response = client.post("/v1/evaluations", json={"transaction": tx()}, headers=headers())
    assert response.status_code == 503
    app.state.security_audit = None
    response = client.post("/v1/outcomes", json={}, headers=headers())
    assert response.status_code in (422, 503)
    response = client.post("/v1/decisions", json={"transaction": tx()}, headers=headers())
    assert response.status_code == 503


def test_audit_redacts_subject_credential_and_raw_tenant(wired) -> None:
    client, audit, _ = wired
    client.post("/v1/decisions", json={"transaction": tx()}, headers=headers())
    content = str(audit.events)
    assert "Bearer" not in content
    assert "synthetic-api-client" not in content
    assert "tenant-a" not in content
    assert "valid" not in content


def test_unwired_bank_app_not_ready_and_cannot_evaluate(wired) -> None:
    client, _, _ = wired
    app.state.identity_verifier = None
    assert client.get("/health/live").json() == {"status": "ok"}
    readiness = client.get("/health/ready")
    assert readiness.status_code == 503
    assert readiness.json()["status"] == "not_ready"
    assert client.post(
        "/v1/decisions", json={"transaction": tx()}, headers=headers(),
    ).status_code == 503


def test_audit_attempt_correlates_authorization_terminal_result_and_event(wired) -> None:
    client, audit, _ = wired
    body = tx()
    response = client.post("/v1/evaluations", json={"transaction": body}, headers=headers())
    assert response.status_code == 200
    records = [e for e in audit.events if e.action == Capability.DECISION_SUBMIT.value]
    assert [e.result for e in records] == ["authorized", "succeeded"]
    assert len({e.attempt_ref for e in records}) == 1
    assert len(records[0].attempt_ref) == 32
    assert len(records[0].event_ref) == 64
    assert records[0].event_ref == records[1].event_ref
    assert len(records[1].context_ref) == 64
    assert str(body["event_id"]) not in str(records)
    assert "synthetic-customer" not in str(records)


def test_failed_context_is_correlated_and_records_terminal_failure(wired) -> None:
    client, audit, _ = wired

    class FailingProvider:
        def resolve(self, transaction, principal):
            raise RuntimeError("synthetic upstream unavailable")

    app.state.decision_context_provider = FailingProvider()
    response = client.post("/v1/decisions", json={"transaction": tx()}, headers=headers())
    assert response.status_code == 503
    events = [e for e in audit.events if e.action == Capability.DECISION_SUBMIT.value]
    assert [e.result for e in events] == ["authorized", "failed"]
    assert events[0].attempt_ref == events[1].attempt_ref
    assert events[0].event_ref == events[1].event_ref
    assert "synthetic upstream" not in str(events)


@pytest.mark.parametrize("kind", ["wrong_event", "wrong_tenant", "stale", "future"])
def test_unbound_or_stale_server_context_fails_closed(wired, kind) -> None:
    client, audit, _ = wired

    class BadProvider:
        def resolve(self, transaction, principal):
            return TrustedDecisionContext(
                tenant_id="tenant-b" if kind == "wrong_tenant" else transaction.tenant_id,
                event_id=uuid4() if kind == "wrong_event" else transaction.event_id,
                policy=DecisionPolicy(
                    configuration_version="synthetic-c1",
                    policy_version="synthetic-p1",
                    rule_version="synthetic-r1",
                ),
                intelligence=IntelligenceSnapshot(network_risk=0.99),
                signal_source_version="synthetic-source-v1",
                signal_version="synthetic-signal-v1",
                collected_at=NOW + timedelta(days=1) if kind == "future" else (
                    NOW - timedelta(days=2) if kind == "stale" else NOW
                ),
                expires_at=NOW + timedelta(days=2) if kind == "future" else (
                    NOW - timedelta(days=1) if kind == "stale" else NOW + timedelta(hours=1)
                ),
            )

    app.state.decision_context_provider = BadProvider()
    response = client.post("/v1/decisions", json={"transaction": tx()}, headers=headers())
    assert response.status_code == 503
    events = [e for e in audit.events if e.action == Capability.DECISION_SUBMIT.value]
    assert [e.result for e in events] == ["authorized", "failed"]


def test_context_snapshot_cannot_be_modified_via_mutable_input_or_getter() -> None:
    policy = DecisionPolicy(
        configuration_version="synthetic-c1",
        policy_version="synthetic-p1",
        rule_version="synthetic-r1",
    )
    intelligence = IntelligenceSnapshot(network_risk=0.97)
    context = TrustedDecisionContext(
        tenant_id="tenant-a", event_id=uuid4(),
        policy=policy, intelligence=intelligence,
        signal_source_version="synthetic-source-v1",
        signal_version="synthetic-signal-v1",
        collected_at=NOW, expires_at=NOW + timedelta(minutes=20),
    )
    original_ref = context.context_ref
    policy.block_threshold = 0.99
    intelligence.network_risk = 0.0
    fetched_policy = context.policy
    fetched_signals = context.intelligence
    fetched_policy.block_threshold = 0.99
    fetched_signals.network_risk = 0.0
    assert context.policy.block_threshold == 0.95
    assert context.intelligence.network_risk == 0.97
    assert context.context_ref == original_ref


def test_audit_failure_before_outcome_mutation_blocks_write(wired) -> None:
    client, _, store = wired

    class OfflineAudit:
        def append(self, event) -> None:
            raise RuntimeError("synthetic audit unavailable")

    app.state.security_audit = OfflineAudit()
    event_id = uuid4()
    body = {
        "tenant_id": "tenant-a", "event_id": str(event_id),
        "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
        "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat(),
    }
    response = client.post("/v1/outcomes", json=body, headers=headers())
    assert response.status_code == 503
    assert store.store.outcomes("tenant-a", event_id) == ()


def test_missing_outcome_store_records_terminal_failure(wired) -> None:
    client, audit, _ = wired
    app.state.outcome_ingestion = None
    body = {
        "tenant_id": "tenant-a", "event_id": str(uuid4()),
        "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
        "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat(),
    }
    response = client.post("/v1/outcomes", json=body, headers=headers())
    assert response.status_code == 503
    events = [e for e in audit.events if e.action == Capability.OUTCOME_SUBMIT.value]
    assert [e.result for e in events] == ["authorized", "failed"]
    assert events[0].attempt_ref == events[1].attempt_ref
    assert events[0].event_ref == events[1].event_ref


@pytest.mark.parametrize("incumbent", [False, True])
def test_terminal_audit_outage_never_orphans_protected_outcome(wired, incumbent) -> None:
    client, _, store = wired

    class FailingTerminalAudit(Audit):
        def append(self, event) -> None:
            if event.result == "failed" and event.reason == "transactional_outcome_unavailable":
                raise RuntimeError("synthetic terminal audit outage")
            super().append(event)

    replacement = FailingTerminalAudit()
    app.state.security_audit = replacement
    eid = uuid4()
    path = "/v1/incumbent-outcomes" if incumbent else "/v1/outcomes"
    body = (
        {"tenant_id": "tenant-a", "event_id": str(eid),
         "outcome": "review", "source_system": "synthetic-incumbent"}
        if incumbent else
        {"tenant_id": "tenant-a", "event_id": str(eid),
         "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
         "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat()}
    )
    for _ in range(2):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code == 503
        assert store.store.outcomes("tenant-a", eid) == ()
        assert store.store.incumbent_outcomes("tenant-a", eid) == ()
    assert sum(e.result == "authorized" for e in replacement.events) == 2
    assert not any(e.result == "succeeded" for e in replacement.events)


@pytest.mark.parametrize("incumbent", [False, True])
def test_legacy_store_error_cannot_reach_protected_outcome_route(wired, incumbent) -> None:
    client, audit, _ = wired

    class ExplodingLegacyStore(OutcomeIngestionService):
        def submit(self, record):
            raise RuntimeError("synthetic outcome store outage")

        def submit_incumbent(self, record):
            raise RuntimeError("synthetic incumbent store outage")

    app.state.outcome_ingestion = ExplodingLegacyStore()
    eid = uuid4()
    path = "/v1/incumbent-outcomes" if incumbent else "/v1/outcomes"
    body = (
        {"tenant_id": "tenant-a", "event_id": str(eid),
         "outcome": "review", "source_system": "synthetic-incumbent"}
        if incumbent else
        {"tenant_id": "tenant-a", "event_id": str(eid),
         "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
         "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat()}
    )
    response = client.post(path, json=body, headers=headers())
    assert response.status_code == 503
    assert response.json()["detail"] == "transactional outcome ingestion unavailable"
    assert any(e.reason == "transactional_outcome_unavailable" for e in audit.events)


@pytest.mark.parametrize("incumbent", [False, True])
def test_concurrent_replays_are_denied_without_orphan_mutations(wired, incumbent) -> None:
    client, audit, store = wired
    eid = uuid4()
    path = "/v1/incumbent-outcomes" if incumbent else "/v1/outcomes"
    body = (
        {"tenant_id": "tenant-a", "event_id": str(eid),
         "outcome": "review", "source_system": "synthetic-incumbent"}
        if incumbent else
        {"tenant_id": "tenant-a", "event_id": str(eid),
         "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
         "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat()}
    )
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(
            lambda _: client.post(path, json=body, headers=headers()), range(6),
        ))
    assert all(response.status_code == 503 for response in responses)
    assert store.store.outcomes("tenant-a", eid) == ()
    assert store.store.incumbent_outcomes("tenant-a", eid) == ()
    cap = Capability.INCUMBENT_OUTCOME_SUBMIT if incumbent else Capability.OUTCOME_SUBMIT
    failures = [e for e in audit.events if
                e.action == cap.value and e.reason == "transactional_outcome_unavailable"]
    assert len(failures) == 6
    assert len({e.attempt_ref for e in failures}) == 6
    assert len({e.event_ref for e in failures}) == 1


def test_ready_never_claims_legacy_outcome_store_is_transactional(wired) -> None:
    client, _, _ = wired
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["outcome_atomic_commit"] is False

@pytest.mark.parametrize(
    "path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"]
)
def test_protected_app_disables_public_schema_routes(wired, path: str) -> None:
    """Protected deployments expose no unauthenticated API metadata routes."""
    client, _, _ = wired
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", [
    "/v1/decisions", "/v1/evaluations",
    "/v1/outcomes", "/v1/incumbent-outcomes",
])
@pytest.mark.parametrize(("token", "status", "audit_result"), [
    (None, 401, "denied"),
    ("bad", 401, "denied"),
    ("expired", 401, "denied"),
    ("outage", 503, "denied"),
    ("valid", 422, "verified"),
])
def test_authentication_precedes_malformed_json(
    wired, path: str, token: str | None, status: int, audit_result: str
) -> None:
    """Malformed JSON must never bypass ingress identity verification/auditing."""
    client, audit, _ = wired
    hdr = {"Content-Type": "application/json"}
    if token is not None:
        hdr.update(headers(token))
    response = client.post(path, content="{", headers=hdr)
    assert response.status_code == status
    auth_events = [event for event in audit.events if event.action == "authenticate"]
    assert len(auth_events) == 1
    assert auth_events[0].result == audit_result
    assert len(auth_events[0].attempt_ref) == 32
    assert not any(event.action != "authenticate" for event in audit.events)
    if status == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


def test_dependency_override_cannot_escalate_ingress_identity(wired) -> None:
    """An endpoint dependency override cannot replace a verified low-privilege principal."""
    client, audit, _ = wired
    saved_overrides = dict(app.dependency_overrides)
    app.dependency_overrides[get_principal] = lambda: identity()
    try:
        # No token must still fail at ingress, before the overridden dependency.
        missing = client.post("/v1/decisions", json={"transaction": tx()})
        assert missing.status_code == 401
        # A low-privilege token cannot gain submit via a forged dependency principal.
        denied = client.post(
            "/v1/decisions", json={"transaction": tx()},
            headers=headers("wrong-capability"),
        )
        assert denied.status_code == 403
        assert any(e.reason == "principal_context_mismatch" for e in audit.events)
        assert not any(e.result == "succeeded" for e in audit.events)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved_overrides)


@pytest.mark.parametrize("path", [
    "/v1/decisions", "/v1/evaluations",
    "/v1/outcomes", "/v1/incumbent-outcomes",
])
def test_malformed_json_with_audit_outage_returns_503(wired, path: str) -> None:
    """Even before body parsing, a missing durable audit must fail closed."""
    client, _, _ = wired

    class OfflineAudit:
        def append(self, event) -> None:
            raise RuntimeError("synthetic audit outage")

    app.state.security_audit = OfflineAudit()
    response = client.post(
        path, content="{",
        headers={"Content-Type": "application/json", **headers()},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "security audit unavailable"


# A routed /v1 endpoint can have a URL with a server-configured root_path.
# Authentication must run before FastAPI parses even malformed JSON in both forms.
@pytest.mark.parametrize("root_path", ["/bank", "/gateway/bank"])
@pytest.mark.parametrize("prefix_in_url", [True, False])
@pytest.mark.parametrize("path", [
    "/v1/decisions", "/v1/evaluations",
    "/v1/outcomes", "/v1/incumbent-outcomes",
])
@pytest.mark.parametrize(("token", "status", "result"), [
    (None, 401, "denied"),
    ("bad", 401, "denied"),
    ("revoked", 401, "denied"),
    ("expired", 401, "denied"),
    ("outage", 503, "denied"),
    ("valid", 422, "verified"),
])
def test_root_path_authenticates_before_malformed_body(
    wired, root_path: str, prefix_in_url: bool, path: str,
    token: str | None, status: int, result: str,
) -> None:
    _, audit, _ = wired
    client = TestClient(app, root_path=root_path)
    url = f"{root_path}{path}" if prefix_in_url else path
    request_headers = {"Content-Type": "application/json",
                       "X-Forwarded-Prefix": "/untrusted"}
    if token is not None:
        request_headers.update(headers(token))
    response = client.post(url, content="{", headers=request_headers)
    assert response.status_code == status
    auth_events = [event for event in audit.events if event.action == "authenticate"]
    assert len(auth_events) == 1
    assert auth_events[0].result == result
    assert len(auth_events[0].attempt_ref) == 32
    assert not any(event.action != "authenticate" for event in audit.events)
    assert "tenant-a" not in str(audit.events)
    if status == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("path", [
    "/v1/decisions", "/v1/evaluations",
    "/v1/outcomes", "/v1/incumbent-outcomes",
])
def test_root_path_malformed_body_audit_outage_returns_503(wired, path: str) -> None:
    _, _, _ = wired

    class FailingAudit:
        def append(self, event) -> None:
            raise RuntimeError("synthetic audit failure")

    app.state.security_audit = FailingAudit()
    response = TestClient(app, root_path="/bank").post(
        f"/bank{path}", content="{",
        headers={"Content-Type": "application/json", **headers()},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "security audit unavailable"


@pytest.mark.parametrize("path", ["/v1/decisions", "/v1/evaluations"])
def test_root_path_tenant_role_and_body_spoofing_fail_closed(wired, path: str) -> None:
    _, audit, _ = wired
    client = TestClient(app, root_path="/bank")
    wrong_tenant = client.post(
        f"/bank{path}", json={"transaction": tx("tenant-b")},
        headers={**headers(), "X-Tenant-Id": "tenant-b", "X-Role": "admin"},
    )
    assert wrong_tenant.status_code == 404
    wrong_role = client.post(
        f"/bank{path}", json={"transaction": tx()},
        headers=headers("wrong-capability"),
    )
    assert wrong_role.status_code == 403
    forged_policy = client.post(
        f"/bank{path}",
        json={"transaction": tx(), "policy": {"policy_version": "forged"}},
        headers=headers(),
    )
    assert forged_policy.status_code == 422
    assert not any(event.result == "succeeded" for event in audit.events)
    assert "tenant-b" not in str(audit.events)


def test_root_path_dependency_override_cannot_raise_privilege(wired) -> None:
    _, audit, _ = wired
    client = TestClient(app, root_path="/bank")
    original_overrides = dict(app.dependency_overrides)
    app.dependency_overrides[get_principal] = lambda: identity()
    try:
        missing = client.post(
            "/bank/v1/decisions", json={"transaction": tx()},
        )
        assert missing.status_code == 401
        denied = client.post(
            "/bank/v1/decisions", json={"transaction": tx()},
            headers=headers("wrong-capability"),
        )
        assert denied.status_code == 403
        assert any(e.reason == "principal_context_mismatch" for e in audit.events)
        assert not any(e.result == "succeeded" for e in audit.events)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)


@pytest.mark.parametrize("incumbent", [False, True])
def test_root_path_concurrent_outcome_attempts_never_mutate(wired, incumbent) -> None:
    _, audit, store = wired
    client = TestClient(app, root_path="/bank")
    event_id = uuid4()
    url = "/bank/v1/incumbent-outcomes" if incumbent else "/bank/v1/outcomes"
    body = (
        {"tenant_id": "tenant-a", "event_id": str(event_id),
         "outcome": "review", "source_system": "synthetic-incumbent"}
        if incumbent else
        {"tenant_id": "tenant-a", "event_id": str(event_id),
         "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
         "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat()}
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(
            lambda _: client.post(url, json=body, headers=headers()), range(4),
        ))
    assert all(response.status_code == 503 for response in responses)
    assert store.store.outcomes("tenant-a", event_id) == ()
    assert store.store.incumbent_outcomes("tenant-a", event_id) == ()
    assert len([e for e in audit.events if
                e.reason == "transactional_outcome_unavailable"]) == 4


def test_forwarded_prefix_header_does_not_select_routing_root(wired) -> None:
    _, audit, _ = wired
    client = TestClient(app)
    # Untrusted X-Forwarded-Prefix cannot skip protected ingress auth.
    response = client.post(
        "/v1/decisions", content="{",
        headers={"Content-Type": "application/json", "X-Forwarded-Prefix": "/bank"},
    )
    assert response.status_code == 401
    assert len([e for e in audit.events if e.action == "authenticate"]) == 1
    # An unconfigured prefix cannot cause the protected endpoint to be routed.
    assert client.post(
        "/bank/v1/decisions", content="{",
        headers={"Content-Type": "application/json", "X-Forwarded-Prefix": "/bank"},
    ).status_code == 404


@pytest.mark.parametrize("prefix", ["/bank", "/gateway/bank"])
def test_root_path_shadow_response_and_health_are_unchanged(wired, prefix: str) -> None:
    _, audit, _ = wired
    client = TestClient(app, root_path=prefix)
    healthy = client.get(f"{prefix}/health/live")
    assert healthy.status_code == 200
    assert healthy.json() == {"status": "ok"}
    assert not audit.events
    for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
        assert client.get(f"{prefix}{path}").status_code == 404
    body = tx()
    response = client.post(
        f"{prefix}/v1/evaluations", json={"transaction": body}, headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["operating_mode"] == "shadow"
    assert response.json()["effective_action"] == "no_action_shadow"
    assert len([e for e in audit.events if e.action == "authenticate"]) == 1
    assert len([e for e in audit.events if e.result == "succeeded"]) == 1
    assert len(response.headers["X-Gasha-Context-Ref"]) == 64


def test_context_digest_binds_signal_validity_window() -> None:
    # Different collection/expiry claims must not share the same lineage ref.
    event_id = uuid4()
    policy = DecisionPolicy(
        configuration_version="synthetic-c1",
        policy_version="synthetic-p1",
        rule_version="synthetic-r1",
    )
    signals = IntelligenceSnapshot(network_risk=0.93)

    def context(collected_at: datetime, expires_at: datetime) -> TrustedDecisionContext:
        return TrustedDecisionContext(
            tenant_id="tenant-a", event_id=event_id,
            policy=policy, intelligence=signals,
            signal_source_version="synthetic-source-1",
            signal_version="synthetic-signals-1",
            collected_at=collected_at, expires_at=expires_at,
        )

    collected_at = NOW - timedelta(minutes=10)
    expires_at = NOW + timedelta(minutes=30)
    baseline = context(collected_at, expires_at)
    same_instants = context(
        collected_at.astimezone(timezone(timedelta(hours=3))),
        expires_at.astimezone(timezone(timedelta(hours=3))),
    )
    assert baseline.context_ref == same_instants.context_ref
    assert len(baseline.context_ref) == 64
    assert baseline.context_ref != context(
        collected_at + timedelta(seconds=1), expires_at
    ).context_ref
    assert baseline.context_ref != context(
        collected_at, expires_at + timedelta(seconds=1)
    ).context_ref



def test_context_ref_has_unambiguous_field_tagged_provenance() -> None:
    """Distinct source/version tuples cannot alias by shifting a NUL delimiter."""
    event_id = uuid4()

    def context(source: str, version: str) -> TrustedDecisionContext:
        return TrustedDecisionContext(
            tenant_id="tenant-a", event_id=event_id,
            policy=DecisionPolicy(
                configuration_version="synthetic-config",
                policy_version="synthetic-policy",
                rule_version="synthetic-rules",
            ),
            intelligence=IntelligenceSnapshot(network_risk=0.91),
            signal_source_version=source, signal_version=version,
            collected_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=15),
        )

    left, right = context("source", "scope"), context("source", "scope")
    assert left.context_ref == right.context_ref
    # The constructor rejects these invalid HTTP metadata tokens. Force them
    # into separate instances *only* to regression-test injectivity of the
    # canonical digest under the previously colliding serialized preimages.
    object.__setattr__(left, "signal_source_version", "source\x00version")
    object.__setattr__(left, "signal_version", "scope")
    object.__setattr__(right, "signal_source_version", "source")
    object.__setattr__(right, "signal_version", "version\x00scope")
    assert left.context_ref != right.context_ref
    assert len(left.context_ref) == len(right.context_ref) == 64
    assert context("source", "scope").context_ref != context(
        "source", "scope-v2"
    ).context_ref
    assert context("source", "scope").context_ref != context(
        "source-v2", "scope"
    ).context_ref


@pytest.mark.parametrize("field", ["signal_source_version", "signal_version"])
@pytest.mark.parametrize("bad", ["\x00", "\r", "\n", "\x7f", "\u2603"])
def test_context_constructor_rejects_unsafe_provider_metadata(
    field: str, bad: str,
) -> None:
    values = {
        "signal_source_version": "synthetic-source",
        "signal_version": "synthetic-signal",
    }
    values[field] = f"synthetic{bad}version"
    with pytest.raises(ValueError, match="trusted event-bound decision provenance"):
        TrustedDecisionContext(
            tenant_id="tenant-a", event_id=uuid4(),
            policy=DecisionPolicy(
                configuration_version="synthetic-config",
                policy_version="synthetic-policy",
                rule_version="synthetic-rules",
            ),
            intelligence=IntelligenceSnapshot(network_risk=0.93),
            collected_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=15),
            **values,
        )


@pytest.mark.parametrize("path", ["/v1/decisions", "/v1/evaluations"])
@pytest.mark.parametrize("root_path", ["", "/bank", "/gateway/bank"])
@pytest.mark.parametrize("field", ["signal_source_version", "signal_version"])
@pytest.mark.parametrize("bad", ["\x00", "\r\n", "\x7f", "\u2603"])
def test_protected_routes_reject_unsafe_provider_metadata_before_success_audit(
    wired, path: str, root_path: str, field: str, bad: str,
) -> None:
    client, audit, store = wired

    class MalformedProvider(ContextProvider):
        def resolve(self, transaction, principal):
            result = super().resolve(transaction, principal)
            # An adapter bug can bypass constructor checks on a frozen object.
            # The bank trust boundary must independently recheck the versions.
            object.__setattr__(result, field, f"synthetic{bad}metadata")
            return result

    app.state.decision_context_provider = MalformedProvider()
    response = TestClient(app, root_path=root_path).post(
        f"{root_path}{path}", json={"transaction": tx()}, headers=headers(),
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "decision unavailable"}
    assert "X-Gasha-Context-Ref" not in response.headers
    assert "X-Gasha-Source-Version" not in response.headers
    assert "X-Gasha-Signal-Version" not in response.headers
    auth = [event for event in audit.events if event.action == "authenticate"]
    actions = [
        event for event in audit.events
        if event.action == Capability.DECISION_SUBMIT.value
    ]
    assert len(auth) == 1 and auth[0].result == "verified"
    assert [event.result for event in actions] == ["authorized", "failed"]
    assert [event.reason for event in actions] == [
        "allowed",
        "decision_unavailable" if path.endswith("decisions") else "evaluation_unavailable",
    ]
    assert actions[0].attempt_ref == actions[1].attempt_ref
    assert actions[0].event_ref == actions[1].event_ref
    assert actions[1].context_ref == ""
    assert "synthetic" not in str(actions)
    assert not any(event.result == "succeeded" for event in audit.events)
    assert store.store.outcomes("tenant-a", uuid4()) == ()
