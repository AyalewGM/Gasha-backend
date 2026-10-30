"""#42 HTTP-level negative and positive tests, using only synthetic credentials."""
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import TrustedDecisionContext, app
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
    evaluation = client.post("/v1/evaluations", json=payload, headers=headers())
    assert evaluation.status_code == 200
    assert evaluation.json()["decision"]["action"] == "block"
    assert evaluation.json()["operating_mode"] == "shadow"
    assert evaluation.json()["effective_action"] == "no_action_shadow"
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


def test_authorized_outcome_ingestion_and_denied_mutations(wired) -> None:
    client, audit, store = wired
    eid = uuid4()
    body = {
        "tenant_id": "tenant-a", "event_id": str(eid),
        "outcome": "confirmed_fraud", "outcome_source": "synthetic-review",
        "outcome_version": "synthetic-v1", "confirmed_at": NOW.isoformat(),
    }
    forbidden = client.post("/v1/outcomes", json=body, headers=headers("wrong-capability"))
    assert forbidden.status_code == 403
    assert store.store.outcomes("tenant-a", eid) == ()
    unauthorized = client.post(
        "/v1/outcomes", json={**body, "tenant_id": "tenant-b"}, headers=headers(),
    )
    assert unauthorized.status_code == 404
    assert store.store.outcomes("tenant-b", eid) == ()
    accepted = client.post("/v1/outcomes", json=body, headers=headers())
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "accepted"
    repeated = client.post("/v1/outcomes", json=body, headers=headers())
    assert repeated.json()["status"] == "duplicate"
    assert any(e.result == "denied" for e in audit.events)


def test_incumbent_outcome_has_separate_capability(wired) -> None:
    client, _, _ = wired
    body = {
        "tenant_id": "tenant-a", "event_id": str(uuid4()),
        "outcome": "review", "source_system": "synthetic-incumbent",
    }
    assert client.post("/v1/incumbent-outcomes", json=body, headers=headers()).status_code == 200
    assert client.post(
        "/v1/incumbent-outcomes", json=body, headers=headers("wrong-capability"),
    ).status_code == 403


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
