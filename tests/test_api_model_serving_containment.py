"""Protected decision/evaluation routes never activate #144 ML artifacts.

These regressions run without optional xgboost and prove that even a
server-installed registry is not consulted for model-version policies.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
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
from gasha.ml.scorer import ArtifactRegistry
from gasha.security.access import Capability, CredentialRejected, TrustedPrincipal


class _Audit:
    def __init__(self) -> None:
        self.events: list[object] = []

    def append(self, event: object) -> None:
        self.events.append(event)


class _Verifier:
    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer != "valid":
            raise CredentialRejected("invalid synthetic credential")
        return TrustedPrincipal(
            subject="synthetic-analyst",
            issuer="synthetic-test",
            credential_ref="synthetic-test-rotation",
            tenant_ids=frozenset({"tenant-a"}),
            capabilities=frozenset({Capability.DECISION_SUBMIT}),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )


class _Context:
    def __init__(self, policy: DecisionPolicy) -> None:
        self.policy = policy

    def resolve(self, transaction: CanonicalTransaction, principal: TrustedPrincipal
                ) -> TrustedDecisionContext:
        assert transaction.tenant_id in principal.tenant_ids
        now = datetime.now(UTC)
        return TrustedDecisionContext(
            tenant_id=transaction.tenant_id,
            event_id=transaction.event_id,
            signal_source_version="synthetic-source-1",
            signal_version="synthetic-signals-1",
            collected_at=now,
            expires_at=now + timedelta(minutes=30),
            policy=self.policy,
            intelligence=IntelligenceSnapshot(
                **{name: 0.85 for name in IntelligenceSnapshot.model_fields}
            ),
        )


def _payload() -> dict[str, object]:
    return {
        "transaction": CanonicalTransaction(
            tenant_id="tenant-a",
            event_id=uuid4(),
            occurred_at=datetime.now(UTC),
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal("100.00"),
            currency="ETB",
            sender_customer_id="synthetic-customer",
            sender_account_id="synthetic-account",
            beneficiary_id="synthetic-beneficiary",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="synthetic-bank",
            correlation_id="synthetic-correlation",
        ).model_dump(mode="json")
    }


@pytest.fixture
def protected_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    keys = ("identity_verifier", "security_audit",
            "decision_context_provider", "model_registry")
    saved = {key: getattr(app.state, key) for key in keys}
    audit = _Audit()
    app.state.identity_verifier = _Verifier()
    app.state.security_audit = audit
    app.state.model_registry = ArtifactRegistry(tmp_path)
    calls: list[str] = []

    def _resolved(self: ArtifactRegistry, model_version: str):
        calls.append(model_version)
        raise AssertionError("protected API consulted unapproved model registry")

    monkeypatch.setattr(ArtifactRegistry, "resolve", _resolved)
    try:
        yield TestClient(app), audit, calls
    finally:
        for key, value in saved.items():
            setattr(app.state, key, value)


@pytest.mark.parametrize(
    ("endpoint", "detail"),
    [
        ("/v1/decisions", "decision unavailable"),
        ("/v1/evaluations", "evaluation unavailable"),
    ],
)
def test_protected_model_activation_denied_even_with_registry(
    protected_app, endpoint: str, detail: str
) -> None:
    client, audit, calls = protected_app
    app.state.decision_context_provider = _Context(
        DecisionPolicy(
            configuration_version="synthetic-cfg-1",
            policy_version="synthetic-policy-1",
            rule_version="synthetic-rules-1",
            model_version="model-v1",
        )
    )
    response = client.post(
        endpoint,
        json=_payload(),
        headers={"Authorization": "Bearer valid"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": detail}
    assert calls == []  # No artifact lookup or model execution.
    assert any(getattr(e, "result", None) == "failed" for e in audit.events)
    assert not any(getattr(e, "result", None) == "succeeded" for e in audit.events)


@pytest.mark.parametrize("endpoint", ["/v1/decisions", "/v1/evaluations"])
def test_rules_only_remain_deterministic_with_registry_installed(
    protected_app, endpoint: str
) -> None:
    client, audit, calls = protected_app
    app.state.decision_context_provider = _Context(
        DecisionPolicy(
            configuration_version="synthetic-cfg-1",
            policy_version="synthetic-policy-1",
            rule_version="synthetic-rules-1",
        )
    )
    response = client.post(
        endpoint,
        json=_payload(),
        headers={"Authorization": "Bearer valid"},
    )
    assert response.status_code == 200
    body = response.json()
    decision = body if endpoint.endswith("/decisions") else body["decision"]
    assert decision["model_version"] is None
    assert decision["risk_score"] == 0.85
    if endpoint.endswith("/evaluations"):
        assert body["operating_mode"] == "shadow"
        assert body["effective_action"] == "no_action_shadow"
    assert calls == []
    assert any(getattr(e, "result", None) == "succeeded" for e in audit.events)
