"""#144: protected routes reject model serving even with a trained registry.

The offline research artifact can exist but has no protected API activation
authority. Deterministic decisions remain available for model-free policies.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest

try:
    import xgboost as _xgboost  # noqa: F401
except Exception:  # noqa: BLE001 -- xgboost raises XGBoostError, not ImportError, when libomp is missing
    pytest.skip(
        "ml optional dependency not installed or unusable",
        allow_module_level=True,
    )

from fastapi.testclient import TestClient

from gasha.api.main import TrustedDecisionContext, app
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ml.scorer import ArtifactRegistry
from gasha.ml.train import TrainingParams, train_model
from gasha.poc.historical import ConfirmedOutcomeLabel, HistoricalTransactionEvent
from gasha.security.access import Capability, CredentialRejected, TrustedPrincipal

NOW = datetime.now(UTC)
AT = datetime(2026, 1, 1, 9, tzinfo=UTC)
CUTOFF = AT + timedelta(days=30)


class Audit:
    def __init__(self) -> None:
        self.events = []

    def append(self, event) -> None:
        self.events.append(event)


class Verifier:
    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer != "valid":
            raise CredentialRejected("unrecognized or revoked")
        return TrustedPrincipal(
            subject="synthetic-api-client",
            issuer="synthetic-only-test",
            credential_ref="synthetic-rotation-v1",
            tenant_ids=frozenset({"tenant-a"}),
            capabilities=frozenset({Capability.DECISION_SUBMIT}),
            expires_at=NOW + timedelta(hours=1),
        )


class ContextProvider:
    def __init__(
        self, policy: DecisionPolicy, intelligence: IntelligenceSnapshot | None = None
    ) -> None:
        self._policy = policy
        self._intelligence = intelligence or IntelligenceSnapshot(
            **{name: 0.85 for name in IntelligenceSnapshot.model_fields}
        )

    def resolve(self, transaction, principal) -> TrustedDecisionContext:
        assert transaction.tenant_id in principal.tenant_ids
        return TrustedDecisionContext(
            tenant_id=transaction.tenant_id,
            event_id=transaction.event_id,
            signal_source_version="synthetic-source-1",
            signal_version="synthetic-signal-v1",
            collected_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
            policy=self._policy,
            intelligence=self._intelligence,
        )


def event(number: int, *, fraud: bool) -> HistoricalTransactionEvent:
    occurred = AT + timedelta(minutes=number)
    base = 0.75 if fraud else 0.05
    snapshot = IntelligenceSnapshot(
        customer_risk=base,
        transaction_risk=base,
        velocity_risk=base,
        device_session_risk=base,
        beneficiary_risk=base,
        relationship_risk=0.05,
        network_risk=base,
        journey_risk=base,
    )
    return HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id="tenant-a",
            event_id=UUID(int=number + 1),
            occurred_at=occurred,
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal(9000 if fraud else 40),
            currency="ETB",
            sender_customer_id=f"customer-{number % 11}",
            sender_account_id=f"account-{number % 11}",
            beneficiary_id=f"beneficiary-{number % 13}",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="external-bank",
            correlation_id=f"corr-{number}",
        ),
        intelligence=snapshot,
        received_at=occurred + timedelta(seconds=1),
        label=ConfirmedOutcomeLabel(
            is_fraud=fraud,
            label_source="synthetic-analyst",
            confirmed_at=occurred + timedelta(days=5),
        ),
    )


def train_artifact(root: Path, version: str = "model-v1") -> None:
    train_model(
        [event(n, fraud=(n % 5 == 0)) for n in range(120)],
        label_cutoff=CUTOFF,
        model_version=version,
        artifact_dir=root / version,
        params=TrainingParams(num_boost_round=60, early_stopping_rounds=10),
    )


def tx() -> dict[str, object]:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=NOW,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("9000.00"),
        currency="ETB",
        sender_customer_id="synthetic-customer",
        sender_account_id="synthetic-account",
        beneficiary_id="synthetic-beneficiary",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="synthetic-destination",
        correlation_id="synthetic-correlation",
    ).model_dump(mode="json")


@pytest.fixture
def wired(tmp_path: Path):
    train_artifact(tmp_path)
    saved = tuple(
        getattr(app.state, key)
        for key in (
            "identity_verifier",
            "security_audit",
            "decision_context_provider",
            "model_registry",
        )
    )
    audit = Audit()
    app.state.security_audit = audit
    app.state.identity_verifier = Verifier()
    app.state.model_registry = ArtifactRegistry(tmp_path)
    try:
        yield TestClient(app), audit
    finally:
        (
            app.state.identity_verifier,
            app.state.security_audit,
            app.state.decision_context_provider,
            app.state.model_registry,
        ) = saved


def model_policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="synthetic-config-1",
        policy_version="synthetic-policy-1",
        rule_version="synthetic-rules-1",
        model_version="model-v1",
        monitor_threshold=0.10,
        review_threshold=0.30,
        hold_threshold=0.60,
        block_threshold=0.90,
    )


def test_trained_registry_cannot_activate_model_in_protected_decision(wired) -> None:
    client, audit = wired
    app.state.decision_context_provider = ContextProvider(model_policy())

    response = client.post(
        "/v1/decisions",
        json={"transaction": tx()},
        headers={"Authorization": "Bearer valid"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "decision unavailable"}
    assert any(e.result == "failed" for e in audit.events)
    assert not any(e.result == "succeeded" for e in audit.events)


def test_trained_registry_cannot_activate_model_in_protected_evaluation(wired) -> None:
    client, audit = wired
    app.state.decision_context_provider = ContextProvider(model_policy())

    response = client.post(
        "/v1/evaluations",
        json={"transaction": tx()},
        headers={"Authorization": "Bearer valid"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "evaluation unavailable"}
    assert any(e.result == "failed" for e in audit.events)
    assert not any(e.result == "succeeded" for e in audit.events)


def test_model_policy_without_registry_fails_closed(wired) -> None:
    client, _ = wired
    app.state.decision_context_provider = ContextProvider(model_policy())
    app.state.model_registry = None

    response = client.post(
        "/v1/decisions",
        json={"transaction": tx()},
        headers={"Authorization": "Bearer valid"},
    )

    assert response.status_code == 503


def test_model_policy_with_missing_artifact_fails_closed(wired) -> None:
    client, _ = wired
    app.state.decision_context_provider = ContextProvider(
        model_policy().model_copy(update={"model_version": "model-absent"})
    )

    response = client.post(
        "/v1/decisions",
        json={"transaction": tx()},
        headers={"Authorization": "Bearer valid"},
    )

    assert response.status_code == 503


def test_rules_policy_still_uses_deterministic_fusion(wired) -> None:
    client, _ = wired
    rules_policy = DecisionPolicy(
        configuration_version="synthetic-config-1",
        policy_version="synthetic-policy-1",
        rule_version="synthetic-rules-1",
    )
    app.state.decision_context_provider = ContextProvider(rules_policy)

    response = client.post(
        "/v1/decisions",
        json={"transaction": tx()},
        headers={"Authorization": "Bearer valid"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["model_version"] is None
    assert body["risk_score"] == 0.85  # max(components)
    assert body["action"] == "hold"
