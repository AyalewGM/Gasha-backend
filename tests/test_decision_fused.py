"""FusedDecisionService tests: model scores drive the same policy contract."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.decision.fused import FusedDecisionService
from gasha.decision.mode import ModeAwareDecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ml.scorer import ScoringError


class FixtureScorer:
    """Deterministic in-memory ModelScorer for decision-path tests."""

    def __init__(
        self,
        value: float,
        *,
        model_version: str = "model-1",
        contribs: Mapping[str, float] | None = None,
        fail: bool = False,
    ) -> None:
        self._value = value
        self._version = model_version
        self._contribs = dict(contribs or {})
        self._fail = fail

    @property
    def model_version(self) -> str:
        return self._version

    def score(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> float:
        if self._fail:
            raise ScoringError("model prediction failed")
        return self._value

    def contributions(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> Mapping[str, float]:
        return self._contribs


def transaction() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(2500),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-7",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-fused",
    )


def snapshot(**changes: float) -> IntelligenceSnapshot:
    values = {name: 0.1 for name in IntelligenceSnapshot.model_fields}
    values.update(changes)
    return IntelligenceSnapshot(**values)


def policy(**changes: object) -> DecisionPolicy:
    values: dict[str, object] = {
        "configuration_version": "config-1",
        "policy_version": "policy-1",
        "rule_version": "rules-1",
        "model_version": "model-1",
    }
    values.update(changes)
    return DecisionPolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("score", "action"),
    [
        (0.10, DecisionAction.ALLOW),
        (0.55, DecisionAction.MONITOR),
        (0.75, DecisionAction.REVIEW),
        (0.90, DecisionAction.HOLD),
        (0.99, DecisionAction.BLOCK),
    ],
)
def test_model_score_maps_through_policy_thresholds(
    score: float, action: DecisionAction
) -> None:
    service = FusedDecisionService(policy(), FixtureScorer(score))
    decision = service.decide(transaction(), snapshot())
    assert decision.action is action
    assert decision.risk_score == score
    assert decision.model_version == "model-1"


def test_component_and_model_reason_codes_are_emitted() -> None:
    service = FusedDecisionService(
        policy(),
        FixtureScorer(
            0.80,
            contribs={
                "velocity_risk": 1.2,
                "journey_risk": 0.9,
                "log_amount": -0.4,
            },
        ),
    )
    decision = service.decide(
        transaction(),
        snapshot(velocity_risk=0.95),
        evidence_reason_codes=["RISK_LIST_MATCH"],
    )
    assert "RISK_LIST_MATCH" in decision.reason_codes
    assert "HIGH_VELOCITY_RISK" in decision.reason_codes
    assert "MODEL_VELOCITY_RISK" in decision.reason_codes
    assert "MODEL_JOURNEY_RISK" in decision.reason_codes
    # Only top-2 positive contributors; negative contributors never alert.
    assert "MODEL_LOG_AMOUNT" not in decision.reason_codes


def test_model_reasons_absent_below_review_threshold() -> None:
    service = FusedDecisionService(
        policy(), FixtureScorer(0.60, contribs={"velocity_risk": 1.0})
    )
    decision = service.decide(transaction(), snapshot())
    assert decision.action is DecisionAction.MONITOR
    assert not any(code.startswith("MODEL_") for code in decision.reason_codes)


def test_version_binding_is_enforced_at_construction() -> None:
    with pytest.raises(ValueError, match="model_version"):
        FusedDecisionService(
            policy(model_version=None), FixtureScorer(0.5, model_version="model-1")
        )
    with pytest.raises(ValueError, match="does not match"):
        FusedDecisionService(
            policy(model_version="model-1"),
            FixtureScorer(0.5, model_version="model-2"),
        )


def test_scorer_failure_propagates_fail_closed() -> None:
    service = FusedDecisionService(policy(), FixtureScorer(0.0, fail=True))
    with pytest.raises(ScoringError):
        service.decide(transaction(), snapshot())


def test_shadow_mode_records_model_decision_without_enforcing() -> None:
    fused = FusedDecisionService(policy(), FixtureScorer(0.99))
    service = ModeAwareDecisionService(
        policy(), operating_mode=OperatingMode.SHADOW, service=fused
    )
    envelope = service.decide(transaction(), snapshot())
    assert envelope.decision.action is DecisionAction.BLOCK
    assert envelope.decision.model_version == "model-1"
    assert envelope.effective_action is DecisionAction.NO_ACTION_SHADOW
    assert envelope.operating_mode is OperatingMode.SHADOW
