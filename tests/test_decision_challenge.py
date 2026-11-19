"""Step-up (CHALLENGE) action wiring across decision backends."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.decision.fused import FusedDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ml.manifest import OperatingThresholds
from gasha.poc.incumbent import IncumbentScoreBackend


def policy(**overrides: object) -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="cfg-v1",
        policy_version="rules-v1",
        rule_version="rules-v1",
        **overrides,
    )


def tx() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=UUID(int=1),
        occurred_at=datetime(2026, 1, 1, 9, tzinfo=UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(500),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-1",
    )


def snapshot(score: float) -> IntelligenceSnapshot:
    return IntelligenceSnapshot(transaction_risk=score)


class StaticScorer:
    def __init__(self, value: float) -> None:
        self._value = value

    @property
    def model_version(self) -> str:
        return "model-1"

    def score(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> float:
        return self._value

    def contributions(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> Mapping[str, float]:
        return {}


CHALLENGE_POLICY = policy(challenge_threshold=0.60)


def test_rules_service_emits_challenge_when_opted_in() -> None:
    decision = DecisionService(CHALLENGE_POLICY).decide(tx(), snapshot(0.65))
    assert decision.action == DecisionAction.CHALLENGE


def test_challenge_disabled_by_default_keeps_legacy_actions() -> None:
    # A tenant without step-up capability never receives CHALLENGE even
    # when the score would have crossed the (absent) challenge rung.
    decision = DecisionService(policy()).decide(tx(), snapshot(0.65))
    assert decision.action == DecisionAction.MONITOR


def test_challenge_ladder_orders_correctly() -> None:
    service = DecisionService(CHALLENGE_POLICY)
    assert service.decide(tx(), snapshot(0.55)).action == DecisionAction.MONITOR
    assert service.decide(tx(), snapshot(0.60)).action == DecisionAction.CHALLENGE
    assert service.decide(tx(), snapshot(0.75)).action == DecisionAction.REVIEW


def test_fused_service_emits_challenge() -> None:
    fused = FusedDecisionService(
        policy(challenge_threshold=0.60, model_version="model-1"),
        StaticScorer(0.62),
    )
    assert fused.decide(tx(), snapshot(0.0)).action == DecisionAction.CHALLENGE


def test_incumbent_backend_honours_challenge() -> None:
    eid = UUID(int=1)
    backend = IncumbentScoreBackend(CHALLENGE_POLICY, {eid: 0.65})
    assert backend.decide(tx(), snapshot(0.0)).action == DecisionAction.CHALLENGE


@pytest.mark.parametrize("challenge", [0.50, 0.70, 0.45, 0.75])
def test_policy_rejects_challenge_outside_monitor_review(challenge: float) -> None:
    with pytest.raises(ValueError, match="challenge"):
        policy(challenge_threshold=challenge)


def test_operating_thresholds_challenge_optional() -> None:
    thresholds = OperatingThresholds(
        monitor_threshold=0.40,
        challenge_threshold=0.60,
        review_threshold=0.70,
        hold_threshold=0.85,
        block_threshold=0.95,
    )
    assert thresholds.challenge_threshold == pytest.approx(0.60)
    without = OperatingThresholds(
        monitor_threshold=0.40,
        review_threshold=0.70,
        hold_threshold=0.85,
        block_threshold=0.95,
    )
    assert without.challenge_threshold is None


def test_operating_thresholds_rejects_misplaced_challenge() -> None:
    with pytest.raises(ValueError, match="challenge"):
        OperatingThresholds(
            monitor_threshold=0.40,
            challenge_threshold=0.35,
            review_threshold=0.70,
            hold_threshold=0.85,
            block_threshold=0.95,
        )
