"""Bounded CHALLENGE recommendation tests: no Bank execution authority."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
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
from gasha.poc.historical import (
    ALERT_ACTIONS,
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.incumbent import IncumbentScoreBackend, IncumbentScoreUnavailable
from gasha.poc.replay import SyntheticReplayCase, replay


def policy(**overrides: object) -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="cfg-v1",
        policy_version="rules-v1",
        rule_version="rules-v1",
        **overrides,
    )


def tx(*, tenant: str = "tenant-a", channel: str = "mobile") -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant,
        event_id=UUID(int=1),
        occurred_at=datetime(2026, 1, 1, 9, tzinfo=UTC),
        channel=channel,
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
        self, transaction: CanonicalTransaction, intelligence: IntelligenceSnapshot
    ) -> float:
        return self._value

    def contributions(
        self, transaction: CanonicalTransaction, intelligence: IntelligenceSnapshot
    ) -> Mapping[str, float]:
        return {}


CHALLENGE_POLICY = policy(
    challenge_threshold=0.60,
    challenge_supported_channels=("mobile",),
    challenge_policy_ref="synthetic-authorized-step-up-policy-v1",
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.49, DecisionAction.ALLOW),
        (0.50, DecisionAction.MONITOR),
        (0.5999, DecisionAction.MONITOR),
        (0.60, DecisionAction.CHALLENGE),
        (0.6999, DecisionAction.CHALLENGE),
        (0.70, DecisionAction.REVIEW),
        (0.85, DecisionAction.HOLD),
        (0.95, DecisionAction.BLOCK),
    ],
)
def test_rule_ladder_exact_boundaries(score: float, expected: DecisionAction) -> None:
    decision = DecisionService(CHALLENGE_POLICY).decide(tx(), snapshot(score))
    assert decision.action == expected
    if expected == DecisionAction.CHALLENGE:
        assert "STEP_UP_RECOMMENDATION_ONLY" in decision.reason_codes
    else:
        assert "STEP_UP_RECOMMENDATION_ONLY" not in decision.reason_codes


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.50, DecisionAction.MONITOR),
        (0.60, DecisionAction.CHALLENGE),
        (0.6999, DecisionAction.CHALLENGE),
        (0.70, DecisionAction.REVIEW),
        (0.85, DecisionAction.HOLD),
        (0.95, DecisionAction.BLOCK),
    ],
)
def test_fused_ladder_and_precedence(score: float, expected: DecisionAction) -> None:
    service = FusedDecisionService(
        policy(
            challenge_threshold=0.60,
            challenge_supported_channels=("mobile",),
            challenge_policy_ref="synthetic-authorized-step-up-policy-v1",
            model_version="model-1",
        ),
        StaticScorer(score),
    )
    decision = service.decide(tx(), snapshot(0.0))
    assert decision.action == expected


def test_step_up_is_default_off_and_unsupported_channel_cannot_challenge() -> None:
    assert DecisionService(policy()).decide(tx(), snapshot(0.65)).action == DecisionAction.MONITOR
    assert (
        DecisionService(CHALLENGE_POLICY).decide(tx(channel="atm"), snapshot(0.65)).action
        == DecisionAction.MONITOR
    )
    assert (
        FusedDecisionService(
            policy(
                challenge_threshold=0.60,
                challenge_supported_channels=("mobile",),
                challenge_policy_ref="synthetic-authorized-step-up-policy-v1",
                model_version="model-1",
            ),
            StaticScorer(0.65),
        ).decide(tx(channel="atm"), snapshot(0.0)).action
        == DecisionAction.MONITOR
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"challenge_threshold": 0.60},
        {"challenge_threshold": 0.60, "challenge_supported_channels": ("mobile",)},
        {"challenge_threshold": 0.50, "challenge_supported_channels": ("mobile",), "challenge_policy_ref": "p"},
        {"challenge_threshold": 0.70, "challenge_supported_channels": ("mobile",), "challenge_policy_ref": "p"},
        {"challenge_threshold": 0.60, "challenge_supported_channels": ("mobile", "mobile"), "challenge_policy_ref": "p"},
        {"challenge_threshold": 0.60, "challenge_supported_channels": ("z", "a"), "challenge_policy_ref": "p"},
        {"challenge_threshold": 0.60, "challenge_supported_channels": (" ",), "challenge_policy_ref": "p"},
        {"challenge_threshold": 0.60, "challenge_supported_channels": ("mobile",), "challenge_policy_ref": " p "},
        {"challenge_supported_channels": ("mobile",)},
        {"challenge_policy_ref": "p"},
    ],
)
def test_invalid_or_unapproved_step_up_policy_fails_closed(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        policy(**overrides)


def test_manifest_suggestion_never_enables_step_up() -> None:
    suggested = OperatingThresholds(
        monitor_threshold=0.40,
        challenge_threshold=0.60,
        review_threshold=0.70,
        hold_threshold=0.85,
        block_threshold=0.95,
    )
    assert suggested.challenge_threshold == pytest.approx(0.60)
    assert policy().challenge_threshold is None
    assert DecisionService(policy()).decide(tx(), snapshot(0.65)).action == DecisionAction.MONITOR
    with pytest.raises(ValueError):
        policy(challenge_threshold=suggested.challenge_threshold)
    with pytest.raises(ValueError, match="challenge"):
        OperatingThresholds(
            monitor_threshold=0.40, challenge_threshold=0.35,
            review_threshold=0.70, hold_threshold=0.85, block_threshold=0.95,
        )


def test_challenge_recommendation_not_counted_as_analyst_alert_or_detected_fraud() -> None:
    assert DecisionAction.CHALLENGE not in ALERT_ACTIONS
    t = tx()
    event = HistoricalTransactionEvent(
        transaction=t,
        intelligence=snapshot(0.65),
        label=ConfirmedOutcomeLabel(
            is_fraud=True,
            label_source="synthetic",
            confirmed_at=t.occurred_at + timedelta(days=5),
        ),
    )
    result = replay_historical((event,), {"tenant-a": CHALLENGE_POLICY})
    assert result.results[0].decision.action == DecisionAction.CHALLENGE
    assert result.metrics.true_positives == 0
    assert result.metrics.false_negatives == 1
    assert result.metrics.explained_alerts == 0
    legacy = replay(
        CHALLENGE_POLICY,
        (SyntheticReplayCase(
            scenario_id="offline-challenge", transaction=t,
            intelligence=snapshot(0.65), expected_fraud=True,
        ),),
    )
    assert legacy.true_positives == 0
    assert legacy.false_negatives == 1


def test_incumbent_replay_preserves_merged_tenant_scoped_score_boundary() -> None:
    t = tx()
    scores = {("tenant-a", t.event_id): 0.96, ("tenant-b", t.event_id): 0.01}
    backend = IncumbentScoreBackend(policy(), scores)
    assert backend.decide(t, snapshot(0.0)).action == DecisionAction.BLOCK
    assert (
        backend.decide(tx(tenant="tenant-b"), snapshot(0.0)).action
        == DecisionAction.ALLOW
    )
    with pytest.raises(IncumbentScoreUnavailable):
        IncumbentScoreBackend(policy(), {("tenant-a", t.event_id): 0.96}).decide(
            tx(tenant="tenant-b"), snapshot(0.0)
        )
