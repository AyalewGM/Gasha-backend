"""Model-backed fused decision service.

``FusedDecisionService`` keeps the exact ``DecisionService`` contract —
the same versioned policy, the same thresholds, the same actions and the
same audit fields — but the fused risk score comes from a trained,
manifest-versioned model instead of ``max(components)``. Component
reason codes are still derived from the intelligence snapshot so model
decisions remain explainable against the same signals, and the model's
top positive score contributors are surfaced as additional reason codes.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
)
from gasha.ml.scorer import ModelScorer, ScoringError

_SIGNAL_COMPONENTS = (
    ("customer", "customer_risk"),
    ("transaction", "transaction_risk"),
    ("velocity", "velocity_risk"),
    ("device_session", "device_session_risk"),
    ("beneficiary", "beneficiary_risk"),
    ("relationship", "relationship_risk"),
    ("network", "network_risk"),
    ("journey", "journey_risk"),
)
_TOP_CONTRIBUTORS = 2


class FusedDecisionService:
    """Deterministic decision policy driven by a model score.

    Construction binds the scorer to the policy's ``model_version``; a
    policy without a model version, or a scorer whose version does not
    match, is rejected so a decision can never carry a score from an
    unexpected artifact.
    """

    def __init__(self, policy: DecisionPolicy, scorer: ModelScorer) -> None:
        if type(policy) is not DecisionPolicy:
            raise ValueError("typed decision policy required")
        if policy.model_version is None:
            raise ValueError("fused decisions require a policy model_version")
        if scorer.model_version != policy.model_version:
            raise ValueError("scorer model_version does not match policy")
        self.policy = policy
        self.scorer = scorer

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> FraudDecision:
        score = self.scorer.score(transaction, intelligence)

        component_reasons = [
            f"HIGH_{name.upper()}_RISK"
            for name, field in _SIGNAL_COMPONENTS
            if getattr(intelligence, field) >= self.policy.review_threshold
        ]
        reasons = list(dict.fromkeys([*evidence_reason_codes, *component_reasons]))
        if score >= self.policy.review_threshold:
            reasons.extend(self._model_reasons(transaction, intelligence))
            reasons = list(dict.fromkeys(reasons))

        if score >= self.policy.block_threshold:
            action = DecisionAction.BLOCK
        elif score >= self.policy.hold_threshold:
            action = DecisionAction.HOLD
        elif score >= self.policy.review_threshold:
            action = DecisionAction.REVIEW
        elif (
            self.policy.challenge_threshold is not None
            and self.policy.challenge_policy_ref is not None
            and transaction.channel in self.policy.challenge_supported_channels
            and score >= self.policy.challenge_threshold
        ):
            # A policy-scoped recommendation; this service cannot dispatch.
            action = DecisionAction.CHALLENGE
            reasons.append("STEP_UP_RECOMMENDATION_ONLY")
        elif score >= self.policy.monitor_threshold:
            action = DecisionAction.MONITOR
        else:
            action = DecisionAction.ALLOW

        return FraudDecision(
            tenant_id=transaction.tenant_id,
            event_id=transaction.event_id,
            action=action,
            risk_score=score,
            reason_codes=reasons or ["NO_HIGH_RISK_SIGNAL"],
            configuration_version=self.policy.configuration_version,
            policy_version=self.policy.policy_version,
            rule_version=self.policy.rule_version,
            model_version=self.policy.model_version,
            decided_at=datetime.now(UTC),
            correlation_id=transaction.correlation_id,
        )

    def _model_reasons(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> list[str]:
        """Maps the top positive score contributors to reason codes."""
        try:
            contributions = self.scorer.contributions(transaction, intelligence)
        except ScoringError:
            return []
        positive = sorted(
            (
                (name, value)
                for name, value in contributions.items()
                if value > 0.0
            ),
            key=lambda item: item[1],
            reverse=True,
        )
        return [
            f"MODEL_{name.upper()}" for name, _ in positive[:_TOP_CONTRIBUTORS]
        ]
