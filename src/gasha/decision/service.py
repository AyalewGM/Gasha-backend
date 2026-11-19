from collections.abc import Sequence
from datetime import UTC, datetime

from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
)


def action_for_score(policy: DecisionPolicy, score: float) -> DecisionAction:
    """Maps a fused risk score to an action through the policy threshold ladder."""
    if score >= policy.block_threshold:
        return DecisionAction.BLOCK
    if score >= policy.hold_threshold:
        return DecisionAction.HOLD
    if score >= policy.review_threshold:
        return DecisionAction.REVIEW
    if policy.challenge_threshold is not None and score >= policy.challenge_threshold:
        return DecisionAction.CHALLENGE
    if score >= policy.monitor_threshold:
        return DecisionAction.MONITOR
    return DecisionAction.ALLOW


class DecisionService:
    """Deterministic risk fusion driven by a versioned tenant policy."""

    def __init__(self, policy: DecisionPolicy) -> None:
        self.policy = policy

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> FraudDecision:
        components = {
            "customer": intelligence.customer_risk,
            "transaction": intelligence.transaction_risk,
            "velocity": intelligence.velocity_risk,
            "device_session": intelligence.device_session_risk,
            "beneficiary": intelligence.beneficiary_risk,
            "relationship": intelligence.relationship_risk,
            "network": intelligence.network_risk,
            "journey": intelligence.journey_risk,
        }
        score = max(components.values())
        component_reasons = [
            f"HIGH_{name.upper()}_RISK"
            for name, value in components.items()
            if value >= self.policy.review_threshold
        ]
        reasons = list(dict.fromkeys([*evidence_reason_codes, *component_reasons]))

        action = action_for_score(self.policy, score)

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
