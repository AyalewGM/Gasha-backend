from datetime import UTC, datetime
from collections.abc import Sequence

from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
)


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
            "beneficiary": intelligence.beneficiary_risk,
            "relationship": intelligence.relationship_risk,
            "network": intelligence.network_risk,
        }
        score = max(components.values())
        component_reasons = [
            f"HIGH_{name.upper()}_RISK"
            for name, value in components.items()
            if value >= self.policy.review_threshold
        ]
        reasons = list(dict.fromkeys([*evidence_reason_codes, *component_reasons]))

        if score >= self.policy.block_threshold:
            action = DecisionAction.BLOCK
        elif score >= self.policy.hold_threshold:
            action = DecisionAction.HOLD
        elif score >= self.policy.review_threshold:
            action = DecisionAction.REVIEW
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
