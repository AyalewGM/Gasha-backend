from datetime import UTC, datetime

from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    FraudDecision,
    IntelligenceSnapshot,
)


class DecisionService:
    """Deterministic M1 fusion policy; replaceable without changing API contracts."""

    RULE_VERSION = "m1.0"

    def decide(
        self, transaction: CanonicalTransaction, intelligence: IntelligenceSnapshot
    ) -> FraudDecision:
        components = {
            "customer": intelligence.customer_risk,
            "transaction": intelligence.transaction_risk,
            "beneficiary": intelligence.beneficiary_risk,
            "relationship": intelligence.relationship_risk,
            "network": intelligence.network_risk,
        }
        score = max(components.values())
        reasons = [f"HIGH_{name.upper()}_RISK" for name, value in components.items() if value >= 0.8]

        if score >= 0.95:
            action = DecisionAction.BLOCK
        elif score >= 0.85:
            action = DecisionAction.HOLD
        elif score >= 0.70:
            action = DecisionAction.REVIEW
        elif score >= 0.50:
            action = DecisionAction.MONITOR
        else:
            action = DecisionAction.ALLOW

        return FraudDecision(
            event_id=transaction.event_id,
            action=action,
            risk_score=score,
            reason_codes=reasons or ["NO_HIGH_RISK_SIGNAL"],
            rule_version=self.RULE_VERSION,
            decided_at=datetime.now(UTC),
            correlation_id=transaction.correlation_id,
        )
