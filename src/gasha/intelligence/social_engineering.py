from __future__ import annotations

from pydantic import BaseModel, Field

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
    RiskScore,
)


class SocialEngineeringSignals(BaseModel):
    """Signals observable by the originating institution for the current payment."""

    beneficiary_is_new_to_sender: bool = False
    amount_to_sender_baseline_ratio: float = Field(default=1.0, ge=0.0)
    sender_beneficiary_prior_transfer_count: int = Field(default=0, ge=0)
    beneficiary_unique_senders_1h: int = Field(default=0, ge=0)
    beneficiary_incoming_count_1h: int = Field(default=0, ge=0)
    beneficiary_confirmed_fraud_sender_count: int = Field(default=0, ge=0)
    device_is_new_to_sender: bool | None = None


class SocialEngineeringAssessment(BaseModel):
    intelligence: IntelligenceSnapshot
    reason_codes: list[str]


class SocialEngineeringDetector:
    """Deterministic Phase-A detector; thresholds become tenant config in a later slice."""

    def assess(
        self,
        transaction: CanonicalTransaction,
        signals: SocialEngineeringSignals,
    ) -> SocialEngineeringAssessment:
        reasons: list[str] = []
        transaction_risk: RiskScore = 0.0
        beneficiary_risk: RiskScore = 0.0
        relationship_risk: RiskScore = 0.0
        network_risk: RiskScore = 0.0

        if signals.beneficiary_is_new_to_sender:
            relationship_risk = max(relationship_risk, 0.72)
            reasons.append("NEW_BENEFICIARY")

        if signals.amount_to_sender_baseline_ratio >= 4.0:
            transaction_risk = max(transaction_risk, 0.78)
            reasons.append("AMOUNT_ABOVE_SENDER_BASELINE")

        if (
            signals.beneficiary_is_new_to_sender
            and signals.sender_beneficiary_prior_transfer_count == 0
        ):
            relationship_risk = max(relationship_risk, 0.80)
            reasons.append("NO_PRIOR_SENDER_BENEFICIARY_HISTORY")

        if signals.beneficiary_unique_senders_1h >= 5:
            beneficiary_risk = max(beneficiary_risk, 0.86)
            network_risk = max(network_risk, 0.76)
            reasons.append("BENEFICIARY_MANY_UNIQUE_SENDERS")

        if signals.beneficiary_incoming_count_1h >= 8:
            beneficiary_risk = max(beneficiary_risk, 0.88)
            reasons.append("BENEFICIARY_INCOMING_VELOCITY_SPIKE")

        if signals.beneficiary_confirmed_fraud_sender_count > 0:
            beneficiary_risk = max(beneficiary_risk, 0.96)
            network_risk = max(network_risk, 0.90)
            reasons.append("BENEFICIARY_LINKED_TO_CONFIRMED_FRAUD")

        if signals.device_is_new_to_sender is True:
            transaction_risk = max(transaction_risk, 0.74)
            reasons.append("NEW_DEVICE_FOR_SENDER")

        if transaction.beneficiary_type == BeneficiaryType.EXTERNAL:
            reasons.append("EXTERNAL_BENEFICIARY_OBSERVABLE_SIGNALS_ONLY")

        return SocialEngineeringAssessment(
            intelligence=IntelligenceSnapshot(
                transaction_risk=transaction_risk,
                beneficiary_risk=beneficiary_risk,
                relationship_risk=relationship_risk,
                network_risk=network_risk,
            ),
            reason_codes=reasons or ["NO_SOCIAL_ENGINEERING_SIGNAL"],
        )
