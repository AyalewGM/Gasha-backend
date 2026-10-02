from __future__ import annotations

from pydantic import BaseModel, Field

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
    RiskScore,
)
from gasha.intelligence.provenance import IntelligenceEvidence, SignalProvenance


class SocialEngineeringSignals(BaseModel):
    """Signals observable by the originating institution for the current payment."""

    beneficiary_is_new_to_sender: bool = False
    amount_to_sender_baseline_ratio: float = Field(default=1.0, ge=0.0)
    sender_beneficiary_prior_transfer_count: int = Field(default=0, ge=0)
    beneficiary_unique_senders_1h: int = Field(default=0, ge=0)
    beneficiary_incoming_count_1h: int = Field(default=0, ge=0)
    beneficiary_confirmed_fraud_sender_count: int = Field(default=0, ge=0)
    device_is_new_to_sender: bool | None = None
    provenance: SignalProvenance


class SocialEngineeringPolicy(BaseModel):
    """Versioned tenant policy for deterministic social-engineering signal scoring."""

    policy_version: str = Field(min_length=1)
    new_beneficiary_risk: RiskScore = 0.72
    amount_baseline_ratio_threshold: float = Field(default=4.0, gt=0.0)
    amount_baseline_risk: RiskScore = 0.78
    no_prior_relationship_risk: RiskScore = 0.80
    unique_senders_1h_threshold: int = Field(default=5, ge=1)
    unique_senders_beneficiary_risk: RiskScore = 0.86
    unique_senders_network_risk: RiskScore = 0.76
    incoming_count_1h_threshold: int = Field(default=8, ge=1)
    incoming_velocity_risk: RiskScore = 0.88
    confirmed_fraud_sender_count_threshold: int = Field(default=1, ge=1)
    confirmed_fraud_beneficiary_risk: RiskScore = 0.96
    confirmed_fraud_network_risk: RiskScore = 0.90
    new_device_risk: RiskScore = 0.74


class SocialEngineeringAssessment(BaseModel):
    intelligence: IntelligenceSnapshot
    reason_codes: list[str]
    signal_policy_version: str
    evidence: list[IntelligenceEvidence]


class SocialEngineeringDetector:
    """Deterministic detector driven by versioned tenant signal policy."""

    def __init__(self, policy: SocialEngineeringPolicy) -> None:
        self.policy = policy

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
            relationship_risk = max(
                relationship_risk, self.policy.new_beneficiary_risk
            )
            reasons.append("NEW_BENEFICIARY")

        if (
            signals.amount_to_sender_baseline_ratio
            >= self.policy.amount_baseline_ratio_threshold
        ):
            transaction_risk = max(transaction_risk, self.policy.amount_baseline_risk)
            reasons.append("AMOUNT_ABOVE_SENDER_BASELINE")

        if (
            signals.beneficiary_is_new_to_sender
            and signals.sender_beneficiary_prior_transfer_count == 0
        ):
            relationship_risk = max(
                relationship_risk, self.policy.no_prior_relationship_risk
            )
            reasons.append("NO_PRIOR_SENDER_BENEFICIARY_HISTORY")

        if (
            signals.beneficiary_unique_senders_1h
            >= self.policy.unique_senders_1h_threshold
        ):
            beneficiary_risk = max(
                beneficiary_risk, self.policy.unique_senders_beneficiary_risk
            )
            network_risk = max(network_risk, self.policy.unique_senders_network_risk)
            reasons.append("BENEFICIARY_MANY_UNIQUE_SENDERS")

        if (
            signals.beneficiary_incoming_count_1h
            >= self.policy.incoming_count_1h_threshold
        ):
            beneficiary_risk = max(
                beneficiary_risk, self.policy.incoming_velocity_risk
            )
            reasons.append("BENEFICIARY_INCOMING_VELOCITY_SPIKE")

        if (
            signals.beneficiary_confirmed_fraud_sender_count
            >= self.policy.confirmed_fraud_sender_count_threshold
        ):
            beneficiary_risk = max(
                beneficiary_risk, self.policy.confirmed_fraud_beneficiary_risk
            )
            network_risk = max(
                network_risk, self.policy.confirmed_fraud_network_risk
            )
            reasons.append("BENEFICIARY_LINKED_TO_CONFIRMED_FRAUD")

        if signals.device_is_new_to_sender is True:
            transaction_risk = max(transaction_risk, self.policy.new_device_risk)
            reasons.append("NEW_DEVICE_FOR_SENDER")

        if transaction.beneficiary_type == BeneficiaryType.EXTERNAL:
            reasons.append("EXTERNAL_BENEFICIARY_OBSERVABLE_SIGNALS_ONLY")

        evidence = [
            IntelligenceEvidence(reason_code=reason, provenance=signals.provenance)
            for reason in reasons
            if reason != "EXTERNAL_BENEFICIARY_OBSERVABLE_SIGNALS_ONLY"
        ]

        return SocialEngineeringAssessment(
            intelligence=IntelligenceSnapshot(
                transaction_risk=transaction_risk,
                beneficiary_risk=beneficiary_risk,
                relationship_risk=relationship_risk,
                network_risk=network_risk,
            ),
            reason_codes=reasons or ["NO_SOCIAL_ENGINEERING_SIGNAL"],
            signal_policy_version=self.policy.policy_version,
            evidence=evidence,
        )
