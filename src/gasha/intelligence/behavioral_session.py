from __future__ import annotations

from pydantic import BaseModel, Field

from gasha.domain.models import IntelligenceSnapshot, RiskScore
from gasha.intelligence.provenance import IntelligenceEvidence, SignalProvenance


class BehavioralSessionSignals(BaseModel):
    """Optional SDK-agnostic observations available during a payment session."""

    hesitation_seconds: float | None = Field(default=None, ge=0.0)
    active_call_indicator: bool | None = None
    remote_access_indicator: bool | None = None
    behavioral_anomaly_score: RiskScore | None = None
    provenance: SignalProvenance


class BehavioralSessionPolicy(BaseModel):
    policy_version: str = Field(min_length=1)
    hesitation_threshold_seconds: float = Field(default=12.0, gt=0.0)
    hesitation_risk: RiskScore = 0.68
    active_call_risk: RiskScore = 0.72
    remote_access_risk: RiskScore = 0.90
    behavioral_anomaly_threshold: RiskScore = 0.75
    behavioral_anomaly_risk: RiskScore = 0.78
    coached_payment_combination_risk: RiskScore = 0.92


class BehavioralSessionAssessment(BaseModel):
    intelligence: IntelligenceSnapshot
    reason_codes: list[str]
    signal_policy_version: str
    evidence: list[IntelligenceEvidence]


class BehavioralSessionDetector:
    """Deterministic scoring for optional behavioral and session telemetry."""

    def __init__(self, policy: BehavioralSessionPolicy) -> None:
        self.policy = policy

    def assess(self, signals: BehavioralSessionSignals) -> BehavioralSessionAssessment:
        reasons: list[str] = []
        transaction_risk: RiskScore = 0.0

        high_hesitation = (
            signals.hesitation_seconds is not None
            and signals.hesitation_seconds >= self.policy.hesitation_threshold_seconds
        )
        if high_hesitation:
            transaction_risk = max(transaction_risk, self.policy.hesitation_risk)
            reasons.append("UNUSUAL_PAYMENT_HESITATION")

        if signals.active_call_indicator is True:
            transaction_risk = max(transaction_risk, self.policy.active_call_risk)
            reasons.append("ACTIVE_CALL_DURING_PAYMENT")

        if signals.remote_access_indicator is True:
            transaction_risk = max(transaction_risk, self.policy.remote_access_risk)
            reasons.append("REMOTE_ACCESS_INDICATOR")

        if (
            signals.behavioral_anomaly_score is not None
            and signals.behavioral_anomaly_score
            >= self.policy.behavioral_anomaly_threshold
        ):
            transaction_risk = max(
                transaction_risk, self.policy.behavioral_anomaly_risk
            )
            reasons.append("BEHAVIORAL_BIOMETRIC_ANOMALY")

        if (
            high_hesitation
            and signals.active_call_indicator is True
            and signals.behavioral_anomaly_score is not None
            and signals.behavioral_anomaly_score
            >= self.policy.behavioral_anomaly_threshold
        ):
            transaction_risk = max(
                transaction_risk, self.policy.coached_payment_combination_risk
            )
            reasons.append("POSSIBLE_LIVE_COACHING_PATTERN")

        evidence = [
            IntelligenceEvidence(reason_code=reason, provenance=signals.provenance)
            for reason in reasons
        ]

        return BehavioralSessionAssessment(
            intelligence=IntelligenceSnapshot(transaction_risk=transaction_risk),
            reason_codes=reasons or ["NO_BEHAVIORAL_SESSION_SIGNAL"],
            signal_policy_version=self.policy.policy_version,
            evidence=evidence,
        )
