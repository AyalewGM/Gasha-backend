from __future__ import annotations

from pydantic import BaseModel, Field

from gasha.domain.models import IntelligenceSnapshot, RiskScore
from gasha.intelligence.provenance import IntelligenceEvidence, SignalProvenance


class InternalGraphSignals(BaseModel):
    """Tenant-observed graph aggregates; no external-bank visibility is implied."""

    unique_senders_to_beneficiary_1h: int = Field(default=0, ge=0)
    incoming_transfers_to_beneficiary_1h: int = Field(default=0, ge=0)
    distinct_accounts_on_device_24h: int = Field(default=0, ge=0)
    confirmed_fraud_neighbors_30d: int = Field(default=0, ge=0)
    rapid_outbound_ratio_1h: float | None = Field(default=None, ge=0.0, le=1.0)
    provenance: SignalProvenance


class InternalGraphPolicy(BaseModel):
    policy_version: str = Field(min_length=1)
    fan_in_unique_senders_threshold: int = Field(default=5, ge=1)
    fan_in_risk: RiskScore = 0.86
    incoming_velocity_threshold: int = Field(default=8, ge=1)
    incoming_velocity_risk: RiskScore = 0.84
    shared_device_accounts_threshold: int = Field(default=3, ge=2)
    shared_device_risk: RiskScore = 0.82
    confirmed_fraud_neighbors_threshold: int = Field(default=1, ge=1)
    confirmed_fraud_neighbor_risk: RiskScore = 0.94
    rapid_outbound_ratio_threshold: float = Field(default=0.80, gt=0.0, le=1.0)
    rapid_outbound_risk: RiskScore = 0.88
    mule_cluster_combination_risk: RiskScore = 0.96


class InternalGraphAssessment(BaseModel):
    intelligence: IntelligenceSnapshot
    reason_codes: list[str]
    signal_policy_version: str
    evidence: list[IntelligenceEvidence]


class InternalGraphDetector:
    """Deterministic mule-network heuristics over precomputed tenant graph aggregates."""

    def __init__(self, policy: InternalGraphPolicy) -> None:
        self.policy = policy

    def assess(self, signals: InternalGraphSignals) -> InternalGraphAssessment:
        reasons: list[str] = []
        beneficiary_risk: RiskScore = 0.0
        network_risk: RiskScore = 0.0

        fan_in = (
            signals.unique_senders_to_beneficiary_1h
            >= self.policy.fan_in_unique_senders_threshold
        )
        if fan_in:
            beneficiary_risk = max(beneficiary_risk, self.policy.fan_in_risk)
            network_risk = max(network_risk, self.policy.fan_in_risk)
            reasons.append("INTERNAL_GRAPH_BENEFICIARY_FAN_IN")

        velocity = (
            signals.incoming_transfers_to_beneficiary_1h
            >= self.policy.incoming_velocity_threshold
        )
        if velocity:
            beneficiary_risk = max(
                beneficiary_risk, self.policy.incoming_velocity_risk
            )
            reasons.append("INTERNAL_GRAPH_INCOMING_VELOCITY")

        shared_device = (
            signals.distinct_accounts_on_device_24h
            >= self.policy.shared_device_accounts_threshold
        )
        if shared_device:
            network_risk = max(network_risk, self.policy.shared_device_risk)
            reasons.append("INTERNAL_GRAPH_SHARED_DEVICE_CLUSTER")

        fraud_neighbors = (
            signals.confirmed_fraud_neighbors_30d
            >= self.policy.confirmed_fraud_neighbors_threshold
        )
        if fraud_neighbors:
            network_risk = max(
                network_risk, self.policy.confirmed_fraud_neighbor_risk
            )
            reasons.append("INTERNAL_GRAPH_CONFIRMED_FRAUD_NEIGHBOR")

        rapid_outbound = (
            signals.rapid_outbound_ratio_1h is not None
            and signals.rapid_outbound_ratio_1h
            >= self.policy.rapid_outbound_ratio_threshold
        )
        if rapid_outbound:
            beneficiary_risk = max(
                beneficiary_risk, self.policy.rapid_outbound_risk
            )
            network_risk = max(network_risk, self.policy.rapid_outbound_risk)
            reasons.append("INTERNAL_GRAPH_RAPID_OUTBOUND_MOVEMENT")

        if fan_in and rapid_outbound:
            beneficiary_risk = max(
                beneficiary_risk, self.policy.mule_cluster_combination_risk
            )
            network_risk = max(
                network_risk, self.policy.mule_cluster_combination_risk
            )
            reasons.append("INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER")

        evidence = [
            IntelligenceEvidence(reason_code=reason, provenance=signals.provenance)
            for reason in reasons
        ]

        return InternalGraphAssessment(
            intelligence=IntelligenceSnapshot(
                beneficiary_risk=beneficiary_risk,
                network_risk=network_risk,
            ),
            reason_codes=reasons or ["NO_INTERNAL_GRAPH_SIGNAL"],
            signal_policy_version=self.policy.policy_version,
            evidence=evidence,
        )
