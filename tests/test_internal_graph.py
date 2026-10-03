from datetime import UTC, datetime

from gasha.intelligence.internal_graph import (
    InternalGraphDetector,
    InternalGraphPolicy,
    InternalGraphSignals,
)
from gasha.intelligence.provenance import (
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)


def provenance() -> SignalProvenance:
    return SignalProvenance(
        source=IntelligenceSource.TENANT_NETWORK,
        scope=IntelligenceScope.TENANT_OBSERVED,
        observed_at=datetime.now(UTC),
        source_version="internal-graph-features-1",
        confidence=0.93,
    )


def test_no_graph_anomaly_produces_no_risk() -> None:
    assessment = InternalGraphDetector(
        InternalGraphPolicy(policy_version="graph-policy-1")
    ).assess(InternalGraphSignals(provenance=provenance()))

    assert assessment.intelligence.beneficiary_risk == 0.0
    assert assessment.intelligence.network_risk == 0.0
    assert assessment.reason_codes == ["NO_INTERNAL_GRAPH_SIGNAL"]


def test_fan_in_and_rapid_outbound_identifies_possible_mule_cluster() -> None:
    assessment = InternalGraphDetector(
        InternalGraphPolicy(policy_version="graph-policy-2")
    ).assess(
        InternalGraphSignals(
            unique_senders_to_beneficiary_1h=9,
            incoming_transfers_to_beneficiary_1h=12,
            rapid_outbound_ratio_1h=0.91,
            provenance=provenance(),
        )
    )

    assert assessment.intelligence.beneficiary_risk == 0.96
    assert assessment.intelligence.network_risk == 0.96
    assert "INTERNAL_GRAPH_BENEFICIARY_FAN_IN" in assessment.reason_codes
    assert "INTERNAL_GRAPH_RAPID_OUTBOUND_MOVEMENT" in assessment.reason_codes
    assert "INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER" in assessment.reason_codes
    assert all(
        item.provenance.scope == IntelligenceScope.TENANT_OBSERVED
        for item in assessment.evidence
    )


def test_shared_device_and_fraud_neighbor_raise_network_risk() -> None:
    assessment = InternalGraphDetector(
        InternalGraphPolicy(policy_version="graph-policy-3")
    ).assess(
        InternalGraphSignals(
            distinct_accounts_on_device_24h=4,
            confirmed_fraud_neighbors_30d=2,
            provenance=provenance(),
        )
    )

    assert assessment.intelligence.network_risk == 0.94
    assert "INTERNAL_GRAPH_SHARED_DEVICE_CLUSTER" in assessment.reason_codes
    assert "INTERNAL_GRAPH_CONFIRMED_FRAUD_NEIGHBOR" in assessment.reason_codes


def test_tenant_policy_changes_fan_in_threshold_without_bank_logic() -> None:
    observed = InternalGraphSignals(
        unique_senders_to_beneficiary_1h=6,
        provenance=provenance(),
    )

    sensitive = InternalGraphDetector(
        InternalGraphPolicy(
            policy_version="tenant-a-graph-2",
            fan_in_unique_senders_threshold=5,
        )
    ).assess(observed)
    tolerant = InternalGraphDetector(
        InternalGraphPolicy(
            policy_version="tenant-b-graph-4",
            fan_in_unique_senders_threshold=10,
        )
    ).assess(observed)

    assert sensitive.intelligence.network_risk == 0.86
    assert tolerant.intelligence.network_risk == 0.0


def test_graph_contract_does_not_require_external_bank_data() -> None:
    signals = InternalGraphSignals(
        unique_senders_to_beneficiary_1h=5,
        provenance=provenance(),
    )

    assert signals.provenance.source == IntelligenceSource.TENANT_NETWORK
    assert signals.provenance.scope == IntelligenceScope.TENANT_OBSERVED
