from datetime import UTC, datetime

from gasha.intelligence.behavioral_session import (
    BehavioralSessionDetector,
    BehavioralSessionPolicy,
    BehavioralSessionSignals,
)
from gasha.intelligence.provenance import (
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)


def provenance() -> SignalProvenance:
    return SignalProvenance(
        source=IntelligenceSource.TENANT_BEHAVIORAL,
        scope=IntelligenceScope.TENANT_OBSERVED,
        observed_at=datetime.now(UTC),
        source_version="mobile-telemetry-1",
        confidence=0.90,
    )


def test_unavailable_optional_telemetry_does_not_create_risk() -> None:
    assessment = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="behavioral-policy-1")
    ).assess(BehavioralSessionSignals(provenance=provenance()))

    assert assessment.intelligence.transaction_risk == 0.0
    assert assessment.reason_codes == ["NO_BEHAVIORAL_SESSION_SIGNAL"]
    assert assessment.evidence == []


def test_remote_access_indicator_is_generic_not_vendor_specific() -> None:
    assessment = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="behavioral-policy-1")
    ).assess(
        BehavioralSessionSignals(
            remote_access_indicator=True,
            provenance=provenance(),
        )
    )

    assert assessment.intelligence.transaction_risk == 0.90
    assert "REMOTE_ACCESS_INDICATOR" in assessment.reason_codes
    assert assessment.evidence[0].provenance.source_version == "mobile-telemetry-1"


def test_live_coaching_pattern_combines_available_session_evidence() -> None:
    assessment = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="behavioral-policy-2")
    ).assess(
        BehavioralSessionSignals(
            hesitation_seconds=19.0,
            active_call_indicator=True,
            behavioral_anomaly_score=0.84,
            provenance=provenance(),
        )
    )

    assert assessment.intelligence.transaction_risk == 0.92
    assert "UNUSUAL_PAYMENT_HESITATION" in assessment.reason_codes
    assert "ACTIVE_CALL_DURING_PAYMENT" in assessment.reason_codes
    assert "BEHAVIORAL_BIOMETRIC_ANOMALY" in assessment.reason_codes
    assert "POSSIBLE_LIVE_COACHING_PATTERN" in assessment.reason_codes
    assert assessment.signal_policy_version == "behavioral-policy-2"


def test_tenant_policy_controls_hesitation_threshold() -> None:
    observed = BehavioralSessionSignals(
        hesitation_seconds=15.0,
        provenance=provenance(),
    )

    sensitive = BehavioralSessionDetector(
        BehavioralSessionPolicy(
            policy_version="tenant-a-behavioral-3",
            hesitation_threshold_seconds=10.0,
        )
    ).assess(observed)
    tolerant = BehavioralSessionDetector(
        BehavioralSessionPolicy(
            policy_version="tenant-b-behavioral-1",
            hesitation_threshold_seconds=20.0,
        )
    ).assess(observed)

    assert sensitive.intelligence.transaction_risk == 0.68
    assert tolerant.intelligence.transaction_risk == 0.0
