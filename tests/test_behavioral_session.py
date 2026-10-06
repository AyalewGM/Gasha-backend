from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
)
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


def transaction() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("1250.00"),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-9",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-behavioral-session",
    )


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-9",
        policy_version="decision-policy-5",
        rule_version="rules-4",
    )


def test_unavailable_optional_telemetry_does_not_create_risk() -> None:
    assessment = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="behavioral-policy-1")
    ).assess(BehavioralSessionSignals(provenance=provenance()))

    assert assessment.intelligence.device_session_risk == 0.0
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

    assert assessment.intelligence.device_session_risk == 0.90
    assert "REMOTE_ACCESS_INDICATOR" in assessment.reason_codes
    assert assessment.evidence[0].provenance.source_version == "mobile-telemetry-1"


def test_session_risk_is_first_class_device_session_signal_in_decision() -> None:
    tx = transaction()
    assessment = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="behavioral-policy-1")
    ).assess(
        BehavioralSessionSignals(
            remote_access_indicator=True,
            provenance=provenance(),
        )
    )

    decision = DecisionService(policy()).decide(
        tx, assessment.intelligence, assessment.reason_codes
    )

    assert decision.action == DecisionAction.HOLD
    assert decision.risk_score == 0.90
    assert "HIGH_DEVICE_SESSION_RISK" in decision.reason_codes
    assert "REMOTE_ACCESS_INDICATOR" in decision.reason_codes


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

    assert assessment.intelligence.device_session_risk == 0.92
    assert "UNUSUAL_PAYMENT_HESITATION" in assessment.reason_codes
    assert "ACTIVE_CALL_DURING_PAYMENT" in assessment.reason_codes
    assert "BEHAVIORAL_BIOMETRIC_ANOMALY" in assessment.reason_codes
    assert "POSSIBLE_LIVE_COACHING_PATTERN" in assessment.reason_codes
    assert assessment.signal_policy_version == "behavioral-policy-2"


def test_remote_access_during_call_with_hesitation_is_coaching_pattern() -> None:
    assessment = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="behavioral-policy-2")
    ).assess(
        BehavioralSessionSignals(
            hesitation_seconds=19.0,
            active_call_indicator=True,
            remote_access_indicator=True,
            provenance=provenance(),
        )
    )

    assert assessment.intelligence.device_session_risk == 0.92
    assert "POSSIBLE_LIVE_COACHING_PATTERN" in assessment.reason_codes


def test_coaching_combination_thresholds_are_tenant_configurable() -> None:
    observed = BehavioralSessionSignals(
        active_call_indicator=True,
        remote_access_indicator=True,
        provenance=provenance(),
    )

    strict = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="tenant-a-behavioral-4")
    ).assess(observed)
    sensitive = BehavioralSessionDetector(
        BehavioralSessionPolicy(
            policy_version="tenant-b-behavioral-2",
            coached_payment_min_signals=2,
        )
    ).assess(observed)

    assert "POSSIBLE_LIVE_COACHING_PATTERN" not in strict.reason_codes
    assert "POSSIBLE_LIVE_COACHING_PATTERN" in sensitive.reason_codes
    assert sensitive.signal_policy_version == "tenant-b-behavioral-2"


def test_coaching_pattern_can_be_configured_without_active_call() -> None:
    observed = BehavioralSessionSignals(
        remote_access_indicator=True,
        behavioral_anomaly_score=0.9,
        hesitation_seconds=30.0,
        provenance=provenance(),
    )

    default = BehavioralSessionDetector(
        BehavioralSessionPolicy(policy_version="tenant-a-behavioral-4")
    ).assess(observed)
    relaxed = BehavioralSessionDetector(
        BehavioralSessionPolicy(
            policy_version="tenant-b-behavioral-3",
            coached_payment_requires_active_call=False,
        )
    ).assess(observed)

    assert "POSSIBLE_LIVE_COACHING_PATTERN" not in default.reason_codes
    assert "POSSIBLE_LIVE_COACHING_PATTERN" in relaxed.reason_codes


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

    assert sensitive.intelligence.device_session_risk == 0.68
    assert tolerant.intelligence.device_session_risk == 0.0
