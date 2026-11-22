from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.attribution import (
    SignalFamily,
    attribute_signals,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    replay_historical,
)

T0 = datetime(2026, 1, 20, 9, 0, 0, tzinfo=UTC)


def transaction(suffix: str, tenant_id: str = "tenant-a") -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid4(),
        occurred_at=T0,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("2500.00"),
        currency="ETB",
        sender_customer_id=f"customer-{suffix}",
        sender_account_id=f"account-{suffix}",
        beneficiary_id=f"beneficiary-{suffix}",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id=f"corr-{suffix}",
    )


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version="policy-1",
        rule_version="rules-1",
    )


def replayed(
    suffix: str,
    intelligence: IntelligenceSnapshot,
    is_fraud: bool,
    *,
    tenant_id: str = "tenant-a",
    reason_codes: tuple[str, ...] = (),
):
    return HistoricalTransactionEvent(
        transaction=transaction(suffix, tenant_id),
        intelligence=intelligence,
        evidence_reason_codes=reason_codes,
        label=ConfirmedOutcomeLabel(
            is_fraud=is_fraud, label_source="synthetic"
        ),
    )


def run(*events: HistoricalTransactionEvent):
    return replay_historical(
        events, {"tenant-a": policy(), "tenant-b": policy()}
    )


def test_single_driving_family_is_attributed() -> None:
    report = run(
        replayed(
            "fraud-1",
            IntelligenceSnapshot(beneficiary_risk=0.91),
            True,
            reason_codes=("BENEFICIARY_MANY_UNIQUE_SENDERS",),
        )
    )
    attribution = attribute_signals(
        report.results, {"tenant-a": policy(), "tenant-b": policy()}
    )

    beneficiary = attribution.families[SignalFamily.BENEFICIARY]
    assert beneficiary.alerts_influenced == 1
    assert beneficiary.driving_alerts == 1
    assert beneficiary.true_positives_influenced == 1
    assert beneficiary.share_of_detected_fraud == 1.0
    assert beneficiary.max_risk_contribution == 0.91
    assert "HIGH_BENEFICIARY_RISK" in beneficiary.reason_codes
    assert "BENEFICIARY_MANY_UNIQUE_SENDERS" in beneficiary.reason_codes

    velocity = attribution.families[SignalFamily.VELOCITY]
    assert velocity.alerts_influenced == 0
    assert velocity.mean_risk_contribution is None


def test_sub_threshold_signal_does_not_count_as_contribution() -> None:
    report = run(
        replayed(
            "fraud-1",
            IntelligenceSnapshot(
                beneficiary_risk=0.91,
                relationship_risk=0.60,
                velocity_risk=0.30,
            ),
            True,
        )
    )
    attribution = attribute_signals(report.results, {"tenant-a": policy()})

    assert attribution.families[SignalFamily.BENEFICIARY].alerts_influenced == 1
    assert attribution.families[SignalFamily.RELATIONSHIP].alerts_influenced == 0
    assert attribution.families[SignalFamily.VELOCITY].alerts_influenced == 0


def test_multi_signal_alert_records_family_combination() -> None:
    report = run(
        replayed(
            "fraud-1",
            IntelligenceSnapshot(
                relationship_risk=0.80, device_session_risk=0.78
            ),
            True,
        ),
        replayed(
            "fraud-2",
            IntelligenceSnapshot(network_risk=0.96, beneficiary_risk=0.88),
            True,
            reason_codes=("INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER",),
        ),
        replayed(
            "legit-1",
            IntelligenceSnapshot(beneficiary_risk=0.72),
            False,
        ),
    )
    attribution = attribute_signals(report.results, {"tenant-a": policy()})

    detections = attribution.multi_signal.detections
    assert len(detections) == 2
    relationship_combo = detections[0]
    assert relationship_combo.families == (
        SignalFamily.RELATIONSHIP,
        SignalFamily.DEVICE_SESSION,
    )
    assert (
        attribution.multi_signal.named_combination_detections[
            "new_beneficiary_active_call"
        ]
        == 1
    )
    assert (
        attribution.multi_signal.named_combination_detections[
            "fan_in_repeat_victims"
        ]
        == 1
    )
    assert attribution.families[
        SignalFamily.BENEFICIARY
    ].false_positives_influenced == 1


def test_non_alerts_never_attribute() -> None:
    report = run(
        replayed(
            "legit-1",
            IntelligenceSnapshot(relationship_risk=0.60),
            False,
        ),
        replayed("legit-2", IntelligenceSnapshot(), False),
    )
    attribution = attribute_signals(report.results, {"tenant-a": policy()})

    assert all(
        family.alerts_influenced == 0
        for family in attribution.families.values()
    )
    assert attribution.multi_signal.detections == ()


def test_share_of_detected_fraud_measures_family_reach() -> None:
    report = run(
        replayed(
            "fraud-1", IntelligenceSnapshot(beneficiary_risk=0.91), True
        ),
        replayed(
            "fraud-2", IntelligenceSnapshot(network_risk=0.96), True
        ),
        replayed(
            "fraud-3", IntelligenceSnapshot(relationship_risk=0.40), True
        ),
    )
    attribution = attribute_signals(report.results, {"tenant-a": policy()})

    assert attribution.families[
        SignalFamily.BENEFICIARY
    ].share_of_detected_fraud == 0.5
    assert attribution.families[
        SignalFamily.NETWORK
    ].share_of_detected_fraud == 0.5
    assert attribution.families[
        SignalFamily.RELATIONSHIP
    ].share_of_detected_fraud == 0.0


def test_attribution_uses_each_events_own_tenant_threshold() -> None:
    strict_b = DecisionPolicy(
        configuration_version="tenant-b-config",
        policy_version="policy-tenant-b",
        rule_version="rules-tenant-b",
        monitor_threshold=0.90,
        review_threshold=0.95,
        hold_threshold=0.97,
        block_threshold=0.99,
    )
    policies = {"tenant-a": policy(), "tenant-b": strict_b}
    report = replay_historical(
        (
            replayed(
                "a-1", IntelligenceSnapshot(beneficiary_risk=0.91), True
            ),
            replayed(
                "b-1",
                IntelligenceSnapshot(beneficiary_risk=0.91),
                True,
                tenant_id="tenant-b",
            ),
        ),
        policies,
    )
    attribution = attribute_signals(
        report.results,
        {"tenant-a": policy(), "tenant-b": strict_b},
    )

    events = {event.tenant_id: event for event in attribution.events}
    assert SignalFamily.BENEFICIARY in events["tenant-a"].influenced
    assert events["tenant-b"].influenced == frozenset()
    assert events["tenant-b"].alerted is False


def test_same_uuid_across_tenants_preserves_family_labels_and_reason_codes() -> None:
    first = replayed(
        "fraud-a",
        IntelligenceSnapshot(network_risk=0.94, beneficiary_risk=0.91),
        True,
        reason_codes=("SYNTHETIC_A_ONLY",),
    )
    second = replayed(
        "legitimate-b",
        IntelligenceSnapshot(relationship_risk=0.95, device_session_risk=0.92),
        False,
        tenant_id="tenant-b",
        reason_codes=("SYNTHETIC_B_ONLY",),
    )
    second = second.model_copy(update={
        "transaction": second.transaction.model_copy(
            update={"event_id": first.transaction.event_id}
        ),
    })
    report = replay_historical((first, second), {
        "tenant-a": policy(), "tenant-b": policy(),
    })
    attributed = attribute_signals(report.results, {
        "tenant-a": policy(), "tenant-b": policy(),
    })
    assert attributed.families[SignalFamily.NETWORK].true_positives_influenced == 1
    assert attributed.families[SignalFamily.NETWORK].false_positives_influenced == 0
    assert attributed.families[SignalFamily.RELATIONSHIP].false_positives_influenced == 1
    assert attributed.families[SignalFamily.RELATIONSHIP].true_positives_influenced == 0
    by_tenant = {
        detection.tenant_id: detection
        for detection in attributed.multi_signal.detections
    }
    assert set(by_tenant) == {"tenant-a", "tenant-b"}
    assert "SYNTHETIC_A_ONLY" in by_tenant["tenant-a"].reason_codes
    assert "SYNTHETIC_B_ONLY" not in by_tenant["tenant-a"].reason_codes
    assert "SYNTHETIC_B_ONLY" in by_tenant["tenant-b"].reason_codes
    assert "SYNTHETIC_A_ONLY" not in by_tenant["tenant-b"].reason_codes


def test_duplicate_composite_attribution_identity_is_rejected() -> None:
    report = run(replayed(
        "fraud-a", IntelligenceSnapshot(network_risk=0.94), True,
    ))
    with pytest.raises(ValueError, match="duplicate tenant/event attribution"):
        attribute_signals(report.results + report.results, {"tenant-a": policy()})


def test_mismatched_decision_and_source_event_identity_is_rejected() -> None:
    report = run(
        replayed("a", IntelligenceSnapshot(network_risk=0.94), True),
        replayed("b", IntelligenceSnapshot(beneficiary_risk=0.94), False),
    )
    corrupted = report.results[0].model_copy(update={
        "event": report.results[1].event,
    })
    with pytest.raises(ValueError, match="identity mismatch"):
        attribute_signals((corrupted,), {"tenant-a": policy()})
