from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.ablation import (
    AblationConfiguration,
    IncrementalDetectionReason,
    ablate_intelligence,
    default_ablation_plan,
    run_ablation,
)
from gasha.poc.attribution import SignalFamily
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
)

T0 = datetime(2026, 1, 25, 9, 0, 0, tzinfo=UTC)


def transaction(suffix: str) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
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


def event(
    suffix: str,
    intelligence: IntelligenceSnapshot,
    is_fraud: bool,
) -> HistoricalTransactionEvent:
    return HistoricalTransactionEvent(
        transaction=transaction(suffix),
        intelligence=intelligence,
        label=ConfirmedOutcomeLabel(
            is_fraud=is_fraud, label_source="synthetic"
        ),
    )


def test_ablate_intelligence_zeros_only_removed_families() -> None:
    snapshot = IntelligenceSnapshot(
        beneficiary_risk=0.9, network_risk=0.8, velocity_risk=0.5
    )
    ablated = ablate_intelligence(
        snapshot, frozenset({SignalFamily.BENEFICIARY})
    )

    assert ablated.beneficiary_risk == 0.0
    assert ablated.network_risk == 0.8
    assert ablated.velocity_risk == 0.5
    assert snapshot.beneficiary_risk == 0.9


def test_default_plan_is_bounded_single_family_plus_strategic_pairs() -> None:
    plan = default_ablation_plan()
    names = [config.name for config in plan]

    assert names[0] == "full"
    singles = [c for c in plan if len(c.removed_families) == 1]
    assert len(singles) == 8
    combos = [c for c in plan if len(c.removed_families) > 1]
    assert len(combos) == 3
    assert len(plan) == 12


def test_ablation_measures_incremental_recall_contribution() -> None:
    events = (
        event(
            "fraud-1",
            IntelligenceSnapshot(beneficiary_risk=0.91),
            True,
        ),
        event(
            "fraud-2",
            IntelligenceSnapshot(network_risk=0.96),
            True,
        ),
        event("legit-1", IntelligenceSnapshot(), False),
    )

    report = run_ablation(events, {"tenant-a": policy()})

    assert report.full.metrics.true_positives == 2
    assert report.full.metrics.recall == 1.0

    by_name = {c.configuration_name: c for c in report.comparisons}
    without_beneficiary = by_name["without_beneficiary"]
    assert without_beneficiary.true_positives == 1
    assert without_beneficiary.recall == 0.5
    assert without_beneficiary.recall_delta == -0.5
    assert without_beneficiary.incremental_recall_contribution == 0.5
    assert without_beneficiary.detections_lost == 1

    without_velocity = by_name["without_velocity"]
    assert without_velocity.incremental_recall_contribution == 0.0
    assert without_velocity.detections_lost == 0


def test_unique_detection_marks_family_necessary_for_detection() -> None:
    events = (
        event(
            "mule-fraud",
            IntelligenceSnapshot(
                network_risk=0.96, transaction_risk=0.40
            ),
            True,
        ),
        event(
            "coached-fraud",
            IntelligenceSnapshot(
                device_session_risk=0.92, beneficiary_risk=0.60
            ),
            True,
        ),
    )

    report = run_ablation(events, {"tenant-a": policy()})

    reasons = {detection.reason for detection in report.unique_detections}
    assert IncrementalDetectionReason.NETWORK_INCREMENTAL_DETECTION in reasons
    assert IncrementalDetectionReason.DEVICE_SESSION_INCREMENTAL_DETECTION in reasons
    # coached-fraud still alerts on device_session alone, so beneficiary is
    # not necessary; mule-fraud never relied on beneficiary either.
    assert IncrementalDetectionReason.BENEFICIARY_INCREMENTAL_DETECTION not in reasons


def test_unique_detection_only_applies_to_confirmed_fraud() -> None:
    events = (
        event(
            "legit-alert",
            IntelligenceSnapshot(beneficiary_risk=0.91),
            False,
        ),
    )

    report = run_ablation(events, {"tenant-a": policy()})

    assert report.unique_detections == ()
    without_beneficiary = next(
        c
        for c in report.comparisons
        if c.configuration_name == "without_beneficiary"
    )
    assert without_beneficiary.false_positive_delta == -1
    assert without_beneficiary.detections_lost == 1


def test_combination_ablation_counts_jointly_removed_families() -> None:
    events = (
        event(
            "fraud-1",
            IntelligenceSnapshot(
                beneficiary_risk=0.72, relationship_risk=0.75
            ),
            True,
        ),
        event("legit-1", IntelligenceSnapshot(), False),
    )
    plan = (
        AblationConfiguration(name="full"),
        AblationConfiguration(
            name="without_beneficiary_and_relationship",
            removed_families=frozenset(
                {SignalFamily.BENEFICIARY, SignalFamily.RELATIONSHIP}
            ),
        ),
    )

    report = run_ablation(events, {"tenant-a": policy()}, configurations=plan)

    combo = report.comparisons[0]
    assert combo.removed_families == (
        SignalFamily.BENEFICIARY,
        SignalFamily.RELATIONSHIP,
    )
    assert combo.true_positives == 0
    assert combo.incremental_recall_contribution == 1.0
    # multi-family ablations do not produce single-family unique detections
    assert report.unique_detections == ()


def test_ablation_enforces_tenant_policy_isolation() -> None:
    from gasha.poc.historical import MissingTenantPolicyError

    events = (event("fraud-1", IntelligenceSnapshot(), True),)
    with pytest.raises(MissingTenantPolicyError):
        run_ablation(events, {})


def test_ablation_preserves_full_run_decision_actions() -> None:
    events = (
        event(
            "fraud-1", IntelligenceSnapshot(network_risk=0.97), True
        ),
    )
    report = run_ablation(events, {"tenant-a": policy()})

    assert report.full.results[0].decision.action == DecisionAction.BLOCK
    # original events untouched by ablation copies
    assert events[0].intelligence.network_risk == 0.97
