from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.replay import SyntheticReplayCase, replay


def transaction(suffix: str) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="synthetic-tenant",
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(2500),
        currency="ETB",
        sender_customer_id=f"synthetic-customer-{suffix}",
        sender_account_id=f"synthetic-account-{suffix}",
        beneficiary_id=f"synthetic-beneficiary-{suffix}",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="synthetic-external-institution",
        correlation_id=f"synthetic-correlation-{suffix}",
    )


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="synthetic-config-1",
        policy_version="synthetic-policy-1",
        rule_version="synthetic-rules-1",
    )


def test_replay_measures_detection_false_positives_and_explainability() -> None:
    cases = (
        SyntheticReplayCase(
            "emergency-new-beneficiary",
            transaction("1"),
            IntelligenceSnapshot(relationship_risk=0.91),
            True,
            ("NEW_BENEFICIARY_UNUSUAL_TRANSFER",),
        ),
        SyntheticReplayCase(
            "support-agent-induced-transfer",
            transaction("2"),
            IntelligenceSnapshot(transaction_risk=0.82, beneficiary_risk=0.76),
            True,
            ("UNUSUAL_TRANSFER_PATTERN",),
        ),
        SyntheticReplayCase(
            "mule-beneficiary-aggregation",
            transaction("3"),
            IntelligenceSnapshot(beneficiary_risk=0.97, network_risk=0.96),
            True,
            ("BENEFICIARY_AGGREGATION_PATTERN",),
        ),
        SyntheticReplayCase(
            "normal-established-beneficiary",
            transaction("4"),
            IntelligenceSnapshot(relationship_risk=0.10, beneficiary_risk=0.08),
            False,
        ),
        SyntheticReplayCase(
            "legitimate-unusual-payment",
            transaction("5"),
            IntelligenceSnapshot(transaction_risk=0.73),
            False,
            ("UNUSUAL_TRANSFER_PATTERN",),
        ),
    )

    metrics = replay(policy(), cases)

    assert metrics.cases == 5
    assert metrics.true_positives == 3
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.false_negatives == 0
    assert metrics.recall == 1.0
    assert metrics.precision == 0.75
    assert metrics.false_positive_rate == 0.5
    assert metrics.explainability_coverage == 1.0


def test_replay_does_not_treat_monitor_as_detection() -> None:
    case = SyntheticReplayCase(
        "weak-synthetic-signal",
        transaction("6"),
        IntelligenceSnapshot(relationship_risk=0.60),
        True,
    )

    metrics = replay(policy(), (case,))

    assert metrics.true_positives == 0
    assert metrics.false_negatives == 1
    assert metrics.recall == 0.0
