from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    ReplayClassification,
    reconcile_outcomes,
    replay_historical,
)
from gasha.poc.incumbent import compare_incumbent
from gasha.poc.outcomes import (
    IncumbentControlOutcome,
    OutcomeRecord,
    OutcomeType,
)

T0 = datetime(2026, 2, 5, 9, 0, 0, tzinfo=UTC)


def transaction(
    suffix: str, tenant_id: str = "tenant-a"
) -> CanonicalTransaction:
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


def event(
    suffix: str,
    intelligence: IntelligenceSnapshot | None = None,
    *,
    tenant_id: str = "tenant-a",
    label: ConfirmedOutcomeLabel | None = None,
    incumbent: IncumbentControlOutcome | None = None,
    received_at: datetime | None = None,
) -> HistoricalTransactionEvent:
    return HistoricalTransactionEvent(
        transaction=transaction(suffix, tenant_id),
        intelligence=intelligence or IntelligenceSnapshot(),
        label=label,
        incumbent_outcome=incumbent,
        received_at=received_at,
    )


def outcome(
    tx: CanonicalTransaction,
    outcome_type: OutcomeType,
    *,
    tenant_id: str | None = None,
    confirmed_at: datetime | None = None,
) -> OutcomeRecord:
    return OutcomeRecord(
        tenant_id=tenant_id or tx.tenant_id,
        event_id=tx.event_id,
        outcome=outcome_type,
        outcome_source="synthetic-case-review",
        outcome_version="outcomes-1",
        confirmed_at=confirmed_at,
    )


def test_reconcile_attaches_late_outcome_without_mutating_decision() -> None:
    ev = event("fraud-1", IntelligenceSnapshot(network_risk=0.96))
    report = replay_historical((ev,), {"tenant-a": policy()})
    original = report.results[0]

    reconciled = reconcile_outcomes(
        report,
        (
            outcome(
                ev.transaction,
                OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD,
                confirmed_at=T0 + timedelta(days=2),
            ),
        ),
    )

    result = reconciled.results[0]
    assert result.classification == ReplayClassification.TRUE_POSITIVE
    assert result.reconciled_outcome is not None
    assert result.reconciled_outcome.outcome == (
        OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD
    )
    assert result.decision == original.decision
    assert result.detection_lead_time == (
        T0 + timedelta(days=2) - result.decision.decided_at
    )


def test_reconcile_reclassifies_bank_confirmed_false_positive() -> None:
    ev = event("legit-1", IntelligenceSnapshot(transaction_risk=0.80))
    report = replay_historical((ev,), {"tenant-a": policy()})

    reconciled = reconcile_outcomes(
        report,
        (outcome(ev.transaction, OutcomeType.BANK_CONFIRMED_FALSE_POSITIVE),),
    )

    assert reconciled.results[0].classification == (
        ReplayClassification.FALSE_POSITIVE
    )
    assert reconciled.metrics.false_positives == 1


def test_reconcile_unresolved_becomes_unlabeled_not_legitimate() -> None:
    ev = event("open-1", IntelligenceSnapshot(transaction_risk=0.80))
    report = replay_historical((ev,), {"tenant-a": policy()})

    reconciled = reconcile_outcomes(
        report, (outcome(ev.transaction, OutcomeType.UNRESOLVED),)
    )

    assert reconciled.results[0].classification == (
        ReplayClassification.UNLABELED
    )
    assert reconciled.metrics.labeled_cases == 0


def test_outcome_cannot_attach_across_tenants() -> None:
    ev = event("fraud-1", tenant_id="tenant-a")
    report = replay_historical(
        (ev,), {"tenant-a": policy()}
    )

    foreign = outcome(
        ev.transaction, OutcomeType.CONFIRMED_FRAUD, tenant_id="tenant-b"
    )
    reconciled = reconcile_outcomes(report, (foreign,))

    assert reconciled.results[0].reconciled_outcome is None
    assert reconciled.results[0].classification == (
        ReplayClassification.UNLABELED
    )
    assert reconciled.unmatched_outcomes == (foreign,)


def test_latency_is_measured_with_injected_clock() -> None:
    ticks = [T0]

    def clock() -> datetime:
        current = ticks[-1]
        ticks.append(current + timedelta(milliseconds=6))
        return current

    report = replay_historical(
        (
            event("e1", received_at=T0),
            event("e2", received_at=T0),
        ),
        {"tenant-a": policy()},
        clock=clock,
    )

    first, second = report.results
    assert first.processing_latency == timedelta(milliseconds=6)
    assert first.evaluation_started_at == T0
    assert first.decision_latency == (
        first.decision.decided_at - T0
    )
    assert second.evaluation_started_at == T0 + timedelta(milliseconds=12)

    metrics = report.metrics
    assert metrics.mean_processing_latency_ms == 6.0
    assert metrics.median_processing_latency_ms == 6.0
    assert metrics.p95_processing_latency_ms is not None
    assert metrics.p99_processing_latency_ms is not None
    assert metrics.max_processing_latency_ms == 6.0


def test_incumbent_comparison_counts_detection_categories() -> None:
    fraud_gasha_only = event(
        "f1",
        IntelligenceSnapshot(network_risk=0.96),
        label=ConfirmedOutcomeLabel(is_fraud=True, label_source="synthetic"),
        incumbent=IncumbentControlOutcome.NO_ALERT,
    )
    fraud_both = event(
        "f2",
        IntelligenceSnapshot(beneficiary_risk=0.90),
        label=ConfirmedOutcomeLabel(is_fraud=True, label_source="synthetic"),
        incumbent=IncumbentControlOutcome.HOLD,
    )
    fraud_incumbent_only = event(
        "f3",
        IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(is_fraud=True, label_source="synthetic"),
        incumbent=IncumbentControlOutcome.ALERT,
    )
    legit_neither = event(
        "l1",
        IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(is_fraud=False, label_source="synthetic"),
        incumbent=IncumbentControlOutcome.NO_ALERT,
    )
    legit_missing_incumbent = event(
        "l2",
        IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(is_fraud=False, label_source="synthetic"),
    )
    report = replay_historical(
        (
            fraud_gasha_only,
            fraud_both,
            fraud_incumbent_only,
            legit_neither,
            legit_missing_incumbent,
        ),
        {"tenant-a": policy()},
    )

    comparison = compare_incumbent(report.results)

    assert comparison.evaluated_cases == 4
    assert comparison.missing_incumbent_outcomes == 1
    assert comparison.both_detected == 1
    assert comparison.gasha_only_detected == 1
    assert comparison.incumbent_only_detected == 1
    assert comparison.neither_detected == 1
    assert comparison.incremental_confirmed_detection == 1
    assert comparison.gasha.true_positives == 2
    assert comparison.incumbent.true_positives == 2
    assert comparison.gasha.recall == 2 / 3
    assert comparison.incumbent.recall == 2 / 3
