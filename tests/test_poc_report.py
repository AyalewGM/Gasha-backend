from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.ablation import run_ablation
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    MissingTenantPolicyError,
    ReplayClassification,
    reconcile_outcomes,
    replay_historical,
)
from gasha.poc.historical import _metrics as _derive_replay_metrics
from gasha.poc.incumbent import compare_incumbent
from gasha.poc.outcomes import (
    IncumbentControlOutcome,
    OutcomeRecord,
    OutcomeType,
)
from gasha.poc.report import build_poc_report

T0 = datetime(2026, 2, 10, 9, 0, 0, tzinfo=UTC)


def transaction(
    suffix: str, tenant_id: str = "tenant-a", at: datetime = T0
) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid4(),
        occurred_at=at,
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
        model_version="model-1",
    )


def event(
    suffix: str,
    intelligence: IntelligenceSnapshot,
    is_fraud: bool | None,
    *,
    tenant_id: str = "tenant-a",
    incumbent: IncumbentControlOutcome | None = None,
) -> HistoricalTransactionEvent:
    return HistoricalTransactionEvent(
        transaction=transaction(suffix, tenant_id),
        intelligence=intelligence,
        signal_policy_versions=("social-engineering-4",),
        label=(
            ConfirmedOutcomeLabel(is_fraud=is_fraud, label_source="synthetic")
            if is_fraud is not None
            else None
        ),
        incumbent_outcome=incumbent,
    )


def dataset() -> tuple[HistoricalTransactionEvent, ...]:
    return (
        event(
            "fraud-mule",
            IntelligenceSnapshot(network_risk=0.96, beneficiary_risk=0.88),
            True,
            incumbent=IncumbentControlOutcome.NO_ALERT,
        ),
        event(
            "fraud-coached",
            IntelligenceSnapshot(
                device_session_risk=0.92, relationship_risk=0.80
            ),
            True,
            incumbent=IncumbentControlOutcome.ALERT,
        ),
        event(
            "fraud-missed",
            IntelligenceSnapshot(relationship_risk=0.40),
            True,
            incumbent=IncumbentControlOutcome.ALERT,
        ),
        event(
            "legit-normal",
            IntelligenceSnapshot(beneficiary_risk=0.10),
            False,
            incumbent=IncumbentControlOutcome.NO_ALERT,
        ),
        event(
            "legit-fp",
            IntelligenceSnapshot(transaction_risk=0.75),
            False,
        ),
        event("unlabeled", IntelligenceSnapshot(), None),
    )


def test_poc_report_assembles_machine_readable_evidence() -> None:
    policies = {"tenant-a": policy()}
    events = dataset()
    report = replay_historical(events, policies)
    ablation = run_ablation(events, policies)

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-campaign-1",
        report=report,
        policies=policies,
        ablation=ablation,
    )

    assert poc.tenant_id == "tenant-a"
    assert poc.dataset_id == "synthetic-campaign-1"
    assert poc.total_events == 6
    assert poc.labeled_events == 5
    assert poc.unresolved_outcomes == 1
    assert poc.fraud_prevalence == pytest.approx(0.6)
    assert poc.confusion.true_positives == 2
    assert poc.confusion.false_negatives == 1
    assert poc.confusion.false_positives == 1
    assert poc.confusion.recall == pytest.approx(2 / 3)
    assert poc.evaluation_period_start == T0
    assert poc.policy_versions == ["policy-1"]
    assert poc.model_versions == ["model-1"]
    assert poc.signal_policy_versions == ["social-engineering-4"]
    assert len(poc.signal_attribution) == 8
    assert len(poc.ablation) == 11
    assert poc.incumbent_comparison is not None
    assert poc.incumbent_comparison.incremental_confirmed_detection == 1
    assert poc.incumbent_comparison.both_detected == 1
    assert poc.incumbent_comparison.incumbent_only_detected == 1
    assert poc.limitations
    assert poc.latency.mean_decision_latency_seconds is None
    assert poc.latency.mean_detection_lead_time_seconds is None
    assert poc.latency.mean_processing_latency_ms is not None
    assert any("historical decision latency" in item for item in poc.limitations)

    serialized = poc.model_dump(mode="json")
    assert serialized["confusion"]["true_positives"] == 2
    assert serialized["multi_signal"]["named_combination_detections"]


def test_report_limitations_are_explicit_and_derived() -> None:
    policies = {"tenant-a": policy()}
    report = replay_historical(dataset(), policies)

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="ds-1",
        report=report,
        policies=policies,
        limitations=["device telemetry incomplete in source feed"],
    )

    text = "\n".join(poc.limitations)
    assert "synthetic" in text
    assert "unlabeled" in text
    assert "incumbent" in text.lower()
    assert "cross-bank" in text
    assert "device telemetry incomplete" in text


def test_missing_incumbent_outcomes_produce_limitation_not_silence() -> None:
    policies = {"tenant-a": policy()}
    events = (
        event("fraud-1", IntelligenceSnapshot(network_risk=0.96), True),
    )
    report = replay_historical(events, policies)

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="ds-1",
        report=report,
        policies=policies,
    )

    assert poc.incumbent_comparison is None
    assert any(
        "incumbent" in limitation.lower()
        for limitation in poc.limitations
    )


def test_report_rejects_mixed_tenant_results() -> None:
    policies = {"tenant-a": policy(), "tenant-b": policy()}
    report = replay_historical(
        (
            event("a1", IntelligenceSnapshot(), False),
            event("b1", IntelligenceSnapshot(), False, tenant_id="tenant-b"),
        ),
        policies,
    )

    with pytest.raises(MissingTenantPolicyError):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="ds-1",
            report=report,
            policies=policies,
        )


def test_report_reflects_reconciled_outcomes() -> None:
    policies = {"tenant-a": policy()}
    ev = event("fraud-1", IntelligenceSnapshot(), None)
    report = replay_historical((ev,), policies)
    reconciled = reconcile_outcomes(
        report,
        (
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=ev.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="case-review",
                outcome_version="outcomes-1",
                confirmed_at=T0 + timedelta(days=3),
            ),
        ),
    )

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="ds-1",
        report=reconciled,
        policies=policies,
    )

    assert poc.confusion.false_negatives == 1
    assert poc.fraud_prevalence == 1.0


@pytest.mark.parametrize(
    ("influenced", "driving", "true_positive", "false_positive"),
    [
        (0, 1, 0, 0),
        (1, 2, 0, 0),
        (2, 3, 1, 0),
        (3, 4, 2, 1),
        (4, 5, 1, 2),
        (0, 0, 0, 1),
        (1, 0, 1, 1),
        (2, 1, 2, 1),
        (3, 2, 1, 3),
        (4, 4, 3, 2),
    ],
)
def test_signal_family_rejects_impossible_subset_counts(
    influenced: int, driving: int, true_positive: int, false_positive: int
) -> None:
    from pydantic import ValidationError

    from gasha.poc.report import RateEvidence, SignalFamilySummary

    assert (
        driving > influenced
        or true_positive + false_positive > influenced
    )
    with pytest.raises(ValidationError):
        SignalFamilySummary(
            family="network",
            alerts_influenced=influenced,
            driving_alerts=driving,
            true_positives_influenced=true_positive,
            false_positives_influenced=false_positive,
            share_of_detected_fraud=(
                true_positive / 10
            ),
            share_of_detected_fraud_evidence=RateEvidence(
                numerator=true_positive,
                denominator=10,
                value=true_positive / 10,
            ),
            mean_risk_contribution=None,
            max_risk_contribution=None,
            reason_codes=[],
        )


def test_signal_family_accepts_valid_subset_counts() -> None:
    from gasha.poc.report import RateEvidence, SignalFamilySummary

    summary = SignalFamilySummary(
        family="network",
        alerts_influenced=5,
        driving_alerts=3,
        true_positives_influenced=2,
        false_positives_influenced=2,
        share_of_detected_fraud=0.5,
        share_of_detected_fraud_evidence=RateEvidence(
            numerator=2, denominator=4, value=0.5
        ),
        mean_risk_contribution=None,
        max_risk_contribution=None,
        reason_codes=[],
    )
    assert summary.driving_alerts == 3


def test_incumbent_cohort_uses_late_reconciled_fraud_label() -> None:
    policies = {"tenant-a": policy()}
    pending = event(
        "late-fraud",
        IntelligenceSnapshot(network_risk=0.97),
        None,
        incumbent=IncumbentControlOutcome.NO_ALERT,
    )
    original = replay_historical((pending,), policies)
    assert original.metrics.unlabeled_cases == 1
    assert compare_incumbent(original.results).evaluated_cases == 0

    confirmed = reconcile_outcomes(
        original,
        (
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=pending.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-investigation",
                outcome_version="outcomes-1",
                confirmed_at=T0 + timedelta(days=3),
            ),
        ),
    )
    comparison = compare_incumbent(confirmed.results)
    assert confirmed.metrics.true_positives == 1
    assert confirmed.metrics.unlabeled_cases == 0
    assert comparison.evaluated_cases == 1
    assert comparison.missing_incumbent_outcomes == 0
    assert comparison.gasha.true_positives == 1
    assert comparison.incumbent.false_negatives == 1
    assert comparison.incremental_confirmed_detection == 1

    serialized = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-late-outcome",
        report=confirmed,
        policies=policies,
    ).model_dump(mode="json")
    assert serialized["confusion"]["true_positives"] == 1
    assert serialized["incumbent_comparison"]["evaluated_cases"] == 1
    assert serialized["incumbent_comparison"]["incremental_confirmed_detection"] == 1


def test_incumbent_cohort_respects_latest_label_and_tenant_boundary() -> None:
    policies = {"tenant-a": policy()}
    corrected = event(
        "corrected",
        IntelligenceSnapshot(network_risk=0.96),
        None,
        incumbent=IncumbentControlOutcome.ALERT,
    )
    unresolved = event(
        "unresolved",
        IntelligenceSnapshot(),
        None,
        incumbent=IncumbentControlOutcome.NO_ALERT,
    )
    no_incumbent = event(
        "no-incumbent",
        IntelligenceSnapshot(),
        False,
    )
    original = replay_historical((corrected, unresolved, no_incumbent), policies)
    reconciled = reconcile_outcomes(
        original,
        (
            OutcomeRecord(
                tenant_id="tenant-b",
                event_id=unresolved.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-investigation",
                outcome_version="outcomes-1",
                confirmed_at=T0 + timedelta(days=4),
            ),
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=corrected.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-investigation",
                outcome_version="outcomes-1",
                confirmed_at=T0 + timedelta(days=1),
            ),
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=corrected.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_LEGITIMATE,
                outcome_source="synthetic-investigation",
                outcome_version="outcomes-2",
                confirmed_at=T0 + timedelta(days=2),
            ),
        ),
    )
    comparison = compare_incumbent(reconciled.results)
    assert reconciled.metrics.false_positives == 1
    assert reconciled.metrics.true_positives == 0
    assert reconciled.metrics.unlabeled_cases == 1
    assert len(reconciled.unmatched_outcomes) == 1
    assert comparison.evaluated_cases == 1
    assert comparison.missing_incumbent_outcomes == 1
    assert comparison.gasha.false_positives == 1
    assert comparison.incumbent.false_positives == 1
    assert comparison.incremental_confirmed_detection == 0


def test_combined_historical_reconciliation_and_report_v2() -> None:
    """Issue #48: timing, reconciled cohort and nullable report rates together."""
    policies = {"tenant-a": policy()}
    pending = event(
        "combined-fraud",
        IntelligenceSnapshot(network_risk=0.97),
        None,
        incumbent=IncumbentControlOutcome.NO_ALERT,
    )
    original = replay_historical((pending,), policies)
    reconciled = reconcile_outcomes(
        original,
        (
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=pending.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-investigation",
                outcome_version="outcomes-1",
                confirmed_at=T0 + timedelta(days=3),
            ),
        ),
    )
    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-combined-issue-48",
        report=reconciled,
        policies=policies,
    )
    payload = poc.model_dump(mode="json")
    assert payload["report_version"] == "poc-report-2"
    assert payload["latency"]["mean_decision_latency_seconds"] is None
    assert payload["latency"]["mean_detection_lead_time_seconds"] is None
    assert payload["confusion"]["true_positives"] == 1
    assert payload["confusion"]["rate_evidence"]["false_positive_rate"]["value"] is None
    assert (
        payload["confusion"]["rate_evidence"]["false_positive_rate"]["undefined_reason"]
        == "no_confirmed_legitimate"
    )
    assert payload["incumbent_comparison"]["evaluated_cases"] == 1
    assert payload["incumbent_comparison"]["incremental_confirmed_detection"] == 1
    assert any("historical decision latency" in note for note in payload["limitations"])


def test_replay_metrics_cannot_fabricate_empty_cohort() -> None:
    """Primary population must be derived from rows, not a plausible aggregate."""
    from dataclasses import replace

    empty = replay_historical((), {})
    fabricated = replace(
        empty,
        metrics=replace(
            empty.metrics,
            cases=1,
            labeled_cases=1,
            false_negatives=1,
        ),
    )
    # This forged metric object is internally coherent: 1 case = 1 labeled FN.
    # It must never turn zero replayed decisions into measured detection evidence.
    with pytest.raises(
        ValueError, match="historical metrics do not match replay results"
    ):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-empty",
            report=fabricated,
            policies={},
        )

    verified = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-empty",
        report=empty,
        policies={},
    )
    assert verified.total_events == 0
    assert verified.labeled_events == 0
    assert verified.confusion.false_negatives == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"true_positives": 1, "false_negatives": 2},  # Same case totals, false recall.
        {"explained_alerts": 0},  # Forged reason-code coverage.
        {"mean_decision_latency_seconds": 10.0},  # No observed historical clock.
        {"max_decision_latency_seconds": 10.0},
        {"mean_detection_lead_time_seconds": 10.0},
        {"mean_processing_latency_ms": 1000000.0},
        {"p95_processing_latency_ms": 1000000.0},
        {"cases": 7, "unlabeled_cases": 2},  # Internally additive fake row.
    ],
)
def test_report_rejects_forged_aggregate_even_when_rows_unchanged(
    changes: dict[str, int | float],
) -> None:
    from dataclasses import replace

    policies = {"tenant-a": policy()}
    exact = replay_historical(dataset(), policies)
    fabricated = replace(exact, metrics=replace(exact.metrics, **changes))
    with pytest.raises(
        ValueError, match="historical metrics do not match replay results"
    ):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-metrics-integrity",
            report=fabricated,
            policies=policies,
        )

    accepted = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-metrics-integrity",
        report=exact,
        policies=policies,
    )
    assert accepted.total_events == len(exact.results)
    assert accepted.confusion.true_positives == exact.metrics.true_positives


@pytest.mark.parametrize(
    ("risk", "is_fraud", "expected", "forged"),
    [
        (
            0.96,
            False,
            ReplayClassification.FALSE_POSITIVE,
            ReplayClassification.TRUE_POSITIVE,
        ),
        (
            0.10,
            True,
            ReplayClassification.FALSE_NEGATIVE,
            ReplayClassification.TRUE_NEGATIVE,
        ),
    ],
)
def test_report_rejects_forged_row_classification_with_matching_aggregates(
    risk: float,
    is_fraud: bool,
    expected: ReplayClassification,
    forged: ReplayClassification,
) -> None:
    """Recomputed aggregate consistency cannot launder a forged row label."""
    policies = {"tenant-a": policy()}
    source = replay_historical(
        (event("classification", IntelligenceSnapshot(network_risk=risk), is_fraud),),
        policies,
    )
    row = source.results[0]
    assert row.classification is expected
    forged_row = replace(row, classification=forged)
    # The aggregate agrees perfectly with the *forged* row, not its event.
    adulterated = replace(
        source,
        results=(forged_row,),
        metrics=_derive_replay_metrics([forged_row]),
    )
    with pytest.raises(ValueError, match="classification does not match"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-forged-classification",
            report=adulterated,
            policies=policies,
        )
    assert build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-original-classification",
        report=source,
        policies=policies,
    ).confusion.true_positives == source.metrics.true_positives


def test_report_rejects_reconciled_outcome_identity_or_clock_forgery() -> None:
    policies = {"tenant-a": policy()}
    original_event = event("outcome", IntelligenceSnapshot(network_risk=0.96), None)
    original = replay_historical((original_event,), policies)
    reconciled = reconcile_outcomes(
        original,
        (
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=original_event.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-review",
                outcome_version="1",
                confirmed_at=T0 + timedelta(days=2),
            ),
        ),
    )
    assert build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-valid-reconciliation",
        report=reconciled,
        policies=policies,
    ).confusion.true_positives == 1
    row = reconciled.results[0]
    assert row.reconciled_outcome is not None
    for changes in (
        {"tenant_id": "tenant-b"},
        {"event_id": uuid4()},
        {"confirmed_at": T0 - timedelta(seconds=1)},
    ):
        forged_row = replace(
            row,
            reconciled_outcome=row.reconciled_outcome.model_copy(update=changes),
        )
        forged_report = replace(
            reconciled,
            results=(forged_row,),
            metrics=_derive_replay_metrics([forged_row]),
        )
        with pytest.raises(ValueError, match="reconciled outcome"):
            build_poc_report(
                tenant_id="tenant-a",
                dataset_id="synthetic-outcome-forgery",
                report=forged_report,
                policies=policies,
            )
    # A row cannot retain post-reconciliation fraud credit without the outcome.
    missing_outcome = replace(row, reconciled_outcome=None)
    with pytest.raises(ValueError, match="classification does not match"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-outcome-removed",
            report=replace(
                reconciled,
                results=(missing_outcome,),
                metrics=_derive_replay_metrics([missing_outcome]),
            ),
            policies=policies,
        )


def test_report_rejects_duplicate_or_cross_identity_replay_rows() -> None:
    policies = {"tenant-a": policy()}
    original = replay_historical(
        (event("identity", IntelligenceSnapshot(network_risk=0.96), False),),
        policies,
    )
    row = original.results[0]
    duplicate = replace(
        original,
        results=(row, row),
        metrics=_derive_replay_metrics([row, row]),
    )
    with pytest.raises(ValueError, match="duplicate replay event identity"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-duplicate",
            report=duplicate,
            policies=policies,
        )

    altered_transaction = row.event.transaction.model_copy(
        update={"tenant_id": "tenant-b"}
    )
    altered_event = row.event.model_copy(
        update={"transaction": altered_transaction}
    )
    forged_row = replace(row, event=altered_event)
    with pytest.raises(ValueError, match="decision does not match replay event"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-identity",
            report=replace(
                original,
                results=(forged_row,),
                metrics=_derive_replay_metrics([forged_row]),
            ),
            policies=policies,
        )
    changed_correlation = replace(
        row,
        decision=row.decision.model_copy(update={"correlation_id": "wrong"}),
    )
    with pytest.raises(ValueError, match="decision does not match replay event"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-correlation",
            report=replace(original, results=(changed_correlation,)),
            policies=policies,
        )


def test_report_rejects_outcome_older_than_confirmed_event_label() -> None:
    policies = {"tenant-a": policy()}
    labeled = event("mature-label", IntelligenceSnapshot(network_risk=0.96), False)
    labeled = labeled.model_copy(
        update={
            "label": ConfirmedOutcomeLabel(
                is_fraud=False,
                label_source="synthetic",
                confirmed_at=T0 + timedelta(days=3),
            )
        }
    )
    original = replay_historical((labeled,), policies)
    stale = reconcile_outcomes(
        original,
        (
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=labeled.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-review",
                outcome_version="1",
                confirmed_at=T0 + timedelta(days=2),
            ),
        ),
    )
    with pytest.raises(ValueError, match="reconciled outcome predates label"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-stale-label",
            report=stale,
            policies=policies,
        )
