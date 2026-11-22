"""Machine-readable POC rates must not turn absent populations into zero scores."""

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.ablation import (
    AblationComparison,
    AblationConfiguration,
    run_ablation,
)
from gasha.poc.attribution import SignalFamily, attribute_signals
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalReplayMetrics,
    HistoricalReplayReport,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.incumbent import (
    ConfusionCounts,
    IncumbentComparison,
    compare_incumbent,
)
from gasha.poc.outcomes import IncumbentControlOutcome
from gasha.poc.report import (
    _ablation_summary,
    _confusion_summary,
    _rate_evidence,
    build_poc_report,
)


def empty_metrics() -> HistoricalReplayMetrics:
    return HistoricalReplayMetrics(
        cases=0,
        labeled_cases=0,
        unlabeled_cases=0,
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        explained_alerts=0,
        mean_decision_latency_seconds=None,
        max_decision_latency_seconds=None,
        mean_detection_lead_time_seconds=None,
    )


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ((0, 0, 0, 0), (None, None, None, None, None)),
        ((0, 0, 3, 0), (None, None, 0.0, None, None)),
        ((0, 1, 0, 0), (None, 0.0, 1.0, 0.0, None)),
        ((2, 1, 3, 1), (2 / 3, 2 / 3, 1 / 4, 2 / 3, 1 / 3)),
    ],
)
def test_confusion_rates_use_actual_denominators(
    counts: tuple[int, int, int, int],
    expected: tuple[float | None, float | None, float | None, float | None, float | None],
) -> None:
    summary = _confusion_summary(*counts)
    actual = (
        summary.recall,
        summary.precision,
        summary.false_positive_rate,
        summary.f1,
        summary.false_negative_rate,
    )
    assert actual == pytest.approx(expected)
    raw_incumbent = ConfusionCounts(*counts)
    assert (
        raw_incumbent.recall,
        raw_incumbent.precision,
        raw_incumbent.false_positive_rate,
    ) == pytest.approx(expected[:3])
    tp, fp, tn, fn = counts
    evidence = summary.rate_evidence
    assert (evidence["recall"].numerator, evidence["recall"].denominator) == (
        tp,
        tp + fn,
    )
    assert (evidence["precision"].numerator, evidence["precision"].denominator) == (
        tp,
        tp + fp,
    )
    assert (evidence["f1"].numerator, evidence["f1"].denominator) == (
        2 * tp,
        2 * tp + fp + fn,
    )
    assert (
        evidence["false_positive_rate"].numerator,
        evidence["false_positive_rate"].denominator,
    ) == (fp, fp + tn)
    assert (
        evidence["false_negative_rate"].numerator,
        evidence["false_negative_rate"].denominator,
    ) == (fn, tp + fn)
    for rate in evidence.values():
        assert (rate.value is None) == (rate.denominator == 0)
        assert (rate.undefined_reason is not None) == (rate.denominator == 0)


@pytest.mark.parametrize("numerator,denominator", [(-1, 1), (2, 1), (0, -1)])
def test_rate_evidence_rejects_inconsistent_populations(
    numerator: int, denominator: int
) -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        _rate_evidence(numerator, denominator, "not_applicable")


def test_empty_poc_report_serializes_nulls_and_reasons() -> None:
    replay = HistoricalReplayReport(results=(), metrics=empty_metrics())
    poc = build_poc_report(
        tenant_id="tenant-synthetic",
        dataset_id="empty-synthetic-cohort",
        report=replay,
        policies={},
    )
    payload = poc.model_dump(mode="json")
    assert payload["confusion"]["recall"] is None
    assert payload["confusion"]["precision"] is None
    assert payload["confusion"]["f1"] is None
    assert payload["confusion"]["false_positive_rate"] is None
    assert payload["confusion"]["false_negative_rate"] is None
    assert payload["confusion"]["rate_evidence"]["precision"] == {
        "numerator": 0,
        "denominator": 0,
        "value": None,
        "undefined_reason": "no_labeled_alerts",
    }
    assert payload["explainability_coverage"] is None
    assert payload["explainability_coverage_evidence"]["denominator"] == 0
    assert payload["explainability_coverage_evidence"]["undefined_reason"] == (
        "no_alerts"
    )
    assert all(
        family["share_of_detected_fraud"] is None
        and family["share_of_detected_fraud_evidence"]["undefined_reason"]
        == "no_detected_fraud"
        for family in payload["signal_attribution"]
    )
    assert any("precision undefined" in caveat for caveat in payload["limitations"])


def test_ablation_reports_undefined_recall_delta_not_zero() -> None:
    comparison = AblationComparison(
        configuration_name="without_device_session",
        removed_families=(),
        true_positives=0,
        false_positives=0,
        true_negatives=0,
        false_negatives=0,
        recall=0.0,
        precision=0.0,
        false_positive_rate=0.0,
        recall_delta=0.0,
        incremental_recall_contribution=0.0,
        false_positive_delta=0,
        detections_lost=0,
    )
    output = _ablation_summary(comparison, empty_metrics()).model_dump(
        mode="json"
    )
    assert output["recall"] is None
    assert output["recall_delta"] is None
    assert output["incremental_recall_contribution"] is None
    assert output["recall_delta_undefined_reason"] == "no_confirmed_fraud"
    assert output["rate_evidence"]["f1"]["undefined_reason"] == (
        "no_positive_labels_or_alerts"
    )


def test_unlabeled_alert_counts_in_explainability_denominator() -> None:
    transaction = CanonicalTransaction(
        tenant_id="tenant-synthetic",
        event_id=uuid4(),
        occurred_at=datetime(2026, 2, 10, tzinfo=UTC),
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("2500.00"),
        currency="ETB",
        sender_customer_id="customer-synthetic",
        sender_account_id="account-synthetic",
        beneficiary_id="beneficiary-synthetic",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-synthetic",
        correlation_id="corr-synthetic",
    )
    event = HistoricalTransactionEvent(
        transaction=transaction,
        intelligence=IntelligenceSnapshot(network_risk=0.96),
    )
    policies = {
        "tenant-synthetic": DecisionPolicy(
            configuration_version="config-synthetic",
            policy_version="policy-synthetic",
            rule_version="rules-synthetic",
        )
    }
    replay = replay_historical((event,), policies)
    assert replay.metrics.labeled_cases == 0
    assert replay.metrics.explained_alerts == 1

    poc = build_poc_report(
        tenant_id="tenant-synthetic",
        dataset_id="unlabeled-alert-synthetic",
        report=replay,
        policies=policies,
    )
    assert poc.confusion.precision is None
    assert poc.explainability_coverage == 1.0
    assert poc.explainability_coverage_evidence.numerator == 1
    assert poc.explainability_coverage_evidence.denominator == 1
    assert poc.explainability_coverage_evidence.undefined_reason is None


def test_empty_observed_incumbent_comparison_cannot_claim_zero_percent_rates() -> None:
    comparison = compare_incumbent(())
    assert comparison.evaluated_cases == 0
    assert comparison.missing_incumbent_outcomes == 0
    for counts in (comparison.gasha, comparison.incumbent):
        assert counts.recall is None
        assert counts.precision is None
        assert counts.false_positive_rate is None
    summary = _confusion_summary(0, 0, 0, 0).model_dump(mode="json")
    for key in ("recall", "precision", "false_positive_rate"):
        assert summary[key] is None
        assert summary["rate_evidence"][key]["denominator"] == 0
        assert summary["rate_evidence"][key]["undefined_reason"]


def test_supplied_unscoped_or_foreign_attribution_cannot_enter_tenant_report() -> None:
    replay = HistoricalReplayReport(results=(), metrics=empty_metrics())
    unscoped = attribute_signals((), {})
    for attribution in (unscoped, replace(unscoped, tenant_id="tenant-other")):
        with pytest.raises(ValueError, match="attribution tenant mismatch"):
            build_poc_report(
                tenant_id="tenant-synthetic",
                dataset_id="synthetic-empty",
                report=replay,
                policies={},
                attribution=attribution,
            )


def _attribution_event(
    tenant_id: str,
    *,
    event_id: UUID | None = None,
    is_fraud: bool = True,
    network_risk: float = 0.97,
    beneficiary_risk: float = 0.94,
) -> HistoricalTransactionEvent:
    """Invented labeled events; no bank data, customer IDs or observed outcomes."""
    identity = event_id or uuid4()
    return HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id=tenant_id,
            event_id=identity,
            occurred_at=datetime(2026, 2, 10, tzinfo=UTC),
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal("100.00"),
            currency="ETB",
            sender_customer_id=f"fictional-{tenant_id}-{identity}",
            sender_account_id=f"fictional-account-{tenant_id}-{identity}",
            beneficiary_id="fictional-beneficiary",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="fictional-destination",
            correlation_id=f"fictional-correlation-{tenant_id}-{identity}",
        ),
        intelligence=IntelligenceSnapshot(
            network_risk=network_risk,
            beneficiary_risk=beneficiary_risk,
        ),
        label=ConfirmedOutcomeLabel(
            is_fraud=is_fraud,
            label_source="synthetic",
        ),
    )


def _attribution_policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="config-synthetic",
        policy_version="policy-synthetic",
        rule_version="rules-synthetic",
    )


def test_relabeling_foreign_attribution_cannot_contaminate_empty_or_nonempty_replay() -> None:
    """QA/Security regression: replacing only top-level tenant must not launder evidence."""
    tenant_a, tenant_b = "tenant-a", "tenant-b"
    shared_id = uuid4()  # Even colliding UUIDs must remain tenant scoped.
    policies_a, policies_b = (
        {tenant_a: _attribution_policy()},
        {tenant_b: _attribution_policy()},
    )
    b_replay = replay_historical(
        (_attribution_event(tenant_b, event_id=shared_id, is_fraud=False),),
        policies_b,
    )
    foreign = attribute_signals(b_replay.results, policies_b)
    assert foreign.families[SignalFamily.NETWORK].false_positives_influenced == 1
    relabeled = replace(foreign, tenant_id=tenant_a)
    a_replay = replay_historical(
        (_attribution_event(tenant_a, event_id=shared_id),), policies_a
    )
    for replay in (HistoricalReplayReport(results=(), metrics=empty_metrics()), a_replay):
        with pytest.raises(ValueError, match="attribution does not match replay cohort"):
            build_poc_report(
                tenant_id=tenant_a,
                dataset_id="fictional-cohort",
                report=replay,
                policies=policies_a,
                attribution=relabeled,
            )


def test_supplied_attribution_requires_exact_event_set_and_current_decisions() -> None:
    tenant_id = "tenant-a"
    policies = {tenant_id: _attribution_policy()}
    first = _attribution_event(tenant_id)
    second = _attribution_event(tenant_id, is_fraud=False)
    replay = replay_historical((first, second), policies)
    original = attribute_signals(replay.results, policies)
    assert len(original.events) == 2

    wrong_cohort = replay_historical((_attribution_event(tenant_id),), policies)
    stale_same_identity = replay_historical(
        (first.model_copy(update={
            "intelligence": IntelligenceSnapshot(
                network_risk=0.02, beneficiary_risk=0.01
            )
        }), second),
        policies,
    )
    for replay_for_report, provided in (
        (replay, replace(original, events=original.events[:1])),
        (replay, replace(original, events=original.events + original.events[:1])),
        (wrong_cohort, original),
        (stale_same_identity, original),
    ):
        with pytest.raises(ValueError, match="attribution does not match replay cohort"):
            build_poc_report(
                tenant_id=tenant_id,
                dataset_id="fictional-cohort",
                report=replay_for_report,
                policies=policies,
                attribution=provided,
            )


def test_supplied_attribution_cannot_forge_family_counts_or_reason_codes() -> None:
    tenant_id = "tenant-a"
    policies = {tenant_id: _attribution_policy()}
    replay = replay_historical((_attribution_event(tenant_id),), policies)
    original = attribute_signals(replay.results, policies)
    network = original.families[SignalFamily.NETWORK]
    forged_counts = replace(
        original,
        families={
            **original.families,
            SignalFamily.NETWORK: replace(network, alerts_influenced=0),
        },
    )
    assert original.multi_signal.detections
    first_detection = original.multi_signal.detections[0]
    forged_reasons = replace(
        original,
        multi_signal=replace(
            original.multi_signal,
            detections=(
                replace(first_detection, reason_codes=("FICTIONAL_FORGED_REASON",)),
                *original.multi_signal.detections[1:],
            ),
        ),
    )
    forged_named_combo = replace(
        original,
        multi_signal=replace(
            original.multi_signal,
            named_combination_detections={"forged_combination": 1},
        ),
    )
    for supplied in (forged_counts, forged_reasons, forged_named_combo):
        with pytest.raises(ValueError, match="attribution does not match replay cohort"):
            build_poc_report(
                tenant_id=tenant_id,
                dataset_id="fictional-cohort",
                report=replay,
                policies=policies,
                attribution=supplied,
            )


def test_matching_supplied_attribution_accepts_unordered_events_and_is_identical() -> None:
    tenant_id = "tenant-a"
    policies = {tenant_id: _attribution_policy()}
    replay = replay_historical(
        (_attribution_event(tenant_id), _attribution_event(tenant_id, is_fraud=False)),
        policies,
    )
    original = attribute_signals(replay.results, policies)
    reordered = replace(
        original,
        events=tuple(reversed(original.events)),
        multi_signal=replace(
            original.multi_signal,
            detections=tuple(reversed(original.multi_signal.detections)),
        ),
    )
    args = {
        "tenant_id": tenant_id,
        "dataset_id": "fictional-cohort",
        "report": replay,
        "policies": policies,
    }
    computed = build_poc_report(**args)
    supplied = build_poc_report(**args, attribution=reordered)
    assert supplied.model_dump(mode="json") == computed.model_dump(mode="json")
    assert supplied.signal_attribution
    assert computed.confusion.true_positives == 1
    assert computed.confusion.false_positives == 1



def test_unrecorded_incumbent_cannot_claim_arithmetic_consistent_incremental_fraud() -> None:
    """Security P1: missing incumbent outcome is never an observed non-alert."""
    tenant = "tenant-a"
    policies = {tenant: _attribution_policy()}
    replay = replay_historical((_attribution_event(tenant),), policies)
    fabricated = IncumbentComparison(
        evaluated_cases=1,
        missing_incumbent_outcomes=0,
        gasha=ConfusionCounts(1, 0, 0, 0),
        incumbent=ConfusionCounts(0, 0, 0, 1),
        both_detected=0,
        gasha_only_detected=1,
        incumbent_only_detected=0,
        neither_detected=0,
        incremental_confirmed_detection=1,
    )
    assert build_poc_report(
        tenant_id=tenant, dataset_id="no-control-observed",
        report=replay, policies=policies,
    ).incumbent_comparison is None
    with pytest.raises(ValueError, match="incumbent does not match recorded"):
        build_poc_report(
            tenant_id=tenant, dataset_id="forged-control",
            report=replay, policies=policies, incumbent=fabricated,
        )


def test_provided_incumbent_requires_exact_recorded_replay_comparison() -> None:
    tenant = "tenant-a"
    policies = {tenant: _attribution_policy()}
    event = _attribution_event(tenant).model_copy(
        update={"incumbent_outcome": IncumbentControlOutcome.NO_ALERT}
    )
    replay = replay_historical((event,), policies)
    recorded = compare_incumbent(replay.results)
    assert recorded.incremental_confirmed_detection == 1
    baseline = build_poc_report(
        tenant_id=tenant, dataset_id="observed-synthetic",
        report=replay, policies=policies,
    ).model_dump(mode="json")
    accepted = build_poc_report(
        tenant_id=tenant, dataset_id="observed-synthetic",
        report=replay, policies=policies, incumbent=recorded,
    ).model_dump(mode="json")
    assert accepted == baseline
    with pytest.raises(ValueError, match="incumbent does not match recorded"):
        build_poc_report(
            tenant_id=tenant, dataset_id="forged-control",
            report=replay, policies=policies,
            incumbent=replace(recorded, missing_incumbent_outcomes=1),
        )


def test_report_binds_ablation_to_same_tenant_replay_and_derived_counts() -> None:
    tenant = "tenant-a"
    policies = {tenant: _attribution_policy()}
    event = _attribution_event(tenant)
    events = (event,)
    replay = replay_historical(events, policies)
    configs = (
        AblationConfiguration(
            name="without_network",
            removed_families=frozenset({SignalFamily.NETWORK}),
        ),
        AblationConfiguration(
            name="without_beneficiary",
            removed_families=frozenset({SignalFamily.BENEFICIARY}),
        ),
    )
    ablation = run_ablation(events, policies, configurations=configs)
    baseline = build_poc_report(
        tenant_id=tenant, dataset_id="matched-ablation",
        report=replay, policies=policies, ablation=ablation,
    ).model_dump(mode="json")
    reordered = replace(
        ablation,
        comparisons=tuple(reversed(ablation.comparisons)),
        unique_detections=tuple(reversed(ablation.unique_detections)),
    )
    assert build_poc_report(
        tenant_id=tenant, dataset_id="matched-ablation",
        report=replay, policies=policies, ablation=reordered,
    ).model_dump(mode="json") == baseline

    stale = run_ablation((_attribution_event(tenant),), policies, configurations=configs)
    foreign = run_ablation(
        (_attribution_event("tenant-b", event_id=event.transaction.event_id),),
        {"tenant-b": _attribution_policy()},
        configurations=configs,
    )
    altered_counts = replace(
        ablation,
        comparisons=(
            replace(ablation.comparisons[0], detections_lost=999),
            *ablation.comparisons[1:],
        ),
    )
    altered_unique = replace(ablation, unique_detections=())
    for bad in (stale, foreign, altered_counts, altered_unique):
        with pytest.raises(ValueError, match="ablation does not match replay cohort"):
            build_poc_report(
                tenant_id=tenant, dataset_id="untrusted-ablation",
                report=replay, policies=policies, ablation=bad,
            )


def test_ablation_rejects_duplicate_configuration_names_before_reporting() -> None:
    tenant = "tenant-a"
    policies = {tenant: _attribution_policy()}
    events = (_attribution_event(tenant),)
    replay = replay_historical(events, policies)
    ablation = run_ablation(
        events, policies,
        configurations=(AblationConfiguration(
            name="without_network",
            removed_families=frozenset({SignalFamily.NETWORK}),
        ),),
    )
    duplicated = replace(ablation, comparisons=ablation.comparisons * 2)
    with pytest.raises(ValueError, match="invalid configurations"):
        build_poc_report(
            tenant_id=tenant, dataset_id="duplicate-ablation",
            report=replay, policies=policies, ablation=duplicated,
        )
