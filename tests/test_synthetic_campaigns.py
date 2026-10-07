from __future__ import annotations

from gasha.domain.models import DecisionPolicy
from gasha.poc.ablation import (
    IncrementalDetectionReason,
    run_ablation,
)
from gasha.poc.attribution import SignalFamily, attribute_signals
from gasha.poc.campaigns import social_engineering_campaign
from gasha.poc.historical import replay_historical
from gasha.poc.report import build_poc_report


def policies(*tenant_ids: str) -> dict[str, DecisionPolicy]:
    return {
        tenant_id: DecisionPolicy(
            configuration_version="tenant-config-1",
            policy_version="policy-1",
            rule_version="rules-1",
            model_version="model-1",
        )
        for tenant_id in tenant_ids
    }


def _run(tenant_id: str = "tenant-a"):
    events = social_engineering_campaign(tenant_id=tenant_id)
    return replay_historical(events, policies(tenant_id))


def test_campaign_dataset_is_deterministic() -> None:
    first = social_engineering_campaign()
    second = social_engineering_campaign()
    assert [e.transaction.event_id for e in first] == [
        e.transaction.event_id for e in second
    ]
    assert [e.transaction.occurred_at for e in first] == [
        e.transaction.occurred_at for e in second
    ]


def test_campaign_metrics_are_non_degenerate() -> None:
    report = _run()
    m = report.metrics
    assert m.cases == 13
    assert m.labeled_cases == 13
    # Ambiguous data: some fraud is missed, some legitimate traffic alerts.
    assert m.true_positives == 6
    assert m.false_negatives == 3
    assert m.false_positives == 1
    assert m.true_negatives == 3
    assert 0.0 < m.recall < 1.0
    assert 0.0 < m.precision < 1.0
    assert m.false_positive_rate > 0.0


def test_campaign_attribution_covers_multiple_families() -> None:
    report = _run()
    attribution = attribute_signals(report.results, policies("tenant-a"))
    tp_influenced = {
        family
        for family, summary in attribution.families.items()
        if summary.true_positives_influenced
    }
    assert SignalFamily.RELATIONSHIP in tp_influenced
    assert SignalFamily.TRANSACTION in tp_influenced
    assert SignalFamily.DEVICE_SESSION in tp_influenced
    assert SignalFamily.BENEFICIARY in tp_influenced
    assert SignalFamily.NETWORK in tp_influenced
    # Velocity is deliberately sub-alerting in the campaign controls.
    assert (
        attribution.families[SignalFamily.VELOCITY].alerts_influenced == 0
    )
    # Strong-emergency (rel+tx), coached (rel+dev), SIM-swap-like
    # (dev+tx) and mule-core (ben+net) all combine two families.
    assert len(attribution.multi_signal.detections) == 4
    named = attribution.multi_signal.named_combination_detections
    assert named["new_beneficiary_active_call"] >= 1
    assert named["fan_in_repeat_victims"] >= 1
    assert named["new_beneficiary_unusual_amount"] >= 1


def test_campaign_ablation_finds_necessary_signal_families() -> None:
    events = social_engineering_campaign()
    report = run_ablation(events, policies("tenant-a"))

    unique = {(u.family, u.event_id) for u in report.unique_detections}
    unique_families = {family for family, _ in unique}
    # compromised-contact needs relationship; weak-network mule needs
    # beneficiary. Other families participate but are never solely
    # necessary on this dataset.
    assert unique_families == {
        SignalFamily.RELATIONSHIP,
        SignalFamily.BENEFICIARY,
    }
    reasons = {u.reason for u in report.unique_detections}
    assert reasons == {
        IncrementalDetectionReason.RELATIONSHIP_INCREMENTAL_DETECTION,
        IncrementalDetectionReason.BENEFICIARY_INCREMENTAL_DETECTION,
    }

    by_name = {c.configuration_name: c for c in report.comparisons}
    assert (
        by_name["without_relationship"].incremental_recall_contribution
        > 0.0
    )
    assert by_name["without_beneficiary"].detections_lost == 1
    # Removing transaction drops the legitimate false positive.
    assert by_name["without_transaction"].false_positive_delta == -1


def test_campaign_feeds_full_poc_report() -> None:
    events = social_engineering_campaign()
    policies_map = policies("tenant-a")
    report = replay_historical(events, policies_map)
    ablation = run_ablation(events, policies_map)

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="epic3-campaign-1",
        report=report,
        policies=policies_map,
        ablation=ablation,
    )

    assert poc.total_events == 13
    assert poc.confusion.true_positives == 6
    assert poc.unique_detections
    assert poc.incumbent_comparison is not None
    assert poc.incumbent_comparison.evaluated_cases == 13
    assert poc.incumbent_comparison.gasha_only_detected == 4
    assert poc.incumbent_comparison.incremental_confirmed_detection == 3
    assert poc.incumbent_comparison.incumbent_only_detected == 1
    assert poc.limitations


def test_campaign_is_tenant_scoped() -> None:
    events_a = social_engineering_campaign(tenant_id="tenant-a")
    events_b = social_engineering_campaign(tenant_id="tenant-b")
    both = replay_historical(
        (*events_a, *events_b), policies("tenant-a", "tenant-b")
    )
    a_results = [r for r in both.results if r.decision.tenant_id == "tenant-a"]
    b_results = [r for r in both.results if r.decision.tenant_id == "tenant-b"]
    assert len(a_results) == len(b_results) == 13
    # Same campaign shape, but decisions stay under each tenant's scope.
    assert {
        r.decision.action for r in a_results
    } == {r.decision.action for r in b_results}
