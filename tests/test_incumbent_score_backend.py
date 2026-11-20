"""Incumbent-score replay and NetGuardians export normalization tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ingestion.netguardians import (
    NetGuardiansExportRejected,
    map_netguardians_outcome,
    normalize_netguardians_export,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    ReplayDecisionSource,
    replay_historical,
)
from gasha.poc.incumbent import (
    IncumbentScoreBackend,
    IncumbentScoreUnavailable,
    build_incumbent_scores,
    compare_incumbent,
)
from gasha.poc.outcomes import IncumbentControlOutcome
from gasha.poc.report import build_poc_report

AT = datetime(2026, 1, 1, 9, tzinfo=UTC)
CUTOFF = AT + timedelta(days=30)

POLICY = DecisionPolicy(
    configuration_version="incumbent-cfg-v1",
    policy_version="incumbent-rules-v1",
    rule_version="incumbent-export-v1",
)


def event(number: int, *, fraud: bool) -> HistoricalTransactionEvent:
    occurred = AT + timedelta(minutes=number)
    return HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id="tenant-a",
            event_id=UUID(int=number + 1),
            occurred_at=occurred,
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal(500),
            currency="ETB",
            sender_customer_id=f"customer-{number}",
            sender_account_id=f"account-{number}",
            beneficiary_id=f"beneficiary-{number}",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="external-bank",
            correlation_id=f"corr-{number}",
        ),
        intelligence=IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(
            is_fraud=fraud,
            label_source="synthetic-analyst",
            confirmed_at=occurred + timedelta(days=5),
        ),
    )


# ---------------- IncumbentScoreBackend ----------------


def test_backend_maps_score_through_policy_thresholds() -> None:
    eid = UUID(int=42)
    backend = IncumbentScoreBackend(POLICY, {("tenant-a", eid): 0.97})
    ev = event(41, fraud=True)
    decision = backend.decide(
        ev.transaction.model_copy(update={"event_id": eid}), ev.intelligence
    )
    assert decision.action == DecisionAction.BLOCK
    assert decision.risk_score == pytest.approx(0.97)
    assert "INCUMBENT_HIGH_SCORE" in decision.reason_codes
    assert decision.rule_version == "incumbent-export-v1"


def test_backend_below_review_marks_not_alerting() -> None:
    eid = UUID(int=7)
    backend = IncumbentScoreBackend(POLICY, {("tenant-a", eid): 0.60})
    ev = event(6, fraud=False)
    decision = backend.decide(
        ev.transaction.model_copy(update={"event_id": eid}), ev.intelligence
    )
    assert decision.action == DecisionAction.MONITOR
    assert "INCUMBENT_BELOW_REVIEW" in decision.reason_codes


def test_backend_missing_score_fails_closed() -> None:
    backend = IncumbentScoreBackend(POLICY, {})
    ev = event(0, fraud=False)
    with pytest.raises(IncumbentScoreUnavailable):
        backend.decide(ev.transaction, ev.intelligence)


# ---------------- build_incumbent_scores ----------------


def test_build_scores_normalizes_vendor_scale() -> None:
    eid = UUID(int=3)
    scores = build_incumbent_scores(
        [{"tenant_id": "tenant-a", "event_id": str(eid), "risk_score": 750}],
        score_max=1000.0,
    )
    assert scores == {("tenant-a", eid): 0.75}


@pytest.mark.parametrize(
    "record",
    [
        {"event_id": "not-a-uuid", "risk_score": 0.5},
        {"event_id": UUID(int=1), "risk_score": "high"},
        {"event_id": UUID(int=1), "risk_score": True},
        {"event_id": UUID(int=1)},
        {"risk_score": 0.5},
        {"event_id": UUID(int=1), "risk_score": 1.5},
        {"event_id": UUID(int=1), "risk_score": float("nan")},
    ],
)
def test_build_scores_rejects_malformed_records(record) -> None:
    with pytest.raises(IncumbentScoreUnavailable):
        build_incumbent_scores([{"tenant_id": "tenant-a", **record}])


def test_build_scores_rejects_duplicate_event_ids() -> None:
    eid = UUID(int=9)
    with pytest.raises(IncumbentScoreUnavailable):
        build_incumbent_scores(
            [
                {"tenant_id": "tenant-a", "event_id": eid, "risk_score": 0.3},
                {"tenant_id": "tenant-a", "event_id": eid, "risk_score": 0.9},
            ]
        )


# ---------------- Replay + comparison integration ----------------


def _cohort_with_ng() -> tuple[
    list[HistoricalTransactionEvent], dict[tuple[str, UUID], float]
]:
    """2 fraud + 6 legit; the incumbent alerts on one fraud and three legit
    (the FP-heavy profile the challenger must beat)."""
    events = [event(n, fraud=n < 2) for n in range(8)]
    scores: dict[tuple[str, UUID], float] = {}
    for n, ev in enumerate(events):
        eid = ev.transaction.event_id
        scores[(ev.transaction.tenant_id, eid)] = 0.90 if n in (0, 2, 3, 4) else 0.10
    return events, scores


def test_replay_through_incumbent_backend_reports_ng_metrics() -> None:
    events, scores = _cohort_with_ng()
    report = replay_historical(
        events,
        {"tenant-a": POLICY},
        service_factory=lambda policy: IncumbentScoreBackend(policy, scores),
    )
    metrics = report.metrics
    assert metrics.labeled_cases == 8
    # NG alerted events 0 (fraud), 2, 3, 4 (legit): TP=1 FP=3 TN=3 FN=1.
    assert metrics.true_positives == 1
    assert metrics.false_positives == 3
    assert metrics.recall == pytest.approx(0.5)
    assert metrics.false_positive_rate == pytest.approx(0.5)


def test_observed_and_threshold_simulated_outcomes_remain_independent() -> None:
    events, scores = _cohort_with_ng()
    ng_records = normalize_netguardians_export(
        [
            {
                "tenant_id": tenant,
                "event_id": str(eid),
                "risk_score": score * 1000,
                # The Bank's observed verdict can disagree with a simulated threshold.
                "verdict": (
                    "allow" if eid == UUID(int=1)
                    else "alert" if eid == UUID(int=2)
                    else "alert" if score >= POLICY.review_threshold
                    else "allow"
                ),
            }
            for (tenant, eid), score in scores.items()
        ],
        score_max=1000.0,
    )
    outcome_by_id = {(r.tenant_id, r.event_id): r.outcome for r in ng_records}
    events = [
        ev.model_copy(
            update={
                "incumbent_outcome": outcome_by_id[
                    (ev.transaction.tenant_id, ev.transaction.event_id)
                ]
            }
        )
        for ev in events
    ]
    report = replay_historical(
        events,
        {"tenant-a": POLICY},
        service_factory=lambda policy: IncumbentScoreBackend(policy, scores),
    )
    # Threshold-simulated actions can disagree with the observed Bank export,
    # but neither may be serialized as an actual Gasha detection.
    assert all(
        result.decision_source is ReplayDecisionSource.INCUMBENT_SCORE_SIMULATION
        for result in report.results
    )
    assert report.results[0].decision.action in (
        DecisionAction.REVIEW, DecisionAction.HOLD, DecisionAction.BLOCK
    )
    assert events[0].incumbent_outcome == IncumbentControlOutcome.NO_ALERT
    with pytest.raises(ValueError, match="requires genuine Gasha decisions"):
        compare_incumbent(report.results)
    with pytest.raises(ValueError, match="cannot label simulated"):
        build_poc_report(
            tenant_id="tenant-a",
            dataset_id="synthetic-incumbent-score",
            report=report,
            policies={"tenant-a": POLICY},
        )

    # The actual Gasha decision path and the mapped observed incumbent outcome
    # remain eligible for the existing scenario/confusion comparison.
    gasha_report = replay_historical(events, {"tenant-a": POLICY})
    assert all(
        result.decision_source is ReplayDecisionSource.GASHA_DECISION
        for result in gasha_report.results
    )
    comparison = compare_incumbent(gasha_report.results)
    assert comparison.evaluated_cases == 8
    assert comparison.missing_incumbent_outcomes == 0
    assert comparison.gasha.false_negatives == 2
    assert comparison.incumbent.true_positives == 1
    assert comparison.incumbent.false_positives == 3
    assert comparison.incumbent_only_detected == 4
    assert comparison.incremental_confirmed_detection == 0
    poc_report = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="synthetic-gasha-versus-observed",
        report=gasha_report,
        policies={"tenant-a": POLICY},
    )
    assert poc_report.incumbent_comparison is not None
    assert poc_report.incumbent_comparison.incumbent.true_positives == 1


# ---------------- NetGuardians normalization ----------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("allow", IncumbentControlOutcome.NO_ALERT),
        ("Recommend-Block", IncumbentControlOutcome.BLOCK),
        ("MANUAL REVIEW", IncumbentControlOutcome.REVIEW),
        ("step-up", IncumbentControlOutcome.CHALLENGE),
    ],
)
def test_verdict_mapping(raw, expected) -> None:
    assert map_netguardians_outcome(raw) == expected


def test_unknown_verdict_fails_closed() -> None:
    with pytest.raises(NetGuardiansExportRejected):
        map_netguardians_outcome("quarantine")


def test_normalize_export_rejects_orphan_rows() -> None:
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export(
            [{"tenant_id": "tenant-a", "event_id": str(UUID(int=1)),
              "risk_score": 0.5, "verdict": "zzz"}]
        )


def test_normalize_export_rejects_empty_and_duplicates() -> None:
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export([])
    eid = str(UUID(int=5))
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export(
            [
                {"tenant_id": "tenant-a", "event_id": eid,
                 "risk_score": 0.1, "verdict": "allow"},
                {"tenant_id": "tenant-a", "event_id": eid,
                 "risk_score": 0.9, "verdict": "alert"},
            ]
        )


def test_two_tenants_same_uuid_have_distinct_threshold_simulations() -> None:
    eid = UUID(int=1)
    scores = build_incumbent_scores([
        {"tenant_id": "tenant-a", "event_id": eid, "risk_score": 0.97},
        {"tenant_id": "tenant-b", "event_id": eid, "risk_score": 0.02},
    ])
    first = event(0, fraud=True)
    second = first.model_copy(
        update={
            "transaction": first.transaction.model_copy(
                update={"tenant_id": "tenant-b", "correlation_id": "different"}
            ),
        }
    )
    report = replay_historical(
        [first, second],
        {"tenant-a": POLICY, "tenant-b": POLICY},
        service_factory=lambda policy: IncumbentScoreBackend(policy, scores),
    )
    actions = {item.decision.tenant_id: item.decision.action for item in report.results}
    assert actions["tenant-a"] == DecisionAction.BLOCK
    assert actions["tenant-b"] == DecisionAction.ALLOW


def test_colliding_uuid_never_substitutes_missing_tenant_score() -> None:
    eid = UUID(int=1)
    backend = IncumbentScoreBackend(POLICY, {("tenant-a", eid): 0.96})
    ev = event(0, fraud=True)
    cross_tenant = ev.transaction.model_copy(update={"tenant_id": "tenant-b"})
    with pytest.raises(IncumbentScoreUnavailable):
        backend.decide(cross_tenant, ev.intelligence)


def test_tenant_scoped_duplicate_and_cross_tenant_reuse() -> None:
    eid = UUID(int=5)
    rows = [
        {"tenant_id": "tenant-a", "event_id": eid, "risk_score": 0.1},
        {"tenant_id": "tenant-b", "event_id": eid, "risk_score": 0.9},
    ]
    assert len(build_incumbent_scores(rows)) == 2
    with pytest.raises(IncumbentScoreUnavailable):
        build_incumbent_scores([rows[0], rows[0]])
    ng_rows = [{**r, "verdict": "allow"} for r in rows]
    assert len(normalize_netguardians_export(ng_rows)) == 2
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export([ng_rows[0], ng_rows[0]])


@pytest.mark.parametrize("tenant", [None, "", " ", " tenant-a ", 0])
def test_missing_or_invalid_tenant_fails_closed(tenant: object) -> None:
    row = {"tenant_id": tenant, "event_id": str(UUID(int=5)), "risk_score": 0.5}
    with pytest.raises(IncumbentScoreUnavailable):
        build_incumbent_scores([row])
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export([{**row, "verdict": "allow"}])


@pytest.mark.parametrize("score", [float("inf"), float("-inf"), float("nan"), -1, 2, True])
def test_invalid_incumbent_scores_rejected_from_both_paths(score: object) -> None:
    row = {"tenant_id": "tenant-a", "event_id": str(UUID(int=5)), "risk_score": score}
    with pytest.raises(IncumbentScoreUnavailable):
        build_incumbent_scores([row])
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export([{**row, "verdict": "allow"}])


def test_bank_export_cannot_be_credited_to_untested_thresholds() -> None:
    eid = UUID(int=5)
    observed = normalize_netguardians_export([{
        "tenant_id": "tenant-a",
        "event_id": eid,
        "risk_score": 0.97,
        "verdict": "allow",
    }])
    assert observed[0].outcome == IncumbentControlOutcome.NO_ALERT
    action = IncumbentScoreBackend(
        POLICY, {("tenant-a", eid): observed[0].risk_score}
    ).decide(
        event(4, fraud=False).transaction.model_copy(update={"event_id": eid}),
        IntelligenceSnapshot(),
    ).action
    assert action == DecisionAction.BLOCK
    assert observed[0].outcome.alerted is False
