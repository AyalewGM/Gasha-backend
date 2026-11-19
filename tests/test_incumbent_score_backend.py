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
    replay_historical,
)
from gasha.poc.incumbent import (
    IncumbentScoreBackend,
    IncumbentScoreUnavailable,
    build_incumbent_scores,
    compare_incumbent,
)
from gasha.poc.outcomes import IncumbentControlOutcome

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
    backend = IncumbentScoreBackend(POLICY, {eid: 0.97})
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
    backend = IncumbentScoreBackend(POLICY, {eid: 0.60})
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
        [{"event_id": str(eid), "risk_score": 750}],
        score_max=1000.0,
    )
    assert scores == {eid: 0.75}


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
        build_incumbent_scores([record])


def test_build_scores_rejects_duplicate_event_ids() -> None:
    eid = UUID(int=9)
    with pytest.raises(IncumbentScoreUnavailable):
        build_incumbent_scores(
            [
                {"event_id": eid, "risk_score": 0.3},
                {"event_id": eid, "risk_score": 0.9},
            ]
        )


# ---------------- Replay + comparison integration ----------------


def _cohort_with_ng() -> tuple[list[HistoricalTransactionEvent], dict[UUID, float]]:
    """2 fraud + 6 legit; the incumbent alerts on one fraud and three legit
    (the FP-heavy profile the challenger must beat)."""
    events = [event(n, fraud=n < 2) for n in range(8)]
    scores: dict[UUID, float] = {}
    for n, ev in enumerate(events):
        eid = ev.transaction.event_id
        scores[eid] = 0.90 if n in (0, 2, 3, 4) else 0.10
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


def test_incumbent_outcome_path_and_score_path_agree() -> None:
    events, scores = _cohort_with_ng()
    ng_records = normalize_netguardians_export(
        [
            {
                "event_id": str(eid),
                "risk_score": score * 1000,
                "verdict": "alert" if score >= POLICY.review_threshold else "allow",
            }
            for eid, score in scores.items()
        ],
        score_max=1000.0,
    )
    outcome_by_id = {r.event_id: r.outcome for r in ng_records}
    events = [
        ev.model_copy(
            update={"incumbent_outcome": outcome_by_id[ev.transaction.event_id]}
        )
        for ev in events
    ]
    report = replay_historical(
        events,
        {"tenant-a": POLICY},
        service_factory=lambda policy: IncumbentScoreBackend(policy, scores),
    )
    comparison = compare_incumbent(report.results)
    # Here Gasha *is* the incumbent backend, so both sides must agree exactly.
    assert comparison.evaluated_cases == 8
    assert comparison.both_detected == 4
    assert comparison.gasha_only_detected == 0
    assert comparison.incumbent_only_detected == 0
    assert comparison.missing_incumbent_outcomes == 0


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
            [{"event_id": str(UUID(int=1)), "risk_score": 0.5, "verdict": "zzz"}]
        )


def test_normalize_export_rejects_empty_and_duplicates() -> None:
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export([])
    eid = str(UUID(int=5))
    with pytest.raises(NetGuardiansExportRejected):
        normalize_netguardians_export(
            [
                {"event_id": eid, "risk_score": 0.1, "verdict": "allow"},
                {"event_id": eid, "risk_score": 0.9, "verdict": "alert"},
            ]
        )
