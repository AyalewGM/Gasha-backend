"""Manifest → candidate policy → activation draft/evidence tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from gasha.configuration.kernel import ConfigKind, ConfigLifecycle
from gasha.ml.activation import (
    ActivationRejected,
    activation_evidence,
    candidate_policy,
    draft_policy_entry,
)
from gasha.ml.manifest import ModelManifest
from gasha.ml.replay import PromotionEvaluation
from gasha.poc.historical import HistoricalReplayMetrics


def manifest(**changes: object) -> ModelManifest:
    metrics = {
        "validation_rows": 10,
        "validation_positives": 2,
        "validation_negatives": 8,
        "auc": 0.9,
        **{
            name: {
                "threshold": 0.5,
                "realized_fpr": 0.0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
            }
            for name in ("at_monitor", "at_review", "at_hold", "at_block")
        },
    }
    values: dict[str, object] = {
        "model_version": "model-1",
        "xgboost_version": "2.1.4",
        "trained_at": datetime(2026, 2, 1, tzinfo=UTC),
        "label_cutoff": datetime(2026, 1, 20, tzinfo=UTC),
        "cohort_digest": "sha256:" + "a" * 64,
        "training_rows": 100,
        "matured_positive": 20,
        "matured_negative": 80,
        "calibration": "isotonic",
        "calibration_knots": ((0.0, 0.0), (0.5, 0.4), (1.0, 1.0)),
        "thresholds": {
            "monitor_threshold": 0.40,
            "challenge_threshold": 0.55,
            "review_threshold": 0.60,
            "hold_threshold": 0.80,
            "block_threshold": 0.95,
        },
        "metrics": metrics,
    }
    values.update(changes)
    return ModelManifest(**values)  # type: ignore[arg-type]


def replay_metrics() -> HistoricalReplayMetrics:
    return HistoricalReplayMetrics(
        cases=10,
        labeled_cases=10,
        unlabeled_cases=0,
        true_positives=2,
        false_positives=1,
        true_negatives=6,
        false_negatives=1,
        explained_alerts=3,
        mean_decision_latency_seconds=0.001,
        max_decision_latency_seconds=0.002,
        mean_detection_lead_time_seconds=None,
    )


def evaluation(*, promotes: bool = True) -> PromotionEvaluation:
    return PromotionEvaluation(
        rules=replay_metrics(),
        model=replay_metrics(),
        label_cutoff=datetime(2026, 1, 20, tzinfo=UTC),
        total_events=10,
        matured_labeled_events=10,
        masked_unconfirmed_count=0,
        masked_late_count=0,
        fraud_positive_denominator=3,
        legitimate_negative_denominator=7,
        candidate_model_versions=(("tenant-a", "model-1"),),
        evidence_digest="sha256:" + "b" * 64,
        rules_fpr=0.14,
        model_fpr=0.07,
        rules_recall=0.66,
        model_recall=0.66,
        rules_precision=0.5,
        model_precision=0.8,
        fpr_delta=-0.07,
        recall_delta=0.0,
        precision_delta=0.3,
        non_promotion_reason=None if promotes else "fpr_not_improved",
        promotes=promotes,
    )


# ---------------- candidate_policy ----------------


def test_candidate_policy_maps_manifest_thresholds_and_version() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
    )
    assert policy.model_version == "model-1"
    assert policy.monitor_threshold == pytest.approx(0.40)
    assert policy.review_threshold == pytest.approx(0.60)
    assert policy.hold_threshold == pytest.approx(0.80)
    assert policy.block_threshold == pytest.approx(0.95)
    # Step-up is opt-in: a suggestion is not an authorization.
    assert policy.challenge_threshold is None


def test_candidate_policy_challenge_opt_in() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
        enable_challenge=True,
    )
    assert policy.challenge_threshold == pytest.approx(0.55)


def test_candidate_policy_rejects_non_manifest() -> None:
    with pytest.raises(ActivationRejected):
        candidate_policy(
            object(),  # type: ignore[arg-type]
            configuration_version="cfg",
            policy_version="pol",
            rule_version="rules",
        )


# ---------------- draft_policy_entry ----------------


def test_draft_entry_validates_through_kernel() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
    )
    entry = draft_policy_entry(
        policy,
        tenant_id="tenant-a",
        version=3,
        created_at=datetime(2026, 3, 1, tzinfo=UTC),
        created_by_ref="c" * 64,
    )
    assert entry.config_kind is ConfigKind.DECISION_POLICY
    assert entry.lifecycle is ConfigLifecycle.DRAFT
    assert entry.tenant_id == "tenant-a"
    assert entry.version == 3
    assert '"model_version":"model-1"' in entry.content_json


def test_draft_rejects_non_policy() -> None:
    with pytest.raises(ActivationRejected):
        draft_policy_entry(
            object(),  # type: ignore[arg-type]
            tenant_id="tenant-a",
            version=1,
            created_at=datetime(2026, 3, 1, tzinfo=UTC),
            created_by_ref="c" * 64,
        )


# ---------------- activation_evidence ----------------


def test_evidence_binds_manifest_evaluation_policy() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
    )
    evidence = activation_evidence(manifest(), evaluation(), policy)
    assert evidence.promotes is True
    assert evidence.model_version == "model-1"
    assert evidence.cohort_digest == manifest().cohort_digest
    assert evidence.evaluation_digest == evaluation().evidence_digest
    assert len(evidence.evidence_digest) == 64
    # Stable digest — same inputs, same bundle.
    assert activation_evidence(manifest(), evaluation(), policy).evidence_digest == (
        evidence.evidence_digest
    )


def test_evidence_refuses_non_promoting_candidate() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
    )
    with pytest.raises(ActivationRejected, match="non-promoting"):
        activation_evidence(manifest(), evaluation(promotes=False), policy)


def test_evidence_refuses_version_mismatch() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
    )
    mismatched = policy.model_copy(update={"model_version": "model-2"})
    with pytest.raises(ActivationRejected, match="model_version"):
        activation_evidence(manifest(), evaluation(), mismatched)


def test_evidence_refuses_wrong_types() -> None:
    policy = candidate_policy(
        manifest(),
        configuration_version="cfg-v2",
        policy_version="policy-v2",
        rule_version="rules-v2",
    )
    with pytest.raises(ActivationRejected):
        activation_evidence(object(), evaluation(), policy)  # type: ignore[arg-type]
    with pytest.raises(ActivationRejected):
        activation_evidence(manifest(), object(), policy)  # type: ignore[arg-type]
    with pytest.raises(ActivationRejected):
        activation_evidence(manifest(), evaluation(), object())  # type: ignore[arg-type]
