"""Deterministic isolation-forest anomaly detector tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from gasha.ml.anomaly import (
    ANOMALY_ARTIFACT_SCHEMA,
    AnomalyArtifact,
    AnomalyRejected,
    AnomalyScorer,
    train_anomaly_detector,
)
from gasha.ml.features import NUM_FEATURES


def _normal_rows(n: int) -> list[list[float]]:
    return [
        [0.0] * (NUM_FEATURES - 1) + [(index % 25) / 100.0]
        for index in range(n)
    ]


def test_artifact_serialization_round_trip() -> None:
    artifact = train_anomaly_detector(_normal_rows(150), anomaly_version="v1")
    restored = AnomalyArtifact.model_validate_json(
        artifact.model_dump_json()
    )
    assert restored == artifact
    assert restored.schema_version == ANOMALY_ARTIFACT_SCHEMA


def test_training_is_deterministic() -> None:
    rows = _normal_rows(150)
    at = datetime(2026, 1, 1, tzinfo=UTC)
    a = train_anomaly_detector(rows, anomaly_version="v1", seed=7, trained_at=at)
    b = train_anomaly_detector(rows, anomaly_version="v1", seed=7, trained_at=at)
    assert a.model_dump() == b.model_dump()


def test_outlier_scores_above_normal_population() -> None:
    scorer = AnomalyScorer(
        train_anomaly_detector(_normal_rows(200), anomaly_version="v1")
    )
    normal = [
        scorer.score_row([0.0] * (NUM_FEATURES - 1) + [0.1])
        for _ in range(10)
    ]
    outlier = scorer.score_row([9.9] * NUM_FEATURES)
    assert outlier > max(normal)


def test_inlier_scores_reasonable() -> None:
    scorer = AnomalyScorer(
        train_anomaly_detector(_normal_rows(200), anomaly_version="v1")
    )
    score = scorer.score_row([0.0] * (NUM_FEATURES - 1) + [0.12])
    assert 0.0 <= score < 0.6


def test_malformed_training_rows_rejected() -> None:
    with pytest.raises(AnomalyRejected, match="column"):
        train_anomaly_detector([[0.1] * 3], anomaly_version="v1")
    with pytest.raises(AnomalyRejected, match="non-finite"):
        train_anomaly_detector(
            [[float("nan")] * NUM_FEATURES], anomaly_version="v1"
        )
    with pytest.raises(AnomalyRejected, match="empty"):
        train_anomaly_detector([], anomaly_version="v1")
    with pytest.raises(AnomalyRejected, match="anomaly_version"):
        train_anomaly_detector(_normal_rows(10), anomaly_version="")


def test_scoring_contract_violations_rejected() -> None:
    scorer = AnomalyScorer(
        train_anomaly_detector(_normal_rows(50), anomaly_version="v1")
    )
    with pytest.raises(AnomalyRejected, match="feature values"):
        scorer.score_row([0.1] * 3)
    with pytest.raises(AnomalyRejected, match="non-finite"):
        scorer.score_row([float("inf")] * NUM_FEATURES)


def test_artifact_integrity_validated() -> None:
    artifact = train_anomaly_detector(_normal_rows(50), anomaly_version="v1")
    tampered = artifact.model_dump()
    tampered["n_trees"] = 1
    with pytest.raises(ValidationError, match="n_trees"):
        AnomalyArtifact.model_validate(tampered)
    bad_schema = artifact.model_dump()
    bad_schema["schema_version"] = "other"
    with pytest.raises(ValidationError, match="schema"):
        AnomalyArtifact.model_validate(bad_schema)
