"""Deterministic isolation-forest anomaly detection for novel fraud.

Supervised models can only find fraud that resembles the confirmed labels
they trained on. ``train_anomaly_detector`` builds an isolation forest over
the canonical feature columns — an unsupervised novelty scorer that isolates
rare transactions in few random splits regardless of label availability —
and serializes it into a versioned ``AnomalyArtifact``. Scores are
deterministic given a fixed seed, so replay and shadow comparisons are
reproducible; the artifact digests bind the training cohort like the
supervised ``ModelManifest`` does.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from math import isfinite, log

from pydantic import BaseModel, Field, model_validator

from gasha.ml.features import NUM_FEATURES

ANOMALY_ARTIFACT_SCHEMA = "gasha-anomaly-artifact-1"
_DEFAULT_TREES = 64
_DEFAULT_SAMPLE = 128
_MAX_DEPTH = 16


class AnomalyRejected(ValueError):
    """Anomaly training or scoring inputs are invalid."""


def _harmonic(n: int) -> float:
    if n <= 0:
        return 0.0
    return log(n) + 0.5772156649


def _expected_path_length(n: int) -> float:
    """Average path length of unsuccessful BST search — c(n)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * _harmonic(n - 1) - 2.0 * (n - 1) / n


class _Node(BaseModel):
    feature: int | None = None
    threshold: float | None = None
    left: _Node | None = None
    right: _Node | None = None
    size: int


class AnomalyArtifact(BaseModel):
    """Versioned, serializable isolation forest artifact."""

    schema_version: str = ANOMALY_ARTIFACT_SCHEMA
    anomaly_version: str = Field(min_length=1)
    trained_at: datetime
    n_trees: int = Field(gt=0)
    sample_size: int = Field(gt=1)
    seed: int
    trained_rows: int = Field(gt=0)
    cohort_digest: str = Field(min_length=64, max_length=64)
    expected_path: float = Field(gt=0.0)
    trees: list[_Node] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_contract(self) -> AnomalyArtifact:
        if self.schema_version != ANOMALY_ARTIFACT_SCHEMA:
            raise AnomalyRejected(
                "anomaly artifact must use schema "
                f"{ANOMALY_ARTIFACT_SCHEMA!r}"
            )
        if self.trained_at.tzinfo is None:
            raise AnomalyRejected("trained_at must be timezone-aware")
        if len(self.trees) != self.n_trees:
            raise AnomalyRejected("tree count must match n_trees")
        return self


def _build_tree(
    rng: random.Random,
    rows: list[list[float]],
    depth: int,
) -> _Node:
    if depth >= _MAX_DEPTH or len(rows) <= 1:
        return _Node(size=len(rows))
    columns = [
        index
        for index in range(NUM_FEATURES)
        if min(row[index] for row in rows) < max(row[index] for row in rows)
    ]
    if not columns:
        return _Node(size=len(rows))
    feature = rng.choice(columns)
    low = min(row[feature] for row in rows)
    high = max(row[feature] for row in rows)
    threshold = rng.uniform(low, high)
    left = [row for row in rows if row[feature] < threshold]
    right = [row for row in rows if row[feature] >= threshold]
    return _Node(
        feature=feature,
        threshold=threshold,
        left=_build_tree(rng, left, depth + 1),
        right=_build_tree(rng, right, depth + 1),
        size=len(rows),
    )


def _path_length(node: _Node, row: Sequence[float], depth: int) -> float:
    if node.feature is None or node.threshold is None:
        return depth + _expected_path_length(node.size)
    child = node.left if row[node.feature] < node.threshold else node.right
    if child is None:
        return depth + 1.0
    return _path_length(child, row, depth + 1)


def _digest_rows(rows: Sequence[Sequence[float]]) -> str:
    return hashlib.sha256(
        json.dumps(
            [list(row) for row in rows],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _validate_rows(
    rows: Sequence[Sequence[float]], *, label: str
) -> list[list[float]]:
    validated: list[list[float]] = []
    for row in rows:
        if len(row) != NUM_FEATURES:
            raise AnomalyRejected(
                f"{label} row violates the {NUM_FEATURES}-column contract"
            )
        floats = [float(v) for v in row]
        if not all(isfinite(v) for v in floats):
            raise AnomalyRejected(f"{label} row contains non-finite values")
        validated.append(floats)
    if not validated:
        raise AnomalyRejected(f"{label} cohort cannot be empty")
    return validated


def train_anomaly_detector(
    rows: Sequence[Sequence[float]],
    *,
    anomaly_version: str,
    seed: int = 0,
    n_trees: int = _DEFAULT_TREES,
    sample_size: int = _DEFAULT_SAMPLE,
    trained_at: datetime | None = None,
) -> AnomalyArtifact:
    """Trains a deterministic isolation forest over feature rows.

    Rows follow the canonical ``FEATURE_NAMES`` order. The training
    cohort should be representative traffic — mostly legitimate — since
    the detector learns what "normal" looks like, not what fraud does.
    """
    if not anomaly_version:
        raise AnomalyRejected("anomaly_version is required")
    validated = _validate_rows(rows, label="training")
    rng = random.Random(seed)
    subsample = min(sample_size, len(validated))
    trees = [
        _build_tree(rng, rng.sample(validated, subsample), 0)
        for _ in range(n_trees)
    ]
    return AnomalyArtifact(
        anomaly_version=anomaly_version,
        trained_at=(
            trained_at.astimezone(UTC)
            if trained_at is not None
            else datetime.now(UTC)
        ),
        n_trees=n_trees,
        sample_size=subsample,
        seed=seed,
        trained_rows=len(validated),
        cohort_digest=_digest_rows(validated),
        expected_path=_expected_path_length(subsample),
        trees=trees,
    )


@dataclass(frozen=True, slots=True)
class AnomalyScorer:
    """Scores transactions against a validated anomaly artifact.

    Scores live in ``[0, 1]`` — values near 1 isolate quickly, meaning
    the transaction looks unlike the training population. The scorer
    never raises on malformed input at the row level; contract
    violations are rejected so callers cannot silently treat a garbage
    score as normal.
    """

    artifact: AnomalyArtifact

    def score_row(self, row: Sequence[float]) -> float:
        if len(row) != NUM_FEATURES:
            raise AnomalyRejected(
                f"scoring requires {NUM_FEATURES} feature values"
            )
        floats = [float(v) for v in row]
        if not all(isfinite(v) for v in floats):
            raise AnomalyRejected("scoring row contains non-finite values")
        paths = [
            _path_length(tree, floats, 0) for tree in self.artifact.trees
        ]
        mean_path = sum(paths) / len(paths)
        return float(2.0 ** (-mean_path / self.artifact.expected_path))
