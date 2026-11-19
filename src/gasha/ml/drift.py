"""Population and score drift measurement for deployed model governance.

``drift_report`` compares the feature columns a model was trained on with a
later serving cohort using population stability index (PSI) per column plus
the model's own score distribution. Bucket edges come from the reference
cohort's quantiles, so the report measures where the live population moved,
not where arbitrary cutoffs say it is. Everything is offline and versioned —
a drift report is evidence for the retraining decision, never an automatic
retrain trigger.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from math import isfinite, log

from pydantic import BaseModel, Field

from gasha.ml.features import FEATURE_NAMES, NUM_FEATURES

DRIFT_REPORT_SCHEMA = "gasha-drift-report-1"
_EPS = 1e-4
_BUCKETS = 10


class DriftRejected(ValueError):
    """Drift inputs cannot support an honest comparison."""


class DriftStatus(StrEnum):
    STABLE = "stable"
    WARN = "warn"
    BREACH = "breach"


class DriftPolicy(BaseModel):
    """Versioned thresholds governing drift severity."""

    policy_version: str = Field(min_length=1)
    warn_psi: float = Field(default=0.10, gt=0.0)
    breach_psi: float = Field(default=0.25, gt=0.0)
    min_rows: int = Field(default=50, ge=1)


def _status(psi: float, policy: DriftPolicy) -> DriftStatus:
    if psi >= policy.breach_psi:
        return DriftStatus.BREACH
    if psi >= policy.warn_psi:
        return DriftStatus.WARN
    return DriftStatus.STABLE


def _quantile_edges(reference: Sequence[float]) -> list[float]:
    ordered = sorted(reference)
    n = len(ordered)
    edges: list[float] = []
    for index in range(1, _BUCKETS):
        edge = ordered[(index * n) // _BUCKETS]
        if not edges or edge > edges[-1]:
            edges.append(edge)
    return edges


def compute_psi(
    reference: Sequence[float], current: Sequence[float]
) -> float:
    """Population stability index between two 1-D samples.

    Bucket edges are the reference sample's deciles; shares below
    ``_EPS`` are floored so sparse buckets cannot produce infinite PSI.
    """
    ref = [float(v) for v in reference if isfinite(float(v))]
    cur = [float(v) for v in current if isfinite(float(v))]
    if len(ref) < _BUCKETS or not cur:
        raise DriftRejected(
            "drift requires a populated reference and current sample"
        )
    if min(ref) == max(ref):
        return 0.0  # constant reference column carries no distribution signal
    edges = _quantile_edges(ref)
    if not edges:
        return 0.0

    ref_buckets = [0] * (len(edges) + 1)
    cur_buckets = [0] * (len(edges) + 1)
    for value in ref:
        for index, edge in enumerate(edges):
            if value <= edge:
                ref_buckets[index] += 1
                break
        else:
            ref_buckets[-1] += 1
    for value in cur:
        for index, edge in enumerate(edges):
            if value <= edge:
                cur_buckets[index] += 1
                break
        else:
            cur_buckets[-1] += 1

    psi = 0.0
    for ref_count, cur_count in zip(ref_buckets, cur_buckets, strict=True):
        ref_share = max(ref_count / len(ref), _EPS)
        cur_share = max(cur_count / len(cur), _EPS)
        psi += (cur_share - ref_share) * log(cur_share / ref_share)
    return psi


def _digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class FeatureDrift:
    name: str
    psi: float
    status: DriftStatus


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Versioned drift evidence over the model's full feature contract."""

    schema_version: str
    generated_at: datetime
    policy_version: str
    reference_rows: int
    current_rows: int
    reference_digest: str
    current_digest: str
    feature_drift: tuple[FeatureDrift, ...]
    score_drift: FeatureDrift | None
    max_psi: float
    status: DriftStatus
    report_digest: str


def drift_report(
    reference_rows: Sequence[Sequence[float]],
    current_rows: Sequence[Sequence[float]],
    policy: DriftPolicy,
    *,
    reference_scores: Sequence[float] | None = None,
    current_scores: Sequence[float] | None = None,
    generated_at: datetime | None = None,
) -> DriftReport:
    """Builds the drift report for a reference vs current feature cohort.

    Rows must follow the canonical ``FEATURE_NAMES`` column order. Both
    cohorts need ``policy.min_rows`` rows — a thin current cohort cannot
    honestly measure drift. Score drift is reported when both score
    distributions are supplied.
    """
    if type(policy) is not DriftPolicy:
        raise DriftRejected("typed drift policy required")
    if policy.breach_psi <= policy.warn_psi:
        raise DriftRejected("breach threshold must exceed warn threshold")
    at = (
        generated_at.astimezone(UTC)
        if generated_at is not None
        else datetime.now(UTC)
    )
    if len(reference_rows) < policy.min_rows or len(current_rows) < policy.min_rows:
        raise DriftRejected(
            "drift report requires min_rows observations in both cohorts"
        )

    columns: dict[str, tuple[list[float], list[float]]] = {
        name: ([], []) for name in FEATURE_NAMES
    }
    for row in reference_rows:
        if len(row) != NUM_FEATURES:
            raise DriftRejected("reference row violates the feature contract")
        for name, value in zip(FEATURE_NAMES, row, strict=True):
            columns[name][0].append(float(value))
    for row in current_rows:
        if len(row) != NUM_FEATURES:
            raise DriftRejected("current row violates the feature contract")
        for name, value in zip(FEATURE_NAMES, row, strict=True):
            columns[name][1].append(float(value))

    feature_drift = tuple(
        FeatureDrift(
            name=name,
            psi=psi,
            status=_status(psi, policy),
        )
        for name, (ref, cur) in columns.items()
        for psi in [compute_psi(ref, cur)]
    )
    score_drift = None
    if reference_scores is not None and current_scores is not None:
        psi = compute_psi(reference_scores, current_scores)
        score_drift = FeatureDrift("model_score", psi, _status(psi, policy))

    max_psi = max(
        [feature.psi for feature in feature_drift]
        + ([score_drift.psi] if score_drift is not None else [])
    )
    status = _status(max_psi, policy)
    body = {
        "schema": DRIFT_REPORT_SCHEMA,
        "generated_at": at.isoformat(),
        "policy_version": policy.policy_version,
        "reference_rows": len(reference_rows),
        "current_rows": len(current_rows),
        "features": {f.name: f.psi for f in feature_drift},
        "score": score_drift.psi if score_drift is not None else None,
    }
    return DriftReport(
        schema_version=DRIFT_REPORT_SCHEMA,
        generated_at=at,
        policy_version=policy.policy_version,
        reference_rows=len(reference_rows),
        current_rows=len(current_rows),
        reference_digest=_digest([list(r) for r in reference_rows]),
        current_digest=_digest([list(r) for r in current_rows]),
        feature_drift=feature_drift,
        score_drift=score_drift,
        max_psi=max_psi,
        status=status,
        report_digest=_digest(body),
    )
