"""Drift measurement and report tests."""

from __future__ import annotations

import pytest

from gasha.ml.drift import (
    DriftPolicy,
    DriftRejected,
    DriftStatus,
    compute_psi,
    drift_report,
)
from gasha.ml.features import NUM_FEATURES

POLICY = DriftPolicy(policy_version="drift-v1")


def _rows(n: int, base: float) -> list[list[float]]:
    return [
        [base + (index % 10) * 0.01] * NUM_FEATURES for index in range(n)
    ]


def test_identical_populations_have_near_zero_psi() -> None:
    ref = [0.1 * i for i in range(10)]
    assert compute_psi(ref, ref) == pytest.approx(0.0, abs=1e-9)


def test_shifted_population_drifts() -> None:
    ref = [0.01 * i for i in range(100)]
    cur = [0.5 + 0.01 * i for i in range(100)]
    assert compute_psi(ref, cur) > 0.25


def test_sparse_or_empty_samples_rejected() -> None:
    with pytest.raises(DriftRejected):
        compute_psi([0.5] * 5, [0.6] * 50)
    with pytest.raises(DriftRejected):
        compute_psi([0.5] * 50, [])


def test_constant_reference_returns_zero() -> None:
    assert compute_psi([0.5] * 100, [0.5 + 0.01 * i for i in range(50)]) == 0.0


def test_stable_report() -> None:
    report = drift_report(_rows(60, 0.1), _rows(60, 0.1), POLICY)
    assert report.status is DriftStatus.STABLE
    assert len(report.feature_drift) == NUM_FEATURES
    assert report.score_drift is None
    assert len(report.report_digest) == 64
    assert report.reference_rows == 60 and report.current_rows == 60


def test_breach_report_marks_status() -> None:
    ref = [[0.0] * (NUM_FEATURES - 1) + [i / 100] for i in range(60)]
    cur = [[0.0] * (NUM_FEATURES - 1) + [0.8 + i / 500] for i in range(60)]
    report = drift_report(ref, cur, POLICY)
    assert report.status is DriftStatus.BREACH
    assert report.max_psi > POLICY.breach_psi
    breached = [f.name for f in report.feature_drift if f.status is DriftStatus.BREACH]
    assert breached


def test_score_drift_included_when_supplied() -> None:
    report = drift_report(
        _rows(60, 0.2),
        _rows(60, 0.2),
        POLICY,
        reference_scores=[i / 100 for i in range(60)],
        current_scores=[0.7 + i / 300 for i in range(60)],
    )
    assert report.score_drift is not None
    assert report.score_drift.name == "model_score"


def test_min_rows_enforced() -> None:
    with pytest.raises(DriftRejected, match="min_rows"):
        drift_report(_rows(10, 0.1), _rows(60, 0.1), POLICY)


def test_row_contract_violation_rejected() -> None:
    with pytest.raises(DriftRejected, match="feature contract"):
        drift_report(_rows(60, 0.1)[:59] + [[0.1] * 3], _rows(60, 0.1), POLICY)


def test_bad_policy_rejected() -> None:
    with pytest.raises(DriftRejected):
        drift_report(_rows(60, 0.1), _rows(60, 0.1), object())  # type: ignore[arg-type]
    with pytest.raises(DriftRejected, match="breach"):
        drift_report(
            _rows(60, 0.1),
            _rows(60, 0.1),
            DriftPolicy(policy_version="p", warn_psi=0.3, breach_psi=0.2),
        )
