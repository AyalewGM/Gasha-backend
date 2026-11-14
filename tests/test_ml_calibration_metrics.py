"""Pure calibration and evaluation-metric tests; no booster required."""

from __future__ import annotations

import pytest

from gasha.ml.calibration import IsotonicCalibrator
from gasha.ml.metrics import auc, confusion_at_threshold, threshold_for_fpr


def test_isotonic_fit_is_monotone_on_noisy_scores() -> None:
    scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    labels = [False, False, True, False, True, False, True, True, True]
    calibrator = IsotonicCalibrator.fit(scores, labels)
    predicted = calibrator.predict_many(scores)
    assert list(predicted) == sorted(predicted)
    assert predicted[-1] > predicted[0]


def test_isotonic_perfect_separation_calibrates_to_extremes() -> None:
    calibrator = IsotonicCalibrator.fit(
        [0.1, 0.2, 0.8, 0.9], [False, False, True, True]
    )
    assert calibrator.predict(0.1) == pytest.approx(0.0)
    assert calibrator.predict(0.9) == pytest.approx(1.0)
    assert calibrator.predict(-5.0) == pytest.approx(0.0)
    assert calibrator.predict(5.0) == pytest.approx(1.0)


def test_isotonic_rejects_degenerate_input() -> None:
    with pytest.raises(ValueError, match="length mismatch"):
        IsotonicCalibrator.fit([0.1], [])
    with pytest.raises(ValueError, match="empty"):
        IsotonicCalibrator.fit([], [])
    with pytest.raises(ValueError, match="finite"):
        IsotonicCalibrator.fit([float("nan")], [True])
    calibrator = IsotonicCalibrator.fit([0.5], [True])
    with pytest.raises(ValueError, match="finite"):
        calibrator.predict(float("inf"))


def test_confusion_counts_and_rates() -> None:
    counts = confusion_at_threshold(
        [0.9, 0.8, 0.4, 0.1], [True, False, True, False], 0.5
    )
    assert (counts.true_positives, counts.false_positives) == (1, 1)
    assert (counts.true_negatives, counts.false_negatives) == (1, 1)
    assert counts.precision == pytest.approx(0.5)
    assert counts.recall == pytest.approx(0.5)
    assert counts.false_positive_rate == pytest.approx(0.5)
    with pytest.raises(ValueError, match="\\[0, 1\\]"):
        confusion_at_threshold([0.5], [True], 1.5)


def test_auc_rank_ordering() -> None:
    perfect = auc([0.9, 0.8, 0.2, 0.1], [True, True, False, False])
    reversed_ = auc([0.1, 0.2, 0.8, 0.9], [True, True, False, False])
    assert perfect == pytest.approx(1.0)
    assert reversed_ == pytest.approx(0.0)
    assert auc([0.5, 0.5], [True, False]) == pytest.approx(0.5)
    assert auc([0.5], [True]) is None


def test_threshold_for_fpr_hits_target_and_reports_realized() -> None:
    scores = [0.1, 0.2, 0.3, 0.95]
    labels = [False, False, False, True]
    threshold, realized = threshold_for_fpr(scores, labels, 1.0 / 3.0)
    assert threshold == pytest.approx(0.2 + 1e-9)
    assert realized == pytest.approx(1.0 / 3.0)

    threshold, realized = threshold_for_fpr(scores, labels, 0.0)
    assert threshold > 0.3
    assert realized == 0.0


def test_threshold_for_fpr_rejects_missing_negatives() -> None:
    with pytest.raises(ValueError, match="negative"):
        threshold_for_fpr([0.9], [True], 0.05)
    with pytest.raises(ValueError, match="\\[0, 1\\]"):
        threshold_for_fpr([0.1], [False], -0.1)
