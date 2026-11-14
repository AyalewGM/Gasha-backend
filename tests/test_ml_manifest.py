"""ModelManifest validation tests: every field is re-validated on load."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from gasha.ml.manifest import ModelManifest, OperatingThresholds


def manifest(**changes: object) -> ModelManifest:
    metrics = {
        "validation_rows": 10,
        "validation_positives": 2,
        "validation_negatives": 8,
        "auc": 0.9,
        **{
            name: {
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
            "monitor_threshold": 0.4,
            "review_threshold": 0.6,
            "hold_threshold": 0.8,
            "block_threshold": 0.95,
        },
        "metrics": metrics,
    }
    values.update(changes)
    return ModelManifest(**values)  # type: ignore[arg-type]


def test_valid_manifest_round_trips() -> None:
    assert manifest().model_version == "model-1"


def test_model_version_must_be_an_opaque_tag() -> None:
    with pytest.raises(ValueError, match="tag"):
        manifest(model_version="../escape")
    with pytest.raises(ValueError, match="tag"):
        manifest(model_version="has space")


def test_threshold_order_is_enforced() -> None:
    with pytest.raises(ValueError, match="strictly increasing"):
        OperatingThresholds(
            monitor_threshold=0.7,
            review_threshold=0.6,
            hold_threshold=0.8,
            block_threshold=0.95,
        )


def test_isotonic_knots_must_be_monotone() -> None:
    with pytest.raises(ValueError, match="strictly increasing"):
        manifest(calibration_knots=((0.5, 0.1), (0.4, 0.2), (0.9, 0.9)))
    with pytest.raises(ValueError, match="non-decreasing"):
        manifest(calibration_knots=((0.1, 0.5), (0.4, 0.2), (0.9, 0.9)))
    with pytest.raises(ValueError, match="at least two"):
        manifest(calibration_knots=((0.5, 0.5),))


def test_uncalibrated_manifest_cannot_carry_knots() -> None:
    with pytest.raises(ValueError, match="cannot carry"):
        manifest(calibration="none")


def test_manifest_schema_is_fixed() -> None:
    with pytest.raises(ValueError):
        manifest(manifest_schema="other-schema")
