"""Versioned model manifest binding an artifact to its training evidence.

The manifest is the audit anchor for a trained scorer: it records the
feature schema, the cohort digest and label cutoff the model was trained
on, the calibration map, and the operating thresholds a tenant policy
should carry. Loading a manifest re-validates every field, so a tampered
or inconsistent artifact fails closed before any score is produced.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from gasha.domain.models import RiskScore

MANIFEST_SCHEMA = "gasha-model-manifest-v1"
MANIFEST_FILENAME = "manifest.json"
MODEL_FILENAME = "model.json"

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class OperatingThresholds(BaseModel):
    """Suggested ``DecisionPolicy`` thresholds derived at training time."""

    monitor_threshold: RiskScore
    review_threshold: RiskScore
    hold_threshold: RiskScore
    block_threshold: RiskScore

    @model_validator(mode="after")
    def validate_threshold_order(self) -> OperatingThresholds:
        thresholds = (
            self.monitor_threshold,
            self.review_threshold,
            self.hold_threshold,
            self.block_threshold,
        )
        if thresholds != tuple(sorted(thresholds)) or len(set(thresholds)) != len(
            thresholds
        ):
            raise ValueError("operating thresholds must be strictly increasing")
        return self


class ThresholdMetrics(BaseModel):
    """Realized validation metrics at one operating threshold."""

    realized_fpr: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)


class ValidationMetrics(BaseModel):
    """Time-ordered validation-slice metrics for the trained artifact."""

    validation_rows: int = Field(ge=0)
    validation_positives: int = Field(ge=0)
    validation_negatives: int = Field(ge=0)
    auc: float | None = Field(default=None, ge=0.0, le=1.0)
    at_monitor: ThresholdMetrics
    at_review: ThresholdMetrics
    at_hold: ThresholdMetrics
    at_block: ThresholdMetrics


class ModelManifest(BaseModel):
    """Trusted descriptor for a versioned scorer artifact directory."""

    manifest_schema: Literal["gasha-model-manifest-v1"] = "gasha-model-manifest-v1"
    model_version: str
    feature_schema: Literal["gasha-model-features-v1"] = "gasha-model-features-v1"
    xgboost_version: str = Field(min_length=1)
    trained_at: datetime
    label_cutoff: datetime
    cohort_digest: str = Field(min_length=1)
    training_rows: int = Field(ge=0)
    matured_positive: int = Field(ge=0)
    matured_negative: int = Field(ge=0)
    calibration: Literal["isotonic", "none"]
    calibration_knots: tuple[tuple[float, float], ...]
    thresholds: OperatingThresholds
    metrics: ValidationMetrics
    booster_params: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_manifest_integrity(self) -> ModelManifest:
        if _TAG.fullmatch(self.model_version) is None:
            raise ValueError("model_version must be a bounded opaque tag")
        knots = self.calibration_knots
        if self.calibration == "isotonic":
            if len(knots) < 2:
                raise ValueError("isotonic calibration requires at least two knots")
            xs = [point[0] for point in knots]
            ys = [point[1] for point in knots]
            if xs != sorted(xs) or len(set(xs)) != len(xs):
                raise ValueError("calibration knot scores must be strictly increasing")
            if ys != sorted(ys):
                raise ValueError("calibration knot probabilities must be non-decreasing")
            if any(not 0.0 <= y <= 1.0 for y in ys):
                raise ValueError("calibration probabilities must be within [0, 1]")
        elif knots:
            raise ValueError("uncalibrated manifests cannot carry calibration knots")
        return self

    def save(self, artifact_dir: Path) -> Path:
        """Writes the manifest into ``artifact_dir`` and returns its path."""
        if not isinstance(artifact_dir, Path):
            raise TypeError("artifact directory path required")
        path = artifact_dir / MANIFEST_FILENAME
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return path


def load_manifest(artifact_dir: Path) -> ModelManifest:
    """Reads and fully re-validates the manifest in ``artifact_dir``."""
    if not isinstance(artifact_dir, Path):
        raise TypeError("artifact directory path required")
    path = artifact_dir / MANIFEST_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("model manifest is not readable") from exc
    try:
        return ModelManifest.model_validate_json(raw)
    except ValueError as exc:
        raise ValueError("model manifest failed validation") from exc
