"""Offline XGBoost training pipeline for the fraud decision scorer.

This module is never imported by the serving path. It consumes matured
historical events, produces a versioned artifact directory
(``model.json`` + ``manifest.json``), and derives operating thresholds at
explicit false-positive-rate targets so the resulting ``DecisionPolicy``
can be reviewed before activation. ``xgboost`` is imported lazily inside
``train_model`` so the module stays importable without the ``ml`` extra.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from gasha.ml.calibration import IsotonicCalibrator
from gasha.ml.dataset import TrainingDataset, build_training_dataset
from gasha.ml.features import FEATURE_NAMES, feature_row
from gasha.ml.manifest import (
    MANIFEST_FILENAME,
    MODEL_FILENAME,
    ModelManifest,
    OperatingThresholds,
    ThresholdMetrics,
    ValidationMetrics,
)
from gasha.ml.metrics import auc, confusion_at_threshold, threshold_for_fpr
from gasha.poc.historical import HistoricalTransactionEvent


class TrainingRejected(ValueError):
    """The cohort or parameters cannot yield a trustworthy artifact."""


@dataclass(frozen=True, slots=True)
class TrainingParams:
    """Bounded training hyperparameters and split/operating-point targets."""

    train_fraction: float = 0.60
    calibration_fraction: float = 0.20
    target_fpr: float = 0.02
    max_depth: int = 4
    eta: float = 0.05
    num_boost_round: int = 400
    early_stopping_rounds: int = 50
    min_child_weight: float = 1.0
    subsample: float = 0.9
    colsample_bytree: float = 0.9
    seed: int = 7


def _split(dataset: TrainingDataset, params: TrainingParams) -> tuple[
    tuple[list[list[float]], list[int]],
    tuple[list[list[float]], list[int]],
    tuple[list[list[float]], list[int]],
]:
    """Chronological train/calibration/validation split; never shuffled."""
    rows = dataset.rows
    count = len(rows)
    train_end = int(count * params.train_fraction)
    cal_end = train_end + int(count * params.calibration_fraction)
    if train_end < 2 or cal_end <= train_end or count - cal_end < 1:
        raise TrainingRejected("cohort too small for a chronological three-way split")
    slices = (rows[:train_end], rows[train_end:cal_end], rows[cal_end:])
    out: list[tuple[list[list[float]], list[int]]] = []
    for part in slices:
        out.append(
            (
                [list(feature_row(row.features)) for row in part],
                [1 if row.is_fraud else 0 for row in part],
            )
        )
    return out[0], out[1], out[2]


def _operating_thresholds(
    scores: Sequence[float],
    labels: Sequence[int],
    target_fpr: float,
) -> tuple[OperatingThresholds, dict[str, ThresholdMetrics]]:
    """Chooses the four policy thresholds at stepped FPR targets.

    ``review`` is the primary operating point at ``target_fpr``; ``monitor``
    relaxes it 4x, ``hold`` tightens it 4x and ``block`` 16x. When the
    negative population cannot realize distinct points, thresholds fall
    back to deterministic spacing around the review point — the realized
    FPR of each final threshold is recorded honestly either way.
    """
    y = [bool(label) for label in labels]
    review, _ = threshold_for_fpr(scores, y, target_fpr)
    monitor, _ = threshold_for_fpr(scores, y, min(1.0, target_fpr * 4.0))
    hold, _ = threshold_for_fpr(scores, y, target_fpr / 4.0)
    block, _ = threshold_for_fpr(scores, y, target_fpr / 16.0)
    if not 0.0 < review < 1.0:
        raise TrainingRejected("degenerate review operating point")
    if monitor >= review:
        monitor = review * 0.5
    if hold <= review or block <= hold:
        # The negative population could not realize tighter points.
        hold = review + (1.0 - review) / 3.0
        block = review + 2.0 * (1.0 - review) / 3.0
    if monitor >= review or review >= hold or hold >= block:
        raise TrainingRejected("operating thresholds are not realizable")
    thresholds = OperatingThresholds(
        monitor_threshold=min(1.0, monitor),
        review_threshold=min(1.0, review),
        hold_threshold=min(1.0, hold),
        block_threshold=min(1.0, block),
    )
    metrics: dict[str, ThresholdMetrics] = {}
    for name, threshold in (
        ("at_monitor", thresholds.monitor_threshold),
        ("at_review", thresholds.review_threshold),
        ("at_hold", thresholds.hold_threshold),
        ("at_block", thresholds.block_threshold),
    ):
        confusion = confusion_at_threshold(scores, y, threshold)
        metrics[name] = ThresholdMetrics(
            realized_fpr=confusion.false_positive_rate,
            precision=confusion.precision,
            recall=confusion.recall,
            f1=confusion.f1,
        )
    return thresholds, metrics


def train_model(
    events: Sequence[HistoricalTransactionEvent],
    *,
    label_cutoff: datetime,
    model_version: str,
    artifact_dir: Path,
    params: TrainingParams | None = None,
    tenant_id: str | None = None,
) -> ModelManifest:
    """Trains, calibrates and persists a versioned scorer artifact.

    The matured cohort is split chronologically: the earliest slice trains
    the booster, the middle slice fits isotonic calibration, and the latest
    slice selects thresholds and reports metrics — so no label or score
    used for evaluation ever influenced the model. The artifact directory
    must not already contain a manifest; overwriting a versioned artifact
    would break the lineage the manifest exists to guarantee.
    """
    if params is None:
        params = TrainingParams()
    dataset = build_training_dataset(
        events, label_cutoff=label_cutoff, tenant_id=tenant_id
    )
    if dataset.matured_positive == 0 or dataset.matured_negative == 0:
        raise TrainingRejected("cohort has no matured positive or negative labels")
    (train_x, train_y), (cal_x, cal_y), (valid_x, valid_y) = _split(dataset, params)
    if 0 in (sum(train_y), len(train_y) - sum(train_y)):
        raise TrainingRejected("training slice must contain both classes")
    if 0 in (sum(valid_y), len(valid_y) - sum(valid_y)):
        raise TrainingRejected("validation slice must contain both classes")

    try:
        import numpy as np
        import xgboost as xgb
    except ImportError as exc:
        raise TrainingRejected("the 'ml' optional dependency is not installed") from exc

    names = list(FEATURE_NAMES)
    dtrain = xgb.DMatrix(
        np.asarray(train_x, dtype=np.float64), label=train_y, feature_names=names
    )
    dcal = xgb.DMatrix(
        np.asarray(cal_x, dtype=np.float64), label=cal_y, feature_names=names
    )
    dvalid = xgb.DMatrix(
        np.asarray(valid_x, dtype=np.float64), label=valid_y, feature_names=names
    )
    negatives = len(train_y) - sum(train_y)
    booster_params: dict[str, str | int | float | bool] = {
        "objective": "binary:logistic",
        "eval_metric": "auc",
        "max_depth": params.max_depth,
        "eta": params.eta,
        "min_child_weight": params.min_child_weight,
        "subsample": params.subsample,
        "colsample_bytree": params.colsample_bytree,
        "scale_pos_weight": negatives / max(1, sum(train_y)),
        "seed": params.seed,
    }
    booster = xgb.train(
        booster_params,
        dtrain,
        num_boost_round=params.num_boost_round,
        evals=[(dvalid, "validation")],
        early_stopping_rounds=params.early_stopping_rounds,
        verbose_eval=False,
    )

    calibrator = IsotonicCalibrator.fit(
        [float(value) for value in booster.predict(dcal)],
        [bool(label) for label in cal_y],
    )
    valid_scores = calibrator.predict_many(
        [float(value) for value in booster.predict(dvalid)]
    )
    thresholds, per_threshold = _operating_thresholds(
        valid_scores, valid_y, params.target_fpr
    )

    if not isinstance(artifact_dir, Path):
        raise TrainingRejected("artifact directory path required")
    if (artifact_dir / MODEL_FILENAME).exists() or (
        artifact_dir / MANIFEST_FILENAME
    ).exists():
        raise TrainingRejected("artifact directory already contains a model")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(artifact_dir / MODEL_FILENAME))

    manifest = ModelManifest(
        model_version=model_version,
        xgboost_version=xgb.__version__,
        trained_at=datetime.now(UTC),
        label_cutoff=dataset.label_cutoff,
        cohort_digest=dataset.cohort_digest,
        training_rows=len(dataset.rows),
        matured_positive=dataset.matured_positive,
        matured_negative=dataset.matured_negative,
        calibration="isotonic",
        calibration_knots=calibrator.knots,
        thresholds=thresholds,
        metrics=ValidationMetrics(
            validation_rows=len(valid_y),
            validation_positives=sum(valid_y),
            validation_negatives=len(valid_y) - sum(valid_y),
            auc=auc(valid_scores, [bool(label) for label in valid_y]),
            at_monitor=per_threshold["at_monitor"],
            at_review=per_threshold["at_review"],
            at_hold=per_threshold["at_hold"],
            at_block=per_threshold["at_block"],
        ),
        booster_params=booster_params,
    )
    manifest.save(artifact_dir)
    return manifest


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gasha-train-model",
        description="Train a calibrated XGBoost fraud scorer from matured labels.",
    )
    parser.add_argument(
        "--events",
        required=True,
        type=Path,
        help="JSONL file of HistoricalTransactionEvent records",
    )
    parser.add_argument("--label-cutoff", required=True, type=datetime.fromisoformat)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--target-fpr", type=float, default=0.02)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point: JSONL matured events in, versioned artifact out."""
    args = _parse_args(argv)
    events = [
        HistoricalTransactionEvent.model_validate_json(line)
        for line in args.events.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    manifest = train_model(
        events,
        label_cutoff=args.label_cutoff,
        model_version=args.model_version,
        artifact_dir=args.artifact_dir,
        params=TrainingParams(target_fpr=args.target_fpr),
        tenant_id=args.tenant_id,
    )
    print(manifest.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
