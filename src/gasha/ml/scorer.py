"""Runtime model scorer and versioned artifact registry.

``XGBoostScorer`` loads a manifest-validated booster artifact and produces
calibrated probabilities through the same feature builder used at training
time. ``xgboost`` itself is imported lazily so the decision path only
requires the optional ``ml`` dependency when a model-backed policy is
actually resolved. Every failure — unreadable artifact, feature-name
drift, non-finite output — raises ``ScoringError`` so callers can fail
closed instead of falling back to an unversioned score.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from math import isfinite
from pathlib import Path
from typing import Any, Protocol

from gasha.domain.models import CanonicalTransaction, IntelligenceSnapshot
from gasha.ml.calibration import IsotonicCalibrator
from gasha.ml.features import FEATURE_NAMES, build_feature_vector, feature_row
from gasha.ml.manifest import MODEL_FILENAME, ModelManifest, load_manifest

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class ScoringError(RuntimeError):
    """A model artifact could not be trusted or produced no usable score."""


class ModelScorer(Protocol):
    """Versioned decision-time scorer contract.

    Implementations produce a calibrated fraud probability in ``[0, 1]``
    for one canonical transaction plus its point-in-time intelligence
    snapshot, and expose per-feature score contributions for reason-code
    generation.
    """

    @property
    def model_version(self) -> str: ...

    def score(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> float: ...

    def contributions(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> Mapping[str, float]: ...


class XGBoostScorer:
    """Calibrated XGBoost scorer bound to one manifest version."""

    def __init__(self, *, manifest: ModelManifest, booster: Any) -> None:
        if type(manifest) is not ModelManifest:
            raise ScoringError("typed model manifest required")
        self._manifest = manifest
        self._booster = booster
        self._calibrator = (
            IsotonicCalibrator(knots=manifest.calibration_knots)
            if manifest.calibration == "isotonic"
            else None
        )

    @property
    def model_version(self) -> str:
        return self._manifest.model_version

    @classmethod
    def load(cls, artifact_dir: Path) -> XGBoostScorer:
        """Loads and validates the booster plus manifest in ``artifact_dir``."""
        if not isinstance(artifact_dir, Path):
            raise ScoringError("artifact directory path required")
        try:
            manifest = load_manifest(artifact_dir)
        except ValueError as exc:
            raise ScoringError("model manifest is not trusted") from exc
        model_path = artifact_dir / MODEL_FILENAME
        try:
            import xgboost as xgb

            booster = xgb.Booster()
            booster.load_model(str(model_path))
        except Exception as exc:
            raise ScoringError("model artifact is not loadable") from exc
        names = booster.feature_names
        if names is None or tuple(names) != FEATURE_NAMES:
            raise ScoringError("model feature schema does not match this build")
        return cls(manifest=manifest, booster=booster)

    def _row(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> Any:
        try:
            vector = build_feature_vector(transaction, intelligence)
        except ValueError as exc:
            raise ScoringError("unscorable decision input") from exc
        try:
            import numpy as np
            import xgboost as xgb

            return xgb.DMatrix(
                np.asarray([feature_row(vector)], dtype=np.float64),
                feature_names=list(FEATURE_NAMES),
            )
        except ScoringError:
            raise
        except Exception as exc:
            raise ScoringError("model input matrix construction failed") from exc

    def score(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> float:
        """Returns the calibrated fraud probability for one decision input."""
        dmatrix = self._row(transaction, intelligence)
        try:
            raw = float(self._booster.predict(dmatrix)[0])
        except Exception as exc:
            raise ScoringError("model prediction failed") from exc
        if not isfinite(raw):
            raise ScoringError("model produced a non-finite score")
        calibrated = (
            self._calibrator.predict(raw) if self._calibrator is not None else raw
        )
        if not 0.0 <= calibrated <= 1.0:
            raise ScoringError("model produced an out-of-range score")
        return calibrated

    def contributions(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> Mapping[str, float]:
        """Returns per-feature SHAP contributions for reason-code mapping."""
        dmatrix = self._row(transaction, intelligence)
        try:
            values = self._booster.predict(dmatrix, pred_contribs=True)[0]
        except Exception as exc:
            raise ScoringError("model contribution computation failed") from exc
        # The final column is the bias term; it is not a feature reason.
        return {
            name: float(values[index])
            for index, name in enumerate(FEATURE_NAMES)
        }


class ArtifactRegistry:
    """Resolves ``model_version`` tags to trusted scorer artifacts.

    The registry root is operator-provisioned; a version tag can only ever
    name a direct child directory because the tag alphabet excludes path
    separators. The manifest inside the directory must declare the same
    version, so a mislabeled directory fails closed. Resolved scorers are
    cached by version: an artifact version is immutable by contract, so a
    cached scorer can never go stale.
    """

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise ScoringError("registry root path required")
        self._root = root
        self._cache: dict[str, XGBoostScorer] = {}

    def resolve(self, model_version: str) -> XGBoostScorer:
        """Loads the scorer bound to ``model_version`` under the registry root."""
        if type(model_version) is not str or _TAG.fullmatch(model_version) is None:
            raise ScoringError("model_version must be a bounded opaque tag")
        cached = self._cache.get(model_version)
        if cached is not None:
            return cached
        scorer = XGBoostScorer.load(self._root / model_version)
        if scorer.model_version != model_version:
            raise ScoringError("artifact manifest does not match requested version")
        self._cache[model_version] = scorer
        return scorer
