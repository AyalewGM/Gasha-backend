from datetime import datetime
from pathlib import Path

import pytest

try:
    import xgboost as _xgboost  # noqa: F401
except Exception:  # noqa: BLE001 -- optional runtime can fail to load when libomp is absent
    pytest.skip("ML runtime unavailable", allow_module_level=True)

from gasha.poc.synthetic_ml_challenger import compare_synthetic_challenger


def test_trained_artifact_and_rules_compare_on_one_matured_holdout(tmp_path: Path) -> None:
    report = compare_synthetic_challenger(artifact_root=tmp_path, alert_budget=12)
    training = report["training"]
    holdout = report["holdout"]
    model = report["model"]
    variants = report["benchmarks"]
    assert isinstance(training, dict) and isinstance(holdout, dict)
    assert isinstance(model, dict) and isinstance(variants, dict)
    assert training["rows"] == 120 and holdout["rows"] == 40
    assert datetime.fromisoformat(training["last_event_at"]) < datetime.fromisoformat(
        training["label_cutoff"]
    ) < datetime.fromisoformat(holdout["first_event_at"])
    assert holdout["matured_labels"] == 38
    assert holdout["late_labels"] == holdout["missing_labels"] == 1
    assert (tmp_path / model["version"] / "model.json").is_file()
    assert len(model["booster_sha256"]) == len(model["scoring_manifest_sha256"]) == 64
    assert report["bank_data_verified"] is report["live_serving_enabled"] is False
    assert report["netguardians_outputs_compared"] is report["enforcement_activated"] is False
    for result in variants.values():
        assert result["alert_count"] == 12
        assert sum(result["confusion_counts"].values()) == 40
        assert result["confusion_counts"]["unlabeled"] == 2
        assert result["false_negative_rate"]["denominator"] == 15
    assert variants["rules_champion"]["auc"] < variants["xgboost_challenger"]["auc"]
    assert variants["xgboost_challenger"]["alerts_with_unavailable_label"] == 1


def test_budget_validation_precedes_artifact_creation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="budget"):
        compare_synthetic_challenger(artifact_root=tmp_path, alert_budget=41)
    assert list(tmp_path.iterdir()) == []
