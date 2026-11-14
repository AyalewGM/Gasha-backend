"""End-to-end pipeline tests: matured events -> artifact -> scorer -> decision."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

try:
    import xgboost as _xgboost  # noqa: F401
except Exception:  # noqa: BLE001 -- xgboost raises XGBoostError, not ImportError, when libomp is missing
    pytest.skip(
        "ml optional dependency not installed or unusable",
        allow_module_level=True,
    )

from gasha.decision.fused import FusedDecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ml.manifest import load_manifest
from gasha.ml.scorer import ArtifactRegistry, ScoringError, XGBoostScorer
from gasha.ml.train import TrainingParams, TrainingRejected, train_model
from gasha.poc.historical import ConfirmedOutcomeLabel, HistoricalTransactionEvent

AT = datetime(2026, 1, 1, 9, tzinfo=UTC)
CUTOFF = AT + timedelta(days=30)


def event(number: int, *, fraud: bool) -> HistoricalTransactionEvent:
    """Separable synthetic population: fraud rows score high on signals."""
    occurred = AT + timedelta(minutes=number)
    base = 0.75 if fraud else 0.05
    jitter = (number % 7) * 0.01
    snapshot = IntelligenceSnapshot(
        customer_risk=base + jitter,
        transaction_risk=base + jitter,
        velocity_risk=base + jitter,
        device_session_risk=base if fraud else 0.05,
        beneficiary_risk=base,
        relationship_risk=0.05,
        network_risk=base if fraud else 0.10,
        journey_risk=base + jitter,
    )
    return HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id="tenant-a",
            event_id=UUID(int=number + 1),
            occurred_at=occurred,
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal(9000 if fraud else 40),
            currency="ETB",
            sender_customer_id=f"customer-{number % 11}",
            sender_account_id=f"account-{number % 11}",
            beneficiary_id=f"beneficiary-{number % 13}",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="external-bank",
            correlation_id=f"corr-{number}",
        ),
        intelligence=snapshot,
        received_at=occurred + timedelta(seconds=1),
        label=ConfirmedOutcomeLabel(
            is_fraud=fraud,
            label_source="synthetic-analyst",
            confirmed_at=occurred + timedelta(days=5),
        ),
    )


def cohort() -> list[HistoricalTransactionEvent]:
    # Interleaved but time-ordered; 20% fraud prevalence.
    return [event(n, fraud=(n % 5 == 0)) for n in range(120)]


def policy_for(manifest_version: str, tmp_path: Path) -> DecisionPolicy:
    manifest = load_manifest(tmp_path / manifest_version)
    return DecisionPolicy(
        configuration_version="config-1",
        policy_version="policy-1",
        rule_version="rules-1",
        model_version=manifest_version,
        monitor_threshold=manifest.thresholds.monitor_threshold,
        review_threshold=manifest.thresholds.review_threshold,
        hold_threshold=manifest.thresholds.hold_threshold,
        block_threshold=manifest.thresholds.block_threshold,
    )


def test_train_persists_validated_artifact(tmp_path: Path) -> None:
    manifest = train_model(
        cohort(),
        label_cutoff=CUTOFF,
        model_version="model-v1",
        artifact_dir=tmp_path / "model-v1",
        params=TrainingParams(num_boost_round=60, early_stopping_rounds=10),
    )
    assert manifest.model_version == "model-v1"
    assert (tmp_path / "model-v1" / "model.json").exists()
    reloaded = load_manifest(tmp_path / "model-v1")
    assert reloaded.model_version == "model-v1"
    assert reloaded.training_rows == 120
    assert reloaded.matured_positive == 24
    assert reloaded.matured_negative == 96
    assert reloaded.calibration == "isotonic"
    assert reloaded.metrics.auc is not None and reloaded.metrics.auc > 0.9
    thresholds = reloaded.thresholds
    assert (
        thresholds.monitor_threshold
        < thresholds.review_threshold
        < thresholds.hold_threshold
        < thresholds.block_threshold
    )


def test_scorer_ranks_fraud_above_legitimate(tmp_path: Path) -> None:
    train_model(
        cohort(),
        label_cutoff=CUTOFF,
        model_version="model-v1",
        artifact_dir=tmp_path / "model-v1",
        params=TrainingParams(num_boost_round=60, early_stopping_rounds=10),
    )
    scorer = ArtifactRegistry(tmp_path).resolve("model-v1")
    fraud = event(200, fraud=True)
    legit = event(201, fraud=False)
    fraud_score = scorer.score(fraud.transaction, fraud.intelligence)
    legit_score = scorer.score(legit.transaction, legit.intelligence)
    assert 0.0 <= legit_score < fraud_score <= 1.0
    contributions = scorer.contributions(fraud.transaction, fraud.intelligence)
    assert len(contributions) == 17


def test_fused_decision_uses_model_score(tmp_path: Path) -> None:
    train_model(
        cohort(),
        label_cutoff=CUTOFF,
        model_version="model-v1",
        artifact_dir=tmp_path / "model-v1",
        params=TrainingParams(num_boost_round=60, early_stopping_rounds=10),
    )
    scorer = ArtifactRegistry(tmp_path).resolve("model-v1")
    service = FusedDecisionService(policy_for("model-v1", tmp_path), scorer)
    fraud = event(300, fraud=True)
    legit = event(301, fraud=False)
    fraud_decision = service.decide(fraud.transaction, fraud.intelligence)
    legit_decision = service.decide(legit.transaction, legit.intelligence)
    assert fraud_decision.risk_score > legit_decision.risk_score
    assert fraud_decision.action in (
        DecisionAction.REVIEW,
        DecisionAction.HOLD,
        DecisionAction.BLOCK,
    )
    assert legit_decision.action in (DecisionAction.ALLOW, DecisionAction.MONITOR)
    assert fraud_decision.model_version == "model-v1"
    assert any(
        code.startswith("MODEL_") for code in fraud_decision.reason_codes
    )


def test_registry_rejects_untrusted_version_tags(tmp_path: Path) -> None:
    registry = ArtifactRegistry(tmp_path)
    for bad in ("../escape", "a/b", "", "..", "version with spaces"):
        with pytest.raises(ScoringError, match="tag"):
            registry.resolve(bad)


def test_registry_rejects_version_mismatched_artifact(tmp_path: Path) -> None:
    train_model(
        cohort(),
        label_cutoff=CUTOFF,
        model_version="model-real",
        artifact_dir=tmp_path / "model-alias",
        params=TrainingParams(num_boost_round=20, early_stopping_rounds=5),
    )
    with pytest.raises(ScoringError, match="does not match"):
        ArtifactRegistry(tmp_path).resolve("model-alias")


def test_missing_and_unmatured_cohorts_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ScoringError):
        XGBoostScorer.load(tmp_path / "nonexistent")
    unlabeled = [
        item.model_copy(update={"label": None}) for item in cohort()
    ]
    with pytest.raises(TrainingRejected, match="matured"):
        train_model(
            unlabeled,
            label_cutoff=CUTOFF,
            model_version="model-x",
            artifact_dir=tmp_path / "model-x",
        )


def test_artifact_directories_are_not_overwritten(tmp_path: Path) -> None:
    target = tmp_path / "model-v1"
    train_model(
        cohort(),
        label_cutoff=CUTOFF,
        model_version="model-v1",
        artifact_dir=target,
        params=TrainingParams(num_boost_round=20, early_stopping_rounds=5),
    )
    with pytest.raises(TrainingRejected, match="already contains"):
        train_model(
            cohort(),
            label_cutoff=CUTOFF,
            model_version="model-v1",
            artifact_dir=target,
            params=TrainingParams(num_boost_round=20, early_stopping_rounds=5),
        )
