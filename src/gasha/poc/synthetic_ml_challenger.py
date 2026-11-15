"""Compare a trained challenger with Gasha rules on later synthetic transactions."""
from __future__ import annotations

from argparse import ArgumentParser
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from json import dumps
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ml.manifest import MODEL_FILENAME
from gasha.ml.metrics import auc
from gasha.ml.scorer import ArtifactRegistry
from gasha.ml.train import TrainingParams, train_model
from gasha.poc.historical import ConfirmedOutcomeLabel, HistoricalTransactionEvent
from gasha.poc.synthetic_rules_comparison import measure_same_budget

_TENANT = "synthetic-ml-challenger"
_TRAIN_START = datetime(2026, 1, 10, 9, tzinfo=UTC)
_TRAIN_CUTOFF = _TRAIN_START + timedelta(days=4)
_HOLDOUT_START = _TRAIN_START + timedelta(days=7)
_HOLDOUT_CUTOFF = _HOLDOUT_START + timedelta(days=4)
_MODEL_VERSION = "synthetic-xgboost-challenger-v1"
_HOLDOUT_SIZE = 40


def _digest(value: object) -> str:
    encoded = dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return sha256(encoded).hexdigest()


def _cohort(*, start: datetime, count: int, offset: int) -> tuple[HistoricalTransactionEvent, ...]:
    rows = []
    for index in range(count):
        identity = offset + index + 1
        occurred = start + timedelta(minutes=index)
        scenario = index % 5
        # Legitimate high-velocity activity and suspicious device/network behavior
        # overlap in rules score. No labels or future features are sent to scorers.
        jitter = ((identity * 17) % 11) / 100
        velocity, device, network = (
            (0.30, 0.80, 0.71), (0.50, 0.69, 0.78), (0.88, 0.13, 0.08),
            (0.35, 0.72, 0.12), (0.30, 0.21, 0.10),
        )[scenario]
        label = ConfirmedOutcomeLabel(
            is_fraud=scenario < 2,
            label_source="synthetic-investigator",
            confirmed_at=occurred + timedelta(days=7 if offset and index == 0 else 2),
        )
        rows.append(HistoricalTransactionEvent(
            transaction=CanonicalTransaction(
                tenant_id=_TENANT, event_id=UUID(int=identity), occurred_at=occurred,
                channel="mobile", transaction_type="transfer", amount=Decimal(100),
                currency="ETB", sender_customer_id=f"synthetic-customer-{identity}",
                sender_account_id=f"synthetic-account-{identity}",
                beneficiary_id=f"synthetic-beneficiary-{identity}",
                beneficiary_type=BeneficiaryType.INTERNAL, correlation_id=f"synthetic-{identity}",
            ),
            intelligence=IntelligenceSnapshot(
                velocity_risk=velocity + jitter, device_session_risk=device + jitter,
                network_risk=network + jitter,
            ),
            received_at=occurred,
            signal_policy_versions=("synthetic-velocity-device-network-v1",),
            label=None if offset and index == 3 else label,
        ))
    return tuple(rows)


def compare_synthetic_challenger(
    *, artifact_root: Path, alert_budget: int = 12,
) -> dict[str, object]:
    """Train, reload and evaluate an offline artifact on a withheld cohort."""
    if type(alert_budget) is not int or not 0 <= alert_budget <= _HOLDOUT_SIZE:
        raise ValueError(f"alert budget must be an integer from 0 to {_HOLDOUT_SIZE}")
    train = _cohort(start=_TRAIN_START, count=120, offset=0)
    holdout = _cohort(start=_HOLDOUT_START, count=_HOLDOUT_SIZE, offset=120)
    artifact_path = artifact_root / _MODEL_VERSION
    manifest = train_model(
        train, label_cutoff=_TRAIN_CUTOFF, model_version=_MODEL_VERSION, artifact_dir=artifact_path,
        tenant_id=_TENANT, params=TrainingParams(num_boost_round=60, early_stopping_rounds=10),
    )
    challenger = ArtifactRegistry(artifact_root).resolve(_MODEL_VERSION)
    policy = DecisionPolicy(
        configuration_version="synthetic-ml-challenger-config-v1",
        policy_version="synthetic-ml-challenger-rules-v1",
        rule_version="gasha-deterministic-max-signal-v1",
    )
    champion = DecisionService(policy)
    variants: dict[str, list[tuple[HistoricalTransactionEvent, float]]] = {"rules_champion": [], "xgboost_challenger": []}
    late = missing = 0
    for event in holdout:
        transaction, features = event.transaction, event.intelligence
        if event.label is None or event.label.confirmed_at is None:
            missing += 1
            event = event.model_copy(update={"label": None})
        elif event.label.confirmed_at > _HOLDOUT_CUTOFF:
            late += 1
            event = event.model_copy(update={"label": None})
        variants["rules_champion"].append(
            (event, champion.decide(transaction, features).risk_score)
        )
        variants["xgboost_challenger"].append((event, challenger.score(transaction, features)))

    results = {}
    for name, scores in variants.items():
        matured = [(event.label.is_fraud, score) for event, score in scores if event.label is not None]
        results[name] = {
            **measure_same_budget(scores, alert_budget=alert_budget),
            "auc": auc([score for _, score in matured], [label for label, _ in matured]),
        }
    report: dict[str, object] = {
        "report_version": "synthetic-ml-challenger-v1",
        "alert_budget_per_variant": alert_budget,
        "selection": "top_k_by_risk_score_then_event_time_then_event_id",
        "training": {
            "rows": manifest.training_rows, "dataset_digest": manifest.cohort_digest,
            "last_event_at": train[-1].transaction.occurred_at.isoformat(),
            "label_cutoff": manifest.label_cutoff.isoformat(),
        },
        "holdout": {
            "rows": len(holdout), "first_event_at": holdout[0].transaction.occurred_at.isoformat(),
            "label_cutoff": _HOLDOUT_CUTOFF.isoformat(), "late_labels": late,
            "missing_labels": missing, "matured_labels": len(holdout) - late - missing,
            "dataset_sha256": _digest([event.model_dump(mode="json") for event in holdout]),
        },
        "model": {
            "version": challenger.model_version, "feature_schema": manifest.feature_schema,
            "xgboost_version": manifest.xgboost_version,
            "booster_sha256": sha256((artifact_path / MODEL_FILENAME).read_bytes()).hexdigest(),
            "scoring_manifest_sha256": _digest(
                manifest.model_dump(mode="json", exclude={"trained_at"})
            ),
        },
        "rules_policy": policy.model_dump(mode="json"),
        "benchmarks": results,
        "live_serving_enabled": False,
        "bank_data_verified": False,
        "netguardians_outputs_compared": False,
        "enforcement_activated": False,
    }
    return {**report, "comparison_sha256": _digest(report)}


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--alert-budget", type=int, default=12)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    try:
        if args.artifact_root is None:
            with TemporaryDirectory(prefix="gasha-synthetic-challenger-") as temp:
                report = compare_synthetic_challenger(
                    artifact_root=Path(temp), alert_budget=args.alert_budget,
                )
        else:
            report = compare_synthetic_challenger(
                artifact_root=args.artifact_root, alert_budget=args.alert_budget,
            )
    except ValueError as exc:
        parser.error(str(exc))
    print(dumps(report, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
