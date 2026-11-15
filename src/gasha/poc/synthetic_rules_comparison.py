"""Offline same-budget comparison of two Gasha rules configurations."""

from __future__ import annotations

from argparse import ArgumentParser
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from json import dumps
from uuid import UUID

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    ReplayedEventResult,
)
from gasha.poc.matured_lineage_replay import OfflineCohortScope, replay_offline_matured_lineage
from gasha.poc.temporal_lineage import HistoricalFeatureEnvelope, SignalLineage

_START = datetime(2026, 1, 10, 9, tzinfo=UTC)
_LABEL_CUTOFF = _START + timedelta(days=7)
_TENANT = "synthetic-comparison"
_SIGNAL_VERSION = "synthetic-comparison-signals-v1"
# Transaction risk, device risk, eventual fraud label, days to confirmation.
_FIXTURE = (
    (0.95, 0.09, False, 2),
    (0.89, 0.93, True, 2),
    (0.20, 0.99, True, 3),
    (0.10, 0.91, True, 2),
    (0.84, 0.10, False, 2),
    (0.23, 0.25, False, 4),
    (0.96, 0.96, True, 9),
    (0.30, 0.30, None, None),
)


def _digest(value: object) -> str:
    encoded = dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + sha256(encoded).hexdigest()


def _fixture() -> tuple[HistoricalTransactionEvent, ...]:
    cohort = []
    for index, (transaction_risk, device_risk, fraud, days) in enumerate(_FIXTURE, 1):
        occurred = _START + timedelta(minutes=index)
        event = HistoricalTransactionEvent(
            transaction=CanonicalTransaction(
                tenant_id=_TENANT, event_id=UUID(int=index), occurred_at=occurred,
                channel="mobile", transaction_type="transfer", amount=Decimal(100),
                currency="ETB", sender_customer_id=f"synthetic-customer-{index}",
                sender_account_id=f"synthetic-account-{index}",
                beneficiary_id=f"synthetic-beneficiary-{index}",
                beneficiary_type=BeneficiaryType.INTERNAL, correlation_id=f"synthetic-{index}",
            ),
            intelligence=IntelligenceSnapshot(
                transaction_risk=transaction_risk, device_session_risk=device_risk,
            ),
            received_at=occurred,
            signal_policy_versions=(_SIGNAL_VERSION,),
            label=ConfirmedOutcomeLabel(
                is_fraud=fraud, label_source="synthetic-investigator",
                confirmed_at=occurred + timedelta(days=days),
            ) if fraud is not None and days is not None else None,
        )
        cohort.append(event)
    return tuple(cohort)


def _rate(numerator: int, denominator: int, reason: str) -> dict[str, object]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
        "undefined_reason": None if denominator else reason,
    }


def _measure(
    results: tuple[ReplayedEventResult, ...], *, alert_budget: int,
) -> dict[str, object]:
    # Budget consumes all selected events, including those whose labels are unavailable.
    ordered = sorted(results, key=lambda row: (
        -row.decision.risk_score, row.event.transaction.occurred_at, row.event.transaction.event_id,
    ))
    alerted_ids = {row.decision.event_id for row in ordered[:alert_budget]}
    tp = fp = tn = fn = unlabeled = alerted_unlabeled = 0
    for row in results:
        alerted = row.decision.event_id in alerted_ids
        label = row.event.label
        if label is None:
            unlabeled += 1
            alerted_unlabeled += int(alerted)
        elif label.is_fraud:
            tp += int(alerted)
            fn += int(not alerted)
        else:
            fp += int(alerted)
            tn += int(not alerted)

    return {
        "alert_count": len(alerted_ids),
        "alerts_with_unavailable_label": alerted_unlabeled,
        "confusion_counts": {
            "true_positive": tp, "false_positive": fp, "true_negative": tn,
            "false_negative": fn, "unlabeled": unlabeled,
        },
        "precision": _rate(tp, tp + fp, "no_alerted_labeled_cases"),
        "recall": _rate(tp, tp + fn, "no_labeled_positives"),
        "f1": _rate(2 * tp, 2 * tp + fp + fn, "no_positive_labels_or_alerts"),
        "false_positive_rate": _rate(fp, fp + tn, "no_labeled_negatives"),
        "false_negative_rate": _rate(fn, tp + fn, "no_labeled_positives"),
    }


def compare_synthetic_rules(*, alert_budget: int = 4) -> dict[str, object]:
    """Replay one fixed cohort through baseline and candidate Gasha rules."""
    cohort = _fixture()
    if type(alert_budget) is not int or not 0 <= alert_budget <= len(cohort):
        raise ValueError(f"alert budget must be an integer from 0 to {len(cohort)}")
    dataset_digest = _digest([event.model_dump(mode="json") for event in cohort])
    variants = {}
    for baseline in (True, False):
        name = "transaction_risk_only" if baseline else "full_signal_fusion"
        policy = DecisionPolicy(
            configuration_version=f"{name}-v1", policy_version="synthetic-comparison-policy-v1",
            rule_version="gasha-deterministic-max-signal-v1",
        )
        scope = OfflineCohortScope(
            tenant_id=_TENANT, dataset_digest=dataset_digest,
            cohort_version="synthetic-comparison-cohort-v1", mapping_version="fixture-v1",
            configuration_version=policy.configuration_version, policy_version=policy.policy_version,
            rule_version=policy.rule_version, signal_policy_version=_SIGNAL_VERSION,
            window_start=_START, window_end=_START + timedelta(minutes=len(cohort)),
            label_cutoff=_LABEL_CUTOFF,
        )
        variant_events = tuple(
            event.model_copy(update={
                "intelligence": IntelligenceSnapshot(transaction_risk=event.intelligence.transaction_risk),
            }) if baseline else event for event in cohort
        )
        lineage = tuple(HistoricalFeatureEnvelope(
            tenant_id=_TENANT, event_id=event.transaction.event_id, dataset_digest=dataset_digest,
            cohort_version=scope.cohort_version, mapping_version=scope.mapping_version,
            configuration_version=scope.configuration_version, policy_version=scope.policy_version,
            signal_policy_version=_SIGNAL_VERSION, occurred_at=event.transaction.occurred_at,
            decision_cutoff=event.transaction.occurred_at,
            signals=tuple(SignalLineage(
                name=field, value=getattr(event.intelligence, field),
                source_ref="synthetic-rule-input", source_version=_SIGNAL_VERSION,
                as_of=event.transaction.occurred_at, available_at=event.transaction.occurred_at,
            ) for field in IntelligenceSnapshot.model_fields),
        ) for event in variant_events)
        result = replay_offline_matured_lineage(
            scope, variant_events, lineage, policy, clock=lambda: _LABEL_CUTOFF,
        )
        variants[name] = {
            "configuration_version": scope.configuration_version,
            "rule_version": scope.rule_version,
            "policy_version": scope.policy_version,
            "evaluation_digest": result.evaluation_digest,
            "maturity": result.to_dict()["maturity"],
            **_measure(tuple(result.replay.results), alert_budget=alert_budget),
        }

    report: dict[str, object] = {
        "report_version": "synthetic-gasha-rules-comparison-v1",
        "dataset_digest": dataset_digest,
        "cohort_size": len(cohort),
        "label_cutoff": _LABEL_CUTOFF.isoformat(),
        "alert_budget_per_variant": alert_budget,
        "selection": "top_k_by_risk_score_then_event_time_then_event_id",
        "bank_data_verified": False,
        "bank_kpi_approved": False,
        "netguardians_outputs_compared": False,
        "enforcement_activated": False,
        "variants": variants,
    }
    return {**report, "comparison_digest": _digest(report)}


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--alert-budget", type=int, default=4)
    args = parser.parse_args()
    try:
        report = compare_synthetic_rules(alert_budget=args.alert_budget)
    except ValueError as exc:
        parser.error(str(exc))
    print(dumps(report, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
