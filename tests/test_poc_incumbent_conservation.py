"""Deserialized POC comparator partitions must conserve both systems' populations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.outcomes import IncumbentControlOutcome
from gasha.poc.report import POCReport, _confusion_summary, build_poc_report


Case = tuple[str, bool, bool, IncumbentControlOutcome | None]

_COHORTS: dict[str, tuple[Case, ...]] = {
    "fraud": (
        ("fraud-gasha", True, True, IncumbentControlOutcome.NO_ALERT),
        ("fraud-incumbent", True, False, IncumbentControlOutcome.ALERT),
    ),
    "legitimate": (
        ("legitimate-both", False, True, IncumbentControlOutcome.ALERT),
        ("legitimate-neither", False, False, IncumbentControlOutcome.NO_ALERT),
    ),
    "mixed": (
        ("fraud-both", True, True, IncumbentControlOutcome.ALERT),
        ("fraud-gasha", True, True, IncumbentControlOutcome.NO_ALERT),
        ("legitimate-incumbent", False, False, IncumbentControlOutcome.ALERT),
        ("legitimate-neither", False, False, IncumbentControlOutcome.NO_ALERT),
    ),
    "missing": (
        ("fraud-gasha", True, True, IncumbentControlOutcome.NO_ALERT),
        ("legitimate-missing", False, False, None),
        ("fraud-incumbent", True, False, IncumbentControlOutcome.ALERT),
    ),
    "legitimate-no-alert": (
        ("legitimate-neither", False, False, IncumbentControlOutcome.NO_ALERT),
    ),
    "incremental-gasha-bound": (
        ("legitimate-gasha", False, True, IncumbentControlOutcome.NO_ALERT),
        ("fraud-neither", True, False, IncumbentControlOutcome.NO_ALERT),
    ),
    "incremental-incumbent-bound": (
        ("fraud-gasha", True, True, IncumbentControlOutcome.NO_ALERT),
        ("fraud-both", True, True, IncumbentControlOutcome.ALERT),
        ("legitimate-gasha", False, True, IncumbentControlOutcome.NO_ALERT),
    ),
}


def _payload(cohort: str) -> dict[str, object]:
    events: list[HistoricalTransactionEvent] = []
    for suffix, fraud, gasha_alert, incumbent in _COHORTS[cohort]:
        transaction = CanonicalTransaction(
            tenant_id="tenant-synthetic",
            event_id=uuid4(),
            occurred_at=datetime(2026, 2, 10, tzinfo=UTC),
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal("10.00"),
            currency="ETB",
            sender_customer_id=f"sender-{suffix}",
            sender_account_id=f"account-{suffix}",
            beneficiary_id=f"beneficiary-{suffix}",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="synthetic-institution",
            correlation_id=f"corr-{suffix}",
        )
        events.append(
            HistoricalTransactionEvent(
                transaction=transaction,
                intelligence=IntelligenceSnapshot(
                    network_risk=0.99 if gasha_alert else 0.0
                ),
                label=ConfirmedOutcomeLabel(
                    is_fraud=fraud, label_source="synthetic"
                ),
                incumbent_outcome=incumbent,
            )
        )

    policies = {
        "tenant-synthetic": DecisionPolicy(
            configuration_version="config-synthetic",
            policy_version="policy-synthetic",
            rule_version="rules-synthetic",
        )
    }
    replay = replay_historical(tuple(events), policies)
    report = build_poc_report(
        tenant_id="tenant-synthetic",
        dataset_id=f"synthetic-{cohort}",
        report=replay,
        policies=policies,
    )
    return report.model_dump(mode="json")


@pytest.mark.parametrize("cohort", ["fraud", "legitimate", "mixed", "missing"])
def test_real_builder_comparator_round_trips_with_conserved_marginals(
    cohort: str,
) -> None:
    payload = _payload(cohort)
    validated = POCReport.model_validate_json(json.dumps(payload))
    comparison = validated.incumbent_comparison
    assert comparison is not None
    assert comparison.evaluated_cases > 0
    assert comparison.both_detected + comparison.gasha_only_detected == (
        comparison.gasha.true_positives + comparison.gasha.false_positives
    )
    assert comparison.both_detected + comparison.incumbent_only_detected == (
        comparison.incumbent.true_positives + comparison.incumbent.false_positives
    )
    assert comparison.gasha.true_positives + comparison.gasha.false_negatives == (
        comparison.incumbent.true_positives
        + comparison.incumbent.false_negatives
    )
    assert comparison.incremental_confirmed_detection <= min(
        comparison.gasha.true_positives,
        comparison.incumbent.false_negatives,
    )
    if cohort == "missing":
        assert comparison.missing_incumbent_outcomes == 1


@pytest.mark.parametrize(
    ("cohort", "mutation"),
    [
        ("legitimate-no-alert", "fabricated_both"),
        ("fraud", "gasha_marginal"),
        ("mixed", "gasha_marginal"),
        ("mixed", "incumbent_marginal"),
        ("missing", "incumbent_marginal"),
        ("mixed", "label_population"),
        ("incremental-gasha-bound", "incremental_gasha"),
        ("incremental-incumbent-bound", "incremental_incumbent"),
    ],
)
def test_json_consumer_rejects_comparison_arithmetic_tampering(
    cohort: str, mutation: str
) -> None:
    payload = _payload(cohort)
    comparison = payload["incumbent_comparison"]
    assert isinstance(comparison, dict)
    assert POCReport.model_validate_json(json.dumps(payload)).incumbent_comparison

    if mutation == "fabricated_both":
        assert comparison["neither_detected"] == 1
        comparison["neither_detected"] = 0
        comparison["both_detected"] = 1
    elif mutation == "gasha_marginal":
        assert comparison["gasha_only_detected"] >= 1
        comparison["gasha_only_detected"] -= 1
        comparison["neither_detected"] += 1
    elif mutation == "incumbent_marginal":
        assert comparison["incumbent_only_detected"] >= 1
        comparison["incumbent_only_detected"] -= 1
        comparison["neither_detected"] += 1
    elif mutation == "label_population":
        source = comparison["incumbent"]
        assert source["true_positives"] >= 1
        comparison["incumbent"] = _confusion_summary(
            source["true_positives"] - 1,
            source["false_positives"] + 1,
            source["true_negatives"],
            source["false_negatives"],
        ).model_dump(mode="json")
    elif mutation == "incremental_gasha":
        assert comparison["gasha_only_detected"] == 1
        assert comparison["gasha"]["true_positives"] == 0
        assert comparison["incumbent"]["false_negatives"] == 1
        comparison["incremental_confirmed_detection"] = 1
    elif mutation == "incremental_incumbent":
        assert comparison["gasha_only_detected"] == 2
        assert comparison["gasha"]["true_positives"] == 2
        assert comparison["incumbent"]["false_negatives"] == 1
        comparison["incremental_confirmed_detection"] = 2
    else:
        raise AssertionError(f"unsupported mutation: {mutation}")

    with pytest.raises(ValidationError, match="incumbent comparison population"):
        POCReport.model_validate_json(json.dumps(payload))
