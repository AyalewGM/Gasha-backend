"""Deserialized POC comparator partitions must conserve both systems' populations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gasha.domain import models
from gasha.poc import historical, outcomes, report


Case = tuple[str, bool, bool, outcomes.IncumbentControlOutcome | None]

_COHORTS: dict[str, tuple[Case, ...]] = {
    "fraud": (
        ("fraud-gasha", True, True, outcomes.IncumbentControlOutcome.NO_ALERT),
        ("fraud-incumbent", True, False, outcomes.IncumbentControlOutcome.ALERT),
    ),
    "legitimate": (
        ("legitimate-both", False, True, outcomes.IncumbentControlOutcome.ALERT),
        ("legitimate-neither", False, False, outcomes.IncumbentControlOutcome.NO_ALERT),
    ),
    "mixed": (
        ("fraud-both", True, True, outcomes.IncumbentControlOutcome.ALERT),
        ("fraud-gasha", True, True, outcomes.IncumbentControlOutcome.NO_ALERT),
        ("legitimate-incumbent", False, False, outcomes.IncumbentControlOutcome.ALERT),
        ("legitimate-neither", False, False, outcomes.IncumbentControlOutcome.NO_ALERT),
    ),
    "missing": (
        ("fraud-gasha", True, True, outcomes.IncumbentControlOutcome.NO_ALERT),
        ("legitimate-missing", False, False, None),
        ("fraud-incumbent", True, False, outcomes.IncumbentControlOutcome.ALERT),
    ),
    "legitimate-no-alert": (
        ("legitimate-neither", False, False, outcomes.IncumbentControlOutcome.NO_ALERT),
    ),
    "incremental-gasha-bound": (
        ("legitimate-gasha", False, True, outcomes.IncumbentControlOutcome.NO_ALERT),
        ("fraud-neither", True, False, outcomes.IncumbentControlOutcome.NO_ALERT),
    ),
    "incremental-incumbent-bound": (
        ("fraud-gasha", True, True, outcomes.IncumbentControlOutcome.NO_ALERT),
        ("fraud-both", True, True, outcomes.IncumbentControlOutcome.ALERT),
        ("legitimate-gasha", False, True, outcomes.IncumbentControlOutcome.NO_ALERT),
    ),
}


def _payload(cohort: str) -> dict[str, object]:
    events: list[historical.HistoricalTransactionEvent] = []
    for suffix, fraud, gasha_alert, incumbent in _COHORTS[cohort]:
        transaction = models.CanonicalTransaction(
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
            beneficiary_type=models.BeneficiaryType.EXTERNAL,
            destination_institution_id="synthetic-institution",
            correlation_id=f"corr-{suffix}",
        )
        events.append(
            historical.HistoricalTransactionEvent(
                transaction=transaction,
                intelligence=models.IntelligenceSnapshot(
                    network_risk=0.99 if gasha_alert else 0.0
                ),
                label=historical.ConfirmedOutcomeLabel(
                    is_fraud=fraud, label_source="synthetic"
                ),
                incumbent_outcome=incumbent,
            )
        )

    policies = {
        "tenant-synthetic": models.DecisionPolicy(
            configuration_version="config-synthetic",
            policy_version="policy-synthetic",
            rule_version="rules-synthetic",
        )
    }
    replay = historical.replay_historical(tuple(events), policies)
    report = report.build_poc_report(
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
    validated = report.POCReport.model_validate_json(json.dumps(payload))
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
        ("fraud", "label_population"),
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
    assert report.POCReport.model_validate_json(json.dumps(payload)).incumbent_comparison

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
        reference = _payload("legitimate")["incumbent_comparison"]
        assert isinstance(reference, dict)
        comparison["incumbent"] = reference["incumbent"]
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
        report.POCReport.model_validate_json(json.dumps(payload))
