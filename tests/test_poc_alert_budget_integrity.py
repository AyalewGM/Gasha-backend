"""#144: equal-budget scoring must preserve tenant ownership and real denominators."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.poc.alert_budget import measure_same_budget
from gasha.poc.historical import ConfirmedOutcomeLabel, HistoricalTransactionEvent

T0 = datetime(2026, 2, 10, 9, tzinfo=UTC)


def _event(
    tenant: str, identity: int, label: bool | None, *,
    occurred_at: datetime = T0,
) -> HistoricalTransactionEvent:
    transaction = CanonicalTransaction(
        tenant_id=tenant,
        event_id=UUID(int=identity),
        occurred_at=occurred_at,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("100.00"),
        currency="ETB",
        sender_customer_id=f"fictional-customer-{tenant}-{identity}",
        sender_account_id=f"fictional-account-{tenant}-{identity}",
        beneficiary_id=f"fictional-beneficiary-{identity}",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="fictional-institution",
        correlation_id=f"fictional-correlation-{tenant}-{identity}",
    )
    return HistoricalTransactionEvent(
        transaction=transaction,
        intelligence=IntelligenceSnapshot(),
        label=(
            ConfirmedOutcomeLabel(is_fraud=label, label_source="synthetic")
            if label is not None else None
        ),
    )


def test_rejects_mixed_tenant_even_when_event_uuids_collide() -> None:
    rows = [
        (_event("tenant-a", 1, True), 0.99),
        (_event("tenant-b", 1, False), 0.01),
    ]
    with pytest.raises(ValueError, match="mixed-tenant"):
        measure_same_budget(rows, alert_budget=1)


def test_same_uuid_in_separate_tenant_cohorts_does_not_inherit_alert() -> None:
    fraud = measure_same_budget(
        [(_event("tenant-a", 1, True), 0.95)], alert_budget=1,
    )
    legitimate = measure_same_budget(
        [(_event("tenant-b", 1, False), 0.05)], alert_budget=0,
    )
    assert fraud["tenant_id"] == "tenant-a"
    assert legitimate["tenant_id"] == "tenant-b"
    assert fraud["confusion_counts"] == {
        "true_positive": 1, "false_positive": 0, "true_negative": 0,
        "false_negative": 0, "unlabeled": 0,
    }
    assert legitimate["confusion_counts"] == {
        "true_positive": 0, "false_positive": 0, "true_negative": 1,
        "false_negative": 0, "unlabeled": 0,
    }


def test_duplicate_composite_identity_rejects_before_budgeting() -> None:
    first = _event("tenant-a", 7, True)
    with pytest.raises(ValueError, match="duplicate tenant/event"):
        measure_same_budget([(first, 0.99), (first, 0.20)], alert_budget=1)


@pytest.mark.parametrize("invalid_budget", [-1, 2, True, 1.0, None])
def test_invalid_budget_rejects(invalid_budget: object) -> None:
    with pytest.raises(ValueError, match="alert budget"):
        measure_same_budget(
            [(_event("tenant-a", 9, False), 0.2)],
            alert_budget=invalid_budget,  # type: ignore[arg-type]
        )


def test_same_risk_score_selects_earlier_event_deterministically() -> None:
    later = _event("tenant-a", 2, False, occurred_at=T0 + timedelta(minutes=1))
    earlier = _event("tenant-a", 1, True, occurred_at=T0)
    for rows in ([(later, 0.9), (earlier, 0.9)],
                 [(earlier, 0.9), (later, 0.9)]):
        metrics = measure_same_budget(rows, alert_budget=1)
        assert metrics["confusion_counts"] == {
            "true_positive": 1, "false_positive": 0, "true_negative": 1,
            "false_negative": 0, "unlabeled": 0,
        }
        assert metrics["alert_count"] == metrics["selected_row_count"] == 1


@pytest.mark.parametrize("budget", [0, 2, 3])
def test_selected_unlabeled_rows_consume_budget_and_counts_conserve(
    budget: int,
) -> None:
    cohort = [
        (_event("tenant-a", 1, None), 0.98),
        (_event("tenant-a", 2, True), 0.75),
        (_event("tenant-a", 3, False), 0.35),
    ]
    metrics = measure_same_budget(cohort, alert_budget=budget)
    counts = metrics["confusion_counts"]
    assert isinstance(counts, dict)
    assert metrics["tenant_id"] == "tenant-a"
    assert metrics["cohort_size"] == 3
    assert metrics["alert_budget"] == metrics["alert_count"] == budget
    assert metrics["selected_row_count"] == budget
    assert (counts["true_positive"] + counts["false_positive"]
            + metrics["alerts_with_unavailable_label"]) == budget
    assert (counts["true_positive"] + counts["false_positive"]
            + counts["true_negative"] + counts["false_negative"]) == 2
    assert metrics["evaluated_labeled_rows"] == 2
    assert counts["unlabeled"] == 1
    assert metrics["alerts_with_unavailable_label"] == int(budget > 0)


def test_empty_cohort_accepts_only_zero_budget_and_rates_are_undefined() -> None:
    empty = measure_same_budget([], alert_budget=0)
    assert empty["tenant_id"] is None
    assert empty["alert_count"] == empty["selected_row_count"] == 0
    assert empty["cohort_size"] == empty["evaluated_labeled_rows"] == 0
    for rate_name in ("precision", "recall", "f1", "false_positive_rate"):
        rate = empty[rate_name]
        assert isinstance(rate, dict)
        assert rate["value"] is None
        assert rate["denominator"] == 0
        assert isinstance(rate["undefined_reason"], str)
    with pytest.raises(ValueError, match="alert budget"):
        measure_same_budget([], alert_budget=1)

@pytest.mark.parametrize(
    "invalid_score",
    [float("nan"), float("inf"), float("-inf"), -0.01, 1.01,
     True, "0.9", None, 10 ** 400],
)
@pytest.mark.parametrize("budget", [0, 1])
def test_invalid_score_fails_closed_before_top_k_even_when_k_is_zero(
    invalid_score: object, budget: int,
) -> None:
    event = _event("tenant-a", 12, True)
    with pytest.raises(ValueError, match="invalid score"):
        measure_same_budget(
            [(event, invalid_score)],  # type: ignore[list-item]
            alert_budget=budget,
        )


def test_finite_normalized_score_selection_is_permutation_invariant() -> None:
    fraud = _event("tenant-a", 11, True)
    legitimate = _event("tenant-a", 12, False)
    rows = [(fraud, 1.0), (legitimate, 0.0)]
    for cohort in (rows, list(reversed(rows))):
        metrics = measure_same_budget(cohort, alert_budget=1)
        assert metrics["alert_count"] == metrics["selected_row_count"] == 1
        assert metrics["confusion_counts"] == {
            "true_positive": 1, "false_positive": 0,
            "true_negative": 1, "false_negative": 0, "unlabeled": 0,
        }
