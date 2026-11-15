"""Matured-label dataset builder tests: masking, ordering and digest binding."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.ml.dataset import DatasetRejected, build_training_dataset
from gasha.poc.historical import ConfirmedOutcomeLabel, HistoricalTransactionEvent

AT = datetime(2026, 1, 10, 9, tzinfo=UTC)
CUTOFF = AT + timedelta(days=10)


def event(
    number: int = 1,
    *,
    label: bool | None = True,
    confirmed_at: datetime | None = AT + timedelta(days=1),
    occurred_at: datetime = AT,
    tenant_id: str = "tenant-a",
    risk: float = 0.2,
) -> HistoricalTransactionEvent:
    snapshot = IntelligenceSnapshot(
        **{name: risk for name in IntelligenceSnapshot.model_fields}
    )
    return HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id=tenant_id,
            event_id=UUID(int=number),
            occurred_at=occurred_at,
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal(10),
            currency="ETB",
            sender_customer_id="customer-1",
            sender_account_id="account-1",
            beneficiary_id="beneficiary-1",
            beneficiary_type=BeneficiaryType.INTERNAL,
            correlation_id="corr-1",
        ),
        intelligence=snapshot,
        label=(
            ConfirmedOutcomeLabel(
                is_fraud=label,
                label_source="synthetic-analyst",
                confirmed_at=confirmed_at,
            )
            if label is not None
            else None
        ),
    )


def test_only_matured_labels_become_rows() -> None:
    dataset = build_training_dataset(
        [
            event(1, label=True),
            event(2, label=False),
            event(3, label=None),
            event(4, label=True, confirmed_at=None),
            event(5, label=True, confirmed_at=CUTOFF + timedelta(seconds=1)),
        ],
        label_cutoff=CUTOFF,
    )
    assert [row.event_id for row in dataset.rows] == [UUID(int=1), UUID(int=2)]
    assert dataset.matured_positive == 1
    assert dataset.matured_negative == 1
    assert dataset.absent_labels == 1
    assert dataset.excluded_unconfirmed_labels == 1
    assert dataset.excluded_future_labels == 1


def test_rows_are_sorted_by_event_time() -> None:
    dataset = build_training_dataset(
        [
            event(1, occurred_at=AT + timedelta(hours=2)),
            event(2, occurred_at=AT),
            event(3, occurred_at=AT + timedelta(hours=1)),
        ],
        label_cutoff=CUTOFF,
    )
    assert [row.event_id for row in dataset.rows] == [
        UUID(int=2),
        UUID(int=3),
        UUID(int=1),
    ]


def test_cohort_digest_binds_rows_labels_and_features() -> None:
    base = build_training_dataset([event(1, label=True)], label_cutoff=CUTOFF)
    same = build_training_dataset([event(1, label=True)], label_cutoff=CUTOFF)
    flipped = build_training_dataset([event(1, label=False)], label_cutoff=CUTOFF)
    different_features = build_training_dataset(
        [event(1, label=True, risk=0.9)], label_cutoff=CUTOFF
    )
    assert base.cohort_digest == same.cohort_digest
    assert base.cohort_digest != flipped.cohort_digest
    assert base.cohort_digest != different_features.cohort_digest


def test_duplicate_event_identity_is_rejected() -> None:
    with pytest.raises(DatasetRejected, match="duplicate"):
        build_training_dataset([event(1), event(1)], label_cutoff=CUTOFF)


def test_tenant_scope_is_enforced_when_declared() -> None:
    with pytest.raises(DatasetRejected, match="tenant"):
        build_training_dataset(
            [event(1, tenant_id="tenant-b")],
            label_cutoff=CUTOFF,
            tenant_id="tenant-a",
        )
    dataset = build_training_dataset(
        [event(1, tenant_id="tenant-a"), event(2, tenant_id="tenant-a")],
        label_cutoff=CUTOFF,
        tenant_id="tenant-a",
    )
    assert len(dataset.rows) == 2


def test_naive_cutoff_and_untyped_events_are_rejected() -> None:
    with pytest.raises(DatasetRejected, match="timezone-aware"):
        build_training_dataset(
            [event(1)], label_cutoff=datetime(2026, 1, 20, 9)  # noqa: DTZ001
        )
    with pytest.raises(DatasetRejected, match="typed historical event"):
        build_training_dataset([object()], label_cutoff=CUTOFF)  # type: ignore[list-item]
