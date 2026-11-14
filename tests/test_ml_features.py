"""Model feature contract tests: deterministic, numeric-only, shared order."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from math import log1p
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.ml.features import (
    FEATURE_NAMES,
    NUM_FEATURES,
    build_feature_vector,
    feature_row,
)

AT = datetime(2026, 3, 9, 14, 30, tzinfo=UTC)  # a Monday


def transaction(**changes: object) -> CanonicalTransaction:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "event_id": uuid4(),
        "occurred_at": AT,
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": Decimal("2500.50"),
        "currency": "ETB",
        "sender_customer_id": "customer-1",
        "sender_account_id": "account-1",
        "beneficiary_id": "beneficiary-7",
        "beneficiary_type": BeneficiaryType.EXTERNAL,
        "destination_institution_id": "external-bank",
        "correlation_id": "corr-1",
    }
    values.update(changes)
    return CanonicalTransaction(**values)  # type: ignore[arg-type]


def snapshot(**changes: float) -> IntelligenceSnapshot:
    values = {name: 0.1 for name in IntelligenceSnapshot.model_fields}
    values.update(changes)
    return IntelligenceSnapshot(**values)


def test_feature_names_match_model_field_order() -> None:
    assert FEATURE_NAMES == (
        "customer_risk",
        "transaction_risk",
        "velocity_risk",
        "device_session_risk",
        "beneficiary_risk",
        "relationship_risk",
        "network_risk",
        "journey_risk",
        "log_amount",
        "hour_of_day",
        "day_of_week",
        "has_device_id",
        "beneficiary_internal",
        "beneficiary_external",
        "beneficiary_merchant",
        "beneficiary_wallet",
        "beneficiary_unknown",
    )
    assert NUM_FEATURES == 17


def test_vector_carries_snapshot_scores_and_derived_fields() -> None:
    vector = build_feature_vector(
        transaction(device_id="device-9"),
        snapshot(velocity_risk=0.8, journey_risk=0.7),
    )
    assert vector.velocity_risk == 0.8
    assert vector.journey_risk == 0.7
    assert vector.log_amount == pytest.approx(log1p(2500.50))
    assert vector.hour_of_day == 14
    assert vector.day_of_week == 0
    assert vector.has_device_id is True
    assert vector.beneficiary_external is True
    assert vector.beneficiary_internal is False


@pytest.mark.parametrize(
    ("beneficiary", "flag"),
    [
        (BeneficiaryType.INTERNAL, "beneficiary_internal"),
        (BeneficiaryType.EXTERNAL, "beneficiary_external"),
        (BeneficiaryType.MERCHANT, "beneficiary_merchant"),
        (BeneficiaryType.WALLET, "beneficiary_wallet"),
        (BeneficiaryType.UNKNOWN, "beneficiary_unknown"),
    ],
)
def test_beneficiary_one_hot_is_exclusive(beneficiary: BeneficiaryType, flag: str) -> None:
    vector = build_feature_vector(
        transaction(
            beneficiary_type=beneficiary,
            destination_institution_id=(
                "external-bank" if beneficiary is BeneficiaryType.EXTERNAL else None
            ),
        ),
        snapshot(),
    )
    one_hots = {
        name: getattr(vector, name)
        for name in (
            "beneficiary_internal",
            "beneficiary_external",
            "beneficiary_merchant",
            "beneficiary_wallet",
            "beneficiary_unknown",
        )
    }
    assert one_hots[flag] is True
    assert sum(bool(value) for value in one_hots.values()) == 1


def test_feature_row_is_numeric_canonical_order() -> None:
    vector = build_feature_vector(transaction(), snapshot())
    row = feature_row(vector)
    assert len(row) == NUM_FEATURES
    assert all(type(value) is float for value in row)
    assert row[0] == 0.1
    assert row[8] == pytest.approx(log1p(2500.50))
    assert row[13] == 1.0  # beneficiary_external


def test_builder_rejects_untrusted_input_types() -> None:
    with pytest.raises(ValueError, match="canonical transaction"):
        build_feature_vector(object(), snapshot())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="intelligence snapshot"):
        build_feature_vector(transaction(), object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="feature vector"):
        feature_row(object())  # type: ignore[arg-type]
