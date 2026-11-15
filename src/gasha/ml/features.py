"""Point-in-time model feature contract shared by training and serving.

The same builder runs inside the offline dataset builder and the runtime
scorer so the feature columns a model was trained on can never drift from
the columns it is scored against. Only bounded numeric features are used;
free-form strings such as ``channel`` or ``transaction_type`` are excluded
because their unbounded vocabularies cannot be bound to a model artifact.
"""

from __future__ import annotations

from math import log1p

from pydantic import BaseModel, Field

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
    RiskScore,
)

FEATURE_SCHEMA_VERSION = "gasha-model-features-v1"


class ModelFeatureVector(BaseModel):
    """Versioned, numeric-only feature row for the fraud scorer."""

    customer_risk: RiskScore
    transaction_risk: RiskScore
    velocity_risk: RiskScore
    device_session_risk: RiskScore
    beneficiary_risk: RiskScore
    relationship_risk: RiskScore
    network_risk: RiskScore
    journey_risk: RiskScore
    log_amount: float = Field(ge=0.0)
    hour_of_day: int = Field(ge=0, le=23)
    day_of_week: int = Field(ge=0, le=6)
    has_device_id: bool
    beneficiary_internal: bool
    beneficiary_external: bool
    beneficiary_merchant: bool
    beneficiary_wallet: bool
    beneficiary_unknown: bool


FEATURE_NAMES: tuple[str, ...] = tuple(ModelFeatureVector.model_fields)
NUM_FEATURES = len(FEATURE_NAMES)


def build_feature_vector(
    transaction: CanonicalTransaction,
    intelligence: IntelligenceSnapshot,
) -> ModelFeatureVector:
    """Derives the canonical feature vector for one decision-time input.

    Every field is point-in-time: the eight signal scores come from the
    trusted ``IntelligenceSnapshot`` assembled by the intelligence layer and
    the raw fields come from the canonical transaction contract only.
    """
    if type(transaction) is not CanonicalTransaction:
        raise ValueError("canonical transaction required")
    if type(intelligence) is not IntelligenceSnapshot:
        raise ValueError("typed intelligence snapshot required")
    beneficiary = transaction.beneficiary_type
    occurred = transaction.occurred_at
    return ModelFeatureVector(
        customer_risk=intelligence.customer_risk,
        transaction_risk=intelligence.transaction_risk,
        velocity_risk=intelligence.velocity_risk,
        device_session_risk=intelligence.device_session_risk,
        beneficiary_risk=intelligence.beneficiary_risk,
        relationship_risk=intelligence.relationship_risk,
        network_risk=intelligence.network_risk,
        journey_risk=intelligence.journey_risk,
        log_amount=log1p(float(transaction.amount)),
        hour_of_day=occurred.hour,
        day_of_week=occurred.weekday(),
        has_device_id=transaction.device_id is not None,
        beneficiary_internal=beneficiary is BeneficiaryType.INTERNAL,
        beneficiary_external=beneficiary is BeneficiaryType.EXTERNAL,
        beneficiary_merchant=beneficiary is BeneficiaryType.MERCHANT,
        beneficiary_wallet=beneficiary is BeneficiaryType.WALLET,
        beneficiary_unknown=beneficiary is BeneficiaryType.UNKNOWN,
    )


def feature_row(vector: ModelFeatureVector) -> tuple[float, ...]:
    """Flattens a validated vector into the canonical column order."""
    if type(vector) is not ModelFeatureVector:
        raise ValueError("typed model feature vector required")
    return tuple(float(getattr(vector, name)) for name in FEATURE_NAMES)
