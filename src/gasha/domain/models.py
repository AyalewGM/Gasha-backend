from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

RiskScore = Annotated[float, Field(ge=0.0, le=1.0)]


class BeneficiaryType(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    MERCHANT = "merchant"
    WALLET = "wallet"
    UNKNOWN = "unknown"


class DecisionAction(StrEnum):
    ALLOW = "allow"
    MONITOR = "monitor"
    CHALLENGE = "challenge"
    REVIEW = "review"
    HOLD = "hold"
    BLOCK = "block"
    NO_ACTION_SHADOW = "no_action_shadow"


class OperatingMode(StrEnum):
    """How a decided evaluation is exposed to the bank-facing channel."""

    ENFORCING = "enforcing"
    SHADOW = "shadow"


class CanonicalTransaction(BaseModel):
    tenant_id: str = Field(min_length=1)
    event_id: UUID
    occurred_at: datetime
    channel: str
    transaction_type: str
    amount: Decimal = Field(gt=0)
    currency: str = Field(min_length=3, max_length=3)
    sender_customer_id: str
    sender_account_id: str
    beneficiary_id: str
    beneficiary_type: BeneficiaryType
    destination_institution_id: str | None = None
    device_id: str | None = None
    correlation_id: str

    @model_validator(mode="after")
    def validate_external_beneficiary(self) -> CanonicalTransaction:
        if (
            self.beneficiary_type == BeneficiaryType.EXTERNAL
            and not self.destination_institution_id
        ):
            raise ValueError("external beneficiary requires destination_institution_id")
        return self


class IntelligenceSnapshot(BaseModel):
    customer_risk: RiskScore = 0.0
    transaction_risk: RiskScore = 0.0
    velocity_risk: RiskScore = 0.0
    device_session_risk: RiskScore = 0.0
    beneficiary_risk: RiskScore = 0.0
    relationship_risk: RiskScore = 0.0
    network_risk: RiskScore = 0.0
    journey_risk: RiskScore = 0.0


class DecisionPolicy(BaseModel):
    configuration_version: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    model_version: str | None = None
    monitor_threshold: RiskScore = 0.50
    challenge_threshold: RiskScore | None = None
    review_threshold: RiskScore = 0.70
    hold_threshold: RiskScore = 0.85
    block_threshold: RiskScore = 0.95

    @model_validator(mode="after")
    def validate_threshold_order(self) -> DecisionPolicy:
        thresholds = (
            self.monitor_threshold,
            self.review_threshold,
            self.hold_threshold,
            self.block_threshold,
        )
        if thresholds != tuple(sorted(thresholds)) or len(set(thresholds)) != len(thresholds):
            raise ValueError("decision thresholds must be strictly increasing")
        challenge = self.challenge_threshold
        if challenge is not None and not (
            self.monitor_threshold < challenge < self.review_threshold
        ):
            raise ValueError(
                "challenge threshold must sit strictly between monitor and review"
            )
        return self


class FraudDecision(BaseModel):
    tenant_id: str
    event_id: UUID
    action: DecisionAction
    risk_score: RiskScore
    reason_codes: list[str]
    configuration_version: str
    policy_version: str
    rule_version: str
    model_version: str | None = None
    decided_at: datetime
    correlation_id: str
