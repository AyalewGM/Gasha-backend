from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, Field

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


class CanonicalTransaction(BaseModel):
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


class IntelligenceSnapshot(BaseModel):
    customer_risk: RiskScore = 0.0
    transaction_risk: RiskScore = 0.0
    beneficiary_risk: RiskScore = 0.0
    relationship_risk: RiskScore = 0.0
    network_risk: RiskScore = 0.0


class FraudDecision(BaseModel):
    event_id: UUID
    action: DecisionAction
    risk_score: RiskScore
    reason_codes: list[str]
    rule_version: str
    model_version: str | None = None
    decided_at: datetime
    correlation_id: str
