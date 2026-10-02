from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from gasha.domain.models import RiskScore


class IntelligenceSource(StrEnum):
    TENANT_TRANSACTION = "tenant_transaction"
    TENANT_BEHAVIORAL = "tenant_behavioral"
    TENANT_DEVICE = "tenant_device"
    TENANT_RELATIONSHIP = "tenant_relationship"
    TENANT_BENEFICIARY = "tenant_beneficiary"
    TENANT_NETWORK = "tenant_network"
    AUTHORIZED_RAIL = "authorized_rail"
    AUTHORIZED_CONSORTIUM = "authorized_consortium"
    AUTHORIZED_SHARED = "authorized_shared"


class IntelligenceScope(StrEnum):
    TENANT_OBSERVED = "tenant_observed"
    AUTHORIZED_SHARED = "authorized_shared"


class SignalProvenance(BaseModel):
    """Trust-boundary metadata attached to derived fraud-intelligence signals."""

    source: IntelligenceSource
    scope: IntelligenceScope
    observed_at: datetime
    source_version: str = Field(min_length=1)
    confidence: RiskScore = 1.0

    @model_validator(mode="after")
    def validate_source_scope(self) -> SignalProvenance:
        authorized_sources = {
            IntelligenceSource.AUTHORIZED_RAIL,
            IntelligenceSource.AUTHORIZED_CONSORTIUM,
            IntelligenceSource.AUTHORIZED_SHARED,
        }
        if self.scope == IntelligenceScope.AUTHORIZED_SHARED:
            if self.source not in authorized_sources:
                raise ValueError(
                    "authorized_shared scope requires an explicitly authorized source"
                )
        elif self.source in authorized_sources:
            raise ValueError(
                "authorized sources must use authorized_shared scope"
            )
        return self


class IntelligenceEvidence(BaseModel):
    reason_code: str = Field(min_length=1)
    provenance: SignalProvenance
