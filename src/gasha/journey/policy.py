from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, Field

from gasha.domain.models import RiskScore
from gasha.journey.features import JourneyWindows


class JourneyRiskPolicy(BaseModel):
    """Versioned, tenant-configurable journey risk policy.

    Every threshold and every risk contribution is configuration — nothing
    is hidden in detector code. The bundled defaults are engineering
    fixtures for synthetic tests, not bank risk recommendations.
    """

    configuration_version: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    windows: JourneyWindows = JourneyWindows()

    # Counts and timing thresholds
    failed_auth_threshold: int = Field(default=2, ge=1)
    payment_count_threshold: int = Field(default=2, ge=1)
    payment_after_beneficiary_window: timedelta = timedelta(hours=2)
    payment_after_credential_window: timedelta = timedelta(hours=2)
    multi_indicator_threshold: int = Field(default=3, ge=2)

    # Per-indicator risk contributions
    auth_failures_risk: RiskScore = 0.15
    success_after_failures_risk: RiskScore = 0.20
    new_device_risk: RiskScore = 0.20
    session_anomaly_risk: RiskScore = 0.20
    credential_change_risk: RiskScore = 0.20
    security_profile_change_risk: RiskScore = 0.15
    beneficiary_creation_risk: RiskScore = 0.20
    payment_soon_after_beneficiary_risk: RiskScore = 0.25
    payment_soon_after_credential_risk: RiskScore = 0.25
    new_device_before_payment_risk: RiskScore = 0.15

    # Combination bonus when an ATO-style sequence pattern matches
    ato_pattern_risk: RiskScore = 0.30
