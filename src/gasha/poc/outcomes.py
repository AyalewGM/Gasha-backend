from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class OutcomeType(StrEnum):
    """Normalized, versionable confirmed-outcome vocabulary.

    Outcomes arrive after the original decision (T0 decision, T1 outcome) and
    are appended as records; they never mutate the stored decision.
    """

    CONFIRMED_FRAUD = "confirmed_fraud"
    CUSTOMER_REPORTED_SCAM = "customer_reported_scam"
    INVESTIGATOR_CONFIRMED_FRAUD = "investigator_confirmed_fraud"
    CHARGEBACK_DISPUTE = "chargeback_dispute"
    BANK_CONFIRMED_FALSE_POSITIVE = "bank_confirmed_false_positive"
    CONFIRMED_LEGITIMATE = "confirmed_legitimate"
    UNRESOLVED = "unresolved"


_FRAUD_OUTCOMES = frozenset(
    {
        OutcomeType.CONFIRMED_FRAUD,
        OutcomeType.CUSTOMER_REPORTED_SCAM,
        OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD,
        OutcomeType.CHARGEBACK_DISPUTE,
    }
)
_LEGITIMATE_OUTCOMES = frozenset(
    {
        OutcomeType.CONFIRMED_LEGITIMATE,
        OutcomeType.BANK_CONFIRMED_FALSE_POSITIVE,
    }
)


class OutcomeRecord(BaseModel):
    """A confirmed outcome attached to a prior tenant-scoped decision.

    ``is_fraud`` is derived: fraud outcomes map to True, legitimate outcomes to
    False, and UNRESOLVED to None so unresolved cases are never silently
    treated as legitimate in POC metrics.
    """

    tenant_id: str = Field(min_length=1)
    event_id: UUID
    outcome: OutcomeType
    outcome_source: str = Field(min_length=1)
    outcome_version: str = Field(min_length=1)
    confirmed_at: datetime | None = None

    @property
    def is_fraud(self) -> bool | None:
        if self.outcome in _FRAUD_OUTCOMES:
            return True
        if self.outcome in _LEGITIMATE_OUTCOMES:
            return False
        return None


class IncumbentControlOutcome(StrEnum):
    """Provider-neutral normalized outcome of a bank's existing controls.

    Bank/vendor-specific outcome names are mapped into this vocabulary by
    adapter-layer integrations; the core never depends on a vendor name.
    """

    NO_ALERT = "no_alert"
    ALERT = "alert"
    REVIEW = "review"
    CHALLENGE = "challenge"
    HOLD = "hold"
    BLOCK = "block"

    @property
    def alerted(self) -> bool:
        return self is not IncumbentControlOutcome.NO_ALERT
