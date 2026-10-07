from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class JourneyEventKind(StrEnum):
    """Canonical non-transaction event categories for UC-03 journeys.

    Banks may supply any subset; missing categories simply yield no
    journey signal — absence is never itself suspicious.
    """

    AUTHENTICATION = "authentication"
    DEVICE_SESSION = "device_session"
    ACCOUNT_SECURITY = "account_security"
    BENEFICIARY = "beneficiary"
    TRANSACTION = "transaction"


class AuthenticationSubtype(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"


class DeviceSessionSubtype(StrEnum):
    SESSION_STARTED = "session_started"
    NEW_DEVICE_OBSERVED = "new_device_observed"
    SESSION_ANOMALY = "session_anomaly"
    DEVICE_RISK_CHANGE = "device_risk_change"


class AccountSecuritySubtype(StrEnum):
    CREDENTIAL_CHANGED = "credential_changed"
    SECURITY_SETTING_CHANGED = "security_setting_changed"
    PROFILE_CHANGED = "profile_changed"


class BeneficiarySubtype(StrEnum):
    CREATED = "beneficiary_created"
    MODIFIED = "beneficiary_modified"
    ACTIVATED = "beneficiary_activated"


class TransactionSubtype(StrEnum):
    PAYMENT_ATTEMPTED = "payment_attempted"
    PAYMENT_COMPLETED = "payment_completed"


_SUBTYPES: dict[JourneyEventKind, tuple[StrEnum, ...]] = {
    JourneyEventKind.AUTHENTICATION: tuple(AuthenticationSubtype),
    JourneyEventKind.DEVICE_SESSION: tuple(DeviceSessionSubtype),
    JourneyEventKind.ACCOUNT_SECURITY: tuple(AccountSecuritySubtype),
    JourneyEventKind.BENEFICIARY: tuple(BeneficiarySubtype),
    JourneyEventKind.TRANSACTION: tuple(TransactionSubtype),
}

_KIND_REQUIRED_FIELDS: dict[JourneyEventKind, tuple[str, ...]] = {
    JourneyEventKind.AUTHENTICATION: (),
    JourneyEventKind.DEVICE_SESSION: ("device_id",),
    JourneyEventKind.ACCOUNT_SECURITY: (),
    JourneyEventKind.BENEFICIARY: ("beneficiary_id",),
    JourneyEventKind.TRANSACTION: (),
}

JOURNEY_EVENT_SCHEMA_VERSION = "journey-event-1"


class JourneyEvent(BaseModel):
    """A canonical point-in-time event in a customer's journey.

    ``occurred_at`` is business time; ``received_at`` is arrival time —
    they are deliberately distinct so out-of-order delivery is explicit
    and testable. Only identifiers relevant to the event kind are
    required; optional fields stay optional.
    """

    schema_version: str = Field(
        default=JOURNEY_EVENT_SCHEMA_VERSION, min_length=1
    )
    tenant_id: str = Field(min_length=1)
    event_id: UUID
    kind: JourneyEventKind
    subtype: str = Field(min_length=1)
    occurred_at: datetime
    received_at: datetime | None = None
    correlation_id: str | None = None
    customer_id: str = Field(min_length=1)
    account_id: str | None = None
    session_id: str | None = None
    device_id: str | None = None
    beneficiary_id: str | None = None

    @model_validator(mode="after")
    def validate_subtype_and_refs(self) -> JourneyEvent:
        valid = {member.value for member in _SUBTYPES[self.kind]}
        if self.subtype not in valid:
            raise ValueError(
                f"subtype {self.subtype!r} invalid for "
                f"kind {self.kind.value!r}"
            )
        for field in _KIND_REQUIRED_FIELDS[self.kind]:
            if not getattr(self, field):
                raise ValueError(
                    f"{self.kind.value} events require {field}"
                )
        return self
