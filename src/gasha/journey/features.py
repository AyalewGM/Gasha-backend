from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from pydantic import BaseModel

from gasha.journey.events import (
    AccountSecuritySubtype,
    AuthenticationSubtype,
    BeneficiarySubtype,
    DeviceSessionSubtype,
    JourneyEvent,
    JourneyEventKind,
    TransactionSubtype,
)
from gasha.journey.repository import JourneyEventRepository


class JourneyWindows(BaseModel):
    """Configurable lookback windows for journey feature computation.

    Defaults are engineering fixtures for synthetic tests, not bank risk
    recommendations — every deployment tunes them per tenant.
    """

    authentication_window: timedelta = timedelta(minutes=30)
    device_session_window: timedelta = timedelta(hours=24)
    account_security_window: timedelta = timedelta(hours=24)
    beneficiary_window: timedelta = timedelta(hours=72)
    transaction_window: timedelta = timedelta(hours=24)


@dataclass(frozen=True)
class JourneyFeatures:
    """Deterministic point-in-time features from journey history.

    Computed only from events with ``occurred_at <= as_of``; future and
    out-of-window events can never influence the result.
    """

    as_of: datetime
    authentication_failures: int = 0
    successful_login_after_failures: bool = False
    new_device: bool = False
    session_anomaly: bool = False
    credential_change: bool = False
    security_profile_change: bool = False
    beneficiary_created: bool = False
    beneficiary_created_at: datetime | None = None
    credential_changed_at: datetime | None = None
    new_device_at: datetime | None = None
    payment_attempts: int = 0
    payment_attempted_after_beneficiary: bool = False
    events: tuple[JourneyEvent, ...] = field(default_factory=tuple)


class JourneyFeatureBuilder:
    """Builds journey features from a tenant-scoped event repository."""

    def __init__(self, repository: JourneyEventRepository) -> None:
        self._repository = repository

    def build(
        self,
        tenant_id: str,
        customer_id: str,
        *,
        as_of: datetime,
        windows: JourneyWindows,
    ) -> JourneyFeatures:
        earliest = as_of - max(
            windows.authentication_window,
            windows.device_session_window,
            windows.account_security_window,
            windows.beneficiary_window,
            windows.transaction_window,
        )
        events = self._repository.recent(
            tenant_id, customer_id, as_of=as_of, since=earliest
        )
        return _compute(events, as_of=as_of, windows=windows)


def _compute(
    events: tuple[JourneyEvent, ...],
    *,
    as_of: datetime,
    windows: JourneyWindows,
) -> JourneyFeatures:
    failures = 0
    success_after_failures = False
    beneficiary_created_at: datetime | None = None
    credential_changed_at: datetime | None = None
    new_device_at: datetime | None = None
    session_anomaly = False
    security_profile_change = False
    payment_attempts = 0
    payment_after_beneficiary = False

    for event in events:  # chronological by occurred_at
        age = as_of - event.occurred_at
        if event.kind == JourneyEventKind.AUTHENTICATION:
            if age > windows.authentication_window:
                continue
            if event.subtype == AuthenticationSubtype.LOGIN_FAILED:
                failures += 1
            elif (
                event.subtype == AuthenticationSubtype.LOGIN_SUCCESS
                and failures > 0
            ):
                success_after_failures = True
        elif event.kind == JourneyEventKind.DEVICE_SESSION:
            if age > windows.device_session_window:
                continue
            if event.subtype == DeviceSessionSubtype.NEW_DEVICE_OBSERVED:
                new_device_at = event.occurred_at
            elif event.subtype == DeviceSessionSubtype.SESSION_ANOMALY:
                session_anomaly = True
        elif event.kind == JourneyEventKind.ACCOUNT_SECURITY:
            if age > windows.account_security_window:
                continue
            if event.subtype == AccountSecuritySubtype.CREDENTIAL_CHANGED:
                credential_changed_at = event.occurred_at
            elif event.subtype in (
                AccountSecuritySubtype.SECURITY_SETTING_CHANGED,
                AccountSecuritySubtype.PROFILE_CHANGED,
            ):
                security_profile_change = True
        elif event.kind == JourneyEventKind.BENEFICIARY:
            if age > windows.beneficiary_window:
                continue
            if event.subtype == BeneficiarySubtype.CREATED:
                beneficiary_created_at = event.occurred_at
        elif event.kind == JourneyEventKind.TRANSACTION:
            if age > windows.transaction_window:
                continue
            if event.subtype == TransactionSubtype.PAYMENT_ATTEMPTED:
                payment_attempts += 1
                if (
                    beneficiary_created_at
                    and event.occurred_at > beneficiary_created_at
                ):
                    payment_after_beneficiary = True

    return JourneyFeatures(
        as_of=as_of,
        authentication_failures=failures,
        successful_login_after_failures=success_after_failures,
        new_device=new_device_at is not None,
        session_anomaly=session_anomaly,
        credential_change=credential_changed_at is not None,
        security_profile_change=security_profile_change,
        beneficiary_created=beneficiary_created_at is not None,
        beneficiary_created_at=beneficiary_created_at,
        credential_changed_at=credential_changed_at,
        new_device_at=new_device_at,
        payment_attempts=payment_attempts,
        payment_attempted_after_beneficiary=payment_after_beneficiary,
        events=events,
    )
