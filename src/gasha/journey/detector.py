from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from gasha.journey.events import (
    AccountSecuritySubtype,
    AuthenticationSubtype,
    BeneficiarySubtype,
    DeviceSessionSubtype,
    JourneyEvent,
    JourneyEventKind,
    TransactionSubtype,
)
from gasha.journey.features import (
    JourneyFeatureBuilder,
    JourneyFeatures,
)
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.repository import JourneyEventRepository


@dataclass(frozen=True)
class ContributingEvent:
    """Minimized evidence pointer for a contributing journey event.

    Carries identifiers and timestamps only — never raw payloads or PII.
    """

    event_id: UUID
    kind: str
    subtype: str
    occurred_at: datetime


@dataclass(frozen=True)
class JourneyAssessment:
    """Deterministic journey risk with explainable evidence."""

    tenant_id: str
    customer_id: str
    as_of: datetime
    journey_risk: float
    reason_codes: tuple[str, ...]
    contributing_events: tuple[ContributingEvent, ...]
    configuration_version: str
    policy_version: str


@dataclass
class _Accumulator:
    risk: float = 0.0
    reasons: list[str] = field(default_factory=list)
    events: list[JourneyEvent] = field(default_factory=list)

    def add(
        self, risk: float, reason: str, events: list[JourneyEvent]
    ) -> None:
        self.risk += risk
        self.reasons.append(reason)
        self.events.extend(events)


def _of_kind(
    events: tuple[JourneyEvent, ...] | list[JourneyEvent],
    kind: JourneyEventKind,
) -> list[JourneyEvent]:
    return [e for e in events if e.kind == kind]


def _of_subtype(
    events: tuple[JourneyEvent, ...] | list[JourneyEvent], subtype: str
) -> list[JourneyEvent]:
    return [e for e in events if e.subtype == subtype]


class JourneyDetector:
    """Deterministic UC-03 sequence detector over journey features.

    Missing telemetry contributes nothing and is never penalized; each
    fired indicator maps to a reason code plus the contributing events.
    ATO combination patterns add a configurable bonus when a sequence
    (failures -> login -> device -> beneficiary -> payment, etc.) is
    materially stronger than its parts.
    """

    def __init__(
        self,
        repository: JourneyEventRepository,
        policy: JourneyRiskPolicy,
    ) -> None:
        self._builder = JourneyFeatureBuilder(repository)
        self._policy = policy

    @property
    def policy(self) -> JourneyRiskPolicy:
        return self._policy

    def assess(
        self,
        tenant_id: str,
        customer_id: str,
        *,
        as_of: datetime,
    ) -> JourneyAssessment:
        features = self._builder.build(
            tenant_id,
            customer_id,
            as_of=as_of,
            windows=self._policy.windows,
        )
        acc = self._score(features)
        return JourneyAssessment(
            tenant_id=tenant_id,
            customer_id=customer_id,
            as_of=as_of,
            journey_risk=min(acc.risk, 1.0),
            reason_codes=tuple(dict.fromkeys(acc.reasons)),
            contributing_events=tuple(
                ContributingEvent(
                    event_id=e.event_id,
                    kind=e.kind.value,
                    subtype=e.subtype,
                    occurred_at=e.occurred_at,
                )
                for e in {
                    event.event_id: event for event in acc.events
                }.values()
            ),
            configuration_version=self._policy.configuration_version,
            policy_version=self._policy.policy_version,
        )

    def _score(self, f: JourneyFeatures) -> _Accumulator:
        p = self._policy
        acc = _Accumulator()
        events = f.events

        auth_events = _of_kind(events, JourneyEventKind.AUTHENTICATION)
        device_events = _of_kind(events, JourneyEventKind.DEVICE_SESSION)
        security_events = _of_kind(
            events, JourneyEventKind.ACCOUNT_SECURITY
        )
        beneficiary_events = _of_kind(events, JourneyEventKind.BENEFICIARY)
        payment_events = _of_subtype(
            _of_kind(events, JourneyEventKind.TRANSACTION),
            TransactionSubtype.PAYMENT_ATTEMPTED.value,
        )

        if f.authentication_failures >= p.failed_auth_threshold:
            acc.add(
                p.auth_failures_risk,
                "RECENT_AUTHENTICATION_FAILURES",
                _of_subtype(
                    auth_events, AuthenticationSubtype.LOGIN_FAILED.value
                ),
            )
        if f.successful_login_after_failures:
            acc.add(
                p.success_after_failures_risk,
                "SUCCESS_AFTER_AUTH_FAILURES",
                auth_events,
            )
        if f.new_device:
            acc.add(
                p.new_device_risk,
                "RECENT_NEW_DEVICE",
                _of_subtype(
                    device_events,
                    DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
                ),
            )
        if f.session_anomaly:
            acc.add(
                p.session_anomaly_risk,
                "RECENT_SESSION_ANOMALY",
                _of_subtype(
                    device_events,
                    DeviceSessionSubtype.SESSION_ANOMALY.value,
                ),
            )
        if f.credential_change:
            acc.add(
                p.credential_change_risk,
                "RECENT_CREDENTIAL_CHANGE",
                _of_subtype(
                    security_events,
                    AccountSecuritySubtype.CREDENTIAL_CHANGED.value,
                ),
            )
        if f.security_profile_change:
            acc.add(
                p.security_profile_change_risk,
                "RECENT_SECURITY_PROFILE_CHANGE",
                _of_subtype(
                    security_events,
                    AccountSecuritySubtype.PROFILE_CHANGED.value,
                )
                + _of_subtype(
                    security_events,
                    AccountSecuritySubtype.SECURITY_SETTING_CHANGED.value,
                ),
            )
        if f.beneficiary_created:
            acc.add(
                p.beneficiary_creation_risk,
                "RECENT_BENEFICIARY_CREATION",
                _of_subtype(
                    beneficiary_events,
                    BeneficiarySubtype.CREATED.value,
                ),
            )

        payment_soon_after_beneficiary = (
            f.beneficiary_created_at is not None
            and any(
                _ZERO
                < (pay.occurred_at - f.beneficiary_created_at)
                <= p.payment_after_beneficiary_window
                for pay in payment_events
            )
        )
        if payment_soon_after_beneficiary:
            acc.add(
                p.payment_soon_after_beneficiary_risk,
                "PAYMENT_SOON_AFTER_BENEFICIARY_CREATION",
                beneficiary_events + payment_events,
            )

        payment_soon_after_credential = (
            f.credential_changed_at is not None
            and any(
                _ZERO
                < (pay.occurred_at - f.credential_changed_at)
                <= p.payment_after_credential_window
                for pay in payment_events
            )
        )
        if payment_soon_after_credential:
            acc.add(
                p.payment_soon_after_credential_risk,
                "PAYMENT_SOON_AFTER_CREDENTIAL_CHANGE",
                security_events + payment_events,
            )

        new_device_before_payment = f.new_device_at is not None and any(
            pay.occurred_at > f.new_device_at for pay in payment_events
        )
        if new_device_before_payment:
            acc.add(
                p.new_device_before_payment_risk,
                "NEW_DEVICE_BEFORE_PAYMENT",
                device_events + payment_events,
            )

        if self._ato_pattern(f, payment_soon_after_beneficiary):
            acc.add(
                p.ato_pattern_risk,
                "MULTI_EVENT_ATO_PATTERN",
                list(events),
            )
        return acc

    def _ato_pattern(
        self, f: JourneyFeatures, payment_soon_after_beneficiary: bool
    ) -> bool:
        """ATO-sequence patterns (spec WP5 A–F), all configurable-weighted."""

        pattern_a = (
            f.authentication_failures >= self._policy.failed_auth_threshold
            and f.successful_login_after_failures
            and (f.new_device or f.session_anomaly)
            and f.payment_attempts >= 1
        )
        pattern_b = (
            f.new_device
            and f.credential_change
            and f.beneficiary_created
            and f.payment_attempted_after_beneficiary
        )
        pattern_c = (
            (f.credential_change or f.security_profile_change)
            and f.beneficiary_created
            and payment_soon_after_beneficiary
        )
        pattern_d = (
            f.new_device
            and f.beneficiary_created
            and f.payment_attempted_after_beneficiary
        )
        pattern_e = (
            sum(
                [
                    f.authentication_failures
                    >= self._policy.failed_auth_threshold,
                    f.successful_login_after_failures,
                    f.new_device,
                    f.session_anomaly,
                    f.credential_change,
                    f.security_profile_change,
                    f.beneficiary_created,
                    f.payment_attempted_after_beneficiary,
                ]
            )
            >= self._policy.multi_indicator_threshold
            and f.payment_attempts >= 1
        )
        return any(
            (pattern_a, pattern_b, pattern_c, pattern_d, pattern_e)
        )


from datetime import timedelta as _td

_ZERO = _td(0)

_ZERO = timedelta(0)
