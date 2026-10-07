from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from gasha.journey.detector import JourneyDetector
from gasha.journey.events import (
    AuthenticationSubtype,
    BeneficiarySubtype,
    DeviceSessionSubtype,
    JourneyEvent,
    JourneyEventKind,
    TransactionSubtype,
)
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.repository import InMemoryJourneyEventRepository

T0 = datetime(2026, 2, 20, 9, 0, 0, tzinfo=UTC)


def ev(
    kind: JourneyEventKind,
    subtype: str,
    *,
    minutes_ago: float,
    customer_id: str = "synthetic-customer",
    **kwargs,
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id="tenant-a",
        event_id=uuid4(),
        kind=kind,
        subtype=subtype,
        occurred_at=T0 - timedelta(minutes=minutes_ago),
        customer_id=customer_id,
        **kwargs,
    )


def auth(subtype: AuthenticationSubtype, minutes_ago: float, **kw):
    return ev(
        JourneyEventKind.AUTHENTICATION, subtype.value,
        minutes_ago=minutes_ago, **kw,
    )


def device(subtype: DeviceSessionSubtype, minutes_ago: float, **kw):
    return ev(
        JourneyEventKind.DEVICE_SESSION, subtype.value,
        minutes_ago=minutes_ago, device_id="sim-device", **kw,
    )


def security(subtype: str, minutes_ago: float, **kw):
    return ev(
        JourneyEventKind.ACCOUNT_SECURITY, subtype,
        minutes_ago=minutes_ago, **kw,
    )


def beneficiary(minutes_ago: float, **kw):
    return ev(
        JourneyEventKind.BENEFICIARY,
        BeneficiarySubtype.CREATED.value,
        minutes_ago=minutes_ago,
        beneficiary_id="sim-beneficiary",
        **kw,
    )


def payment(minutes_ago: float, **kw):
    return ev(
        JourneyEventKind.TRANSACTION,
        TransactionSubtype.PAYMENT_ATTEMPTED.value,
        minutes_ago=minutes_ago,
        **kw,
    )


def detector(events, policy=None, customer_id="synthetic-customer"):
    repo = InMemoryJourneyEventRepository()
    for e in events:
        repo.append(e)
    return (
        JourneyDetector(
            repo,
            policy
            or JourneyRiskPolicy(
                configuration_version="journey-config-1",
                policy_version="journey-1",
            ),
        ).assess("tenant-a", customer_id, as_of=T0),
        repo,
    )


def test_pattern_a_ato_sequence() -> None:
    assessment, _ = detector(
        [
            auth(AuthenticationSubtype.LOGIN_FAILED, 25),
            auth(AuthenticationSubtype.LOGIN_FAILED, 20),
            auth(AuthenticationSubtype.LOGIN_SUCCESS, 15),
            device(DeviceSessionSubtype.NEW_DEVICE_OBSERVED, 12),
            payment(3),
        ]
    )
    assert "RECENT_AUTHENTICATION_FAILURES" in assessment.reason_codes
    assert "SUCCESS_AFTER_AUTH_FAILURES" in assessment.reason_codes
    assert "RECENT_NEW_DEVICE" in assessment.reason_codes
    assert "NEW_DEVICE_BEFORE_PAYMENT" in assessment.reason_codes
    assert "MULTI_EVENT_ATO_PATTERN" in assessment.reason_codes
    assert assessment.journey_risk >= 0.85
    assert assessment.contributing_events
    assert assessment.policy_version == "journey-1"


def test_pattern_b_device_credential_beneficiary_payment() -> None:
    assessment, _ = detector(
        [
            device(DeviceSessionSubtype.NEW_DEVICE_OBSERVED, 120),
            security("credential_changed", 90),
            beneficiary(60),
            payment(30),
        ]
    )
    assert "RECENT_CREDENTIAL_CHANGE" in assessment.reason_codes
    assert "RECENT_BENEFICIARY_CREATION" in assessment.reason_codes
    assert (
        "PAYMENT_SOON_AFTER_BENEFICIARY_CREATION"
        in assessment.reason_codes
    )
    assert "MULTI_EVENT_ATO_PATTERN" in assessment.reason_codes


def test_pattern_c_profile_change_then_beneficiary_then_payment() -> None:
    assessment, _ = detector(
        [
            security("profile_changed", 90),
            beneficiary(45),
            payment(30),
        ]
    )
    assert "RECENT_SECURITY_PROFILE_CHANGE" in assessment.reason_codes
    assert (
        "PAYMENT_SOON_AFTER_BENEFICIARY_CREATION"
        in assessment.reason_codes
    )
    assert "MULTI_EVENT_ATO_PATTERN" in assessment.reason_codes
    assert assessment.journey_risk >= 0.60


def test_pattern_d_new_device_new_beneficiary_payment() -> None:
    assessment, _ = detector(
        [
            device(DeviceSessionSubtype.NEW_DEVICE_OBSERVED, 50),
            beneficiary(40),
            payment(10),
        ]
    )
    assert "MULTI_EVENT_ATO_PATTERN" in assessment.reason_codes
    assert "NEW_DEVICE_BEFORE_PAYMENT" in assessment.reason_codes


def test_pattern_f_rapid_beneficiary_then_payment() -> None:
    assessment, _ = detector([beneficiary(20), payment(15)])
    assert (
        "PAYMENT_SOON_AFTER_BENEFICIARY_CREATION"
        in assessment.reason_codes
    )
    assert assessment.journey_risk == 0.45  # 0.20 + 0.25, no ATO bonus


def test_legitimate_password_reset_is_low_risk() -> None:
    assessment, _ = detector(
        [
            security("credential_changed", 60),
            payment(55),  # normal payment soon after own reset
        ]
    )
    assert "PAYMENT_SOON_AFTER_CREDENTIAL_CHANGE" in assessment.reason_codes
    # Moderate but not an ATO pattern; well under review threshold.
    assert assessment.journey_risk == 0.45
    assert "MULTI_EVENT_ATO_PATTERN" not in assessment.reason_codes


def test_legitimate_new_phone_login_is_minimal() -> None:
    assessment, _ = detector(
        [device(DeviceSessionSubtype.NEW_DEVICE_OBSERVED, 60)]
    )
    assert assessment.journey_risk == 0.20
    assert assessment.reason_codes == ("RECENT_NEW_DEVICE",)


def test_legitimate_family_beneficiary_then_payment_days_later() -> None:
    # Beneficiary created 50h ago, payment now: inside 72h beneficiary
    # window but outside the 2h soon-after window.
    assessment, _ = detector([beneficiary(3000), payment(5)])
    assert "RECENT_BENEFICIARY_CREATION" in assessment.reason_codes
    assert (
        "PAYMENT_SOON_AFTER_BENEFICIARY_CREATION"
        not in assessment.reason_codes
    )
    assert assessment.journey_risk == 0.20


def test_mistyped_password_single_failure_no_flag() -> None:
    assessment, _ = detector([auth(AuthenticationSubtype.LOGIN_FAILED, 5)])
    assert assessment.journey_risk == 0.0
    assert assessment.reason_codes == ()


def test_empty_history_zero_risk() -> None:
    assessment, _ = detector([])
    assert assessment.journey_risk == 0.0
    assert assessment.contributing_events == ()


def test_contributing_events_are_minimized() -> None:
    assessment, _ = detector(
        [
            auth(AuthenticationSubtype.LOGIN_FAILED, 20),
            auth(AuthenticationSubtype.LOGIN_FAILED, 15),
            auth(AuthenticationSubtype.LOGIN_SUCCESS, 10),
        ]
    )
    for c in assessment.contributing_events:
        dumped = c.__dict__
        assert set(dumped) == {
            "event_id",
            "kind",
            "subtype",
            "occurred_at",
        }


def test_policy_thresholds_are_configurable() -> None:
    strict = JourneyRiskPolicy(
        configuration_version="journey-config-2",
        policy_version="journey-2",
        failed_auth_threshold=3,
    )
    lenient = JourneyRiskPolicy(
        configuration_version="journey-config-1",
        policy_version="journey-1",
    )
    events = [
        auth(AuthenticationSubtype.LOGIN_FAILED, 10),
        auth(AuthenticationSubtype.LOGIN_FAILED, 8),
    ]
    strict_assessment, _ = detector(events, policy=strict)
    lenient_assessment, _ = detector(events, policy=lenient)
    assert "RECENT_AUTHENTICATION_FAILURES" in (
        lenient_assessment.reason_codes
    )
    assert "RECENT_AUTHENTICATION_FAILURES" not in (
        strict_assessment.reason_codes
    )
    assert strict_assessment.policy_version == "journey-2"


def test_missing_telemetry_never_creates_risk() -> None:
    # Only a payment — nothing else known.
    assessment, _ = detector([payment(2)])
    assert assessment.journey_risk == 0.0
