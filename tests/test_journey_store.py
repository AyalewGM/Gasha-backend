from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from gasha.journey.events import (
    AuthenticationSubtype,
    BeneficiarySubtype,
    DeviceSessionSubtype,
    JourneyEvent,
    JourneyEventKind,
    TransactionSubtype,
)
from gasha.journey.features import (
    JourneyFeatureBuilder,
    JourneyWindows,
)
from gasha.journey.repository import InMemoryJourneyEventRepository

T0 = datetime(2026, 2, 20, 9, 0, 0, tzinfo=UTC)


def event(
    kind: JourneyEventKind,
    subtype: str,
    *,
    minutes_ago: float,
    tenant_id: str = "tenant-a",
    customer_id: str = "synthetic-customer",
    **kwargs,
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id=tenant_id,
        event_id=uuid4(),
        kind=kind,
        subtype=subtype,
        occurred_at=T0 - timedelta(minutes=minutes_ago),
        customer_id=customer_id,
        **kwargs,
    )


def build(events, *, customer_id="synthetic-customer", as_of=T0):
    repo = InMemoryJourneyEventRepository()
    for e in events:
        repo.append(e)
    return JourneyFeatureBuilder(repo).build(
        "tenant-a", customer_id, as_of=as_of, windows=JourneyWindows()
    )


def test_failed_logins_then_success() -> None:
    f = build(
        [
            event(
                JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                minutes_ago=12,
            ),
            event(
                JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                minutes_ago=10,
            ),
            event(
                JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_SUCCESS.value,
                minutes_ago=5,
            ),
        ]
    )
    assert f.authentication_failures == 2
    assert f.successful_login_after_failures is True


def test_success_without_prior_failures_not_flagged() -> None:
    f = build(
        [
            event(
                JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                minutes_ago=90,  # outside 30m auth window
            ),
            event(
                JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_SUCCESS.value,
                minutes_ago=5,
            ),
        ]
    )
    assert f.authentication_failures == 0
    assert f.successful_login_after_failures is False


def test_point_in_time_no_lookahead() -> None:
    repo = InMemoryJourneyEventRepository()
    past = event(
        JourneyEventKind.BENEFICIARY,
        BeneficiarySubtype.CREATED.value,
        minutes_ago=10,
        beneficiary_id="b1",
    )
    repo.append(past)

    before = JourneyFeatureBuilder(repo).build(
        "tenant-a",
        "synthetic-customer",
        as_of=T0,
        windows=JourneyWindows(),
    )
    assert before.beneficiary_created is True
    assert before.beneficiary_created_at == past.occurred_at

    # A FUTURE event appended later must not change the T0 evaluation.
    future = event(
        JourneyEventKind.ACCOUNT_SECURITY,
        "credential_changed",
        minutes_ago=-60,  # occurs after T0
    )
    repo.append(future)
    after = JourneyFeatureBuilder(repo).build(
        "tenant-a",
        "synthetic-customer",
        as_of=T0,
        windows=JourneyWindows(),
    )
    assert after.credential_change is False
    assert after == before


def test_out_of_order_arrival_sorted_by_occurred_at() -> None:
    repo = InMemoryJourneyEventRepository()
    # Arrived out of order: beneficiary created first in business time,
    # appended last.
    payment = event(
        JourneyEventKind.TRANSACTION,
        TransactionSubtype.PAYMENT_ATTEMPTED.value,
        minutes_ago=5,
    )
    beneficiary = event(
        JourneyEventKind.BENEFICIARY,
        BeneficiarySubtype.CREATED.value,
        minutes_ago=20,
        beneficiary_id="b1",
    )
    repo.append(payment)
    repo.append(beneficiary)

    f = JourneyFeatureBuilder(repo).build(
        "tenant-a",
        "synthetic-customer",
        as_of=T0,
        windows=JourneyWindows(),
    )
    assert f.payment_attempted_after_beneficiary is True
    # Ordering is by occurred_at, not arrival order.
    assert [e.kind for e in f.events] == [
        JourneyEventKind.BENEFICIARY,
        JourneyEventKind.TRANSACTION,
    ]


def test_payment_before_beneficiary_does_not_flag_sequence() -> None:
    f = build(
        [
            event(
                JourneyEventKind.TRANSACTION,
                TransactionSubtype.PAYMENT_ATTEMPTED.value,
                minutes_ago=30,
            ),
            event(
                JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                minutes_ago=10,
                beneficiary_id="b1",
            ),
        ]
    )
    assert f.beneficiary_created is True
    assert f.payment_attempted_after_beneficiary is False


def test_tenant_isolation() -> None:
    repo = InMemoryJourneyEventRepository()
    repo.append(
        event(
            JourneyEventKind.BENEFICIARY,
            BeneficiarySubtype.CREATED.value,
            minutes_ago=10,
            tenant_id="tenant-b",
            beneficiary_id="b1",
        )
    )
    f = JourneyFeatureBuilder(repo).build(
        "tenant-a",
        "synthetic-customer",
        as_of=T0,
        windows=JourneyWindows(),
    )
    assert f.events == ()
    assert f.beneficiary_created is False


def test_customer_isolation() -> None:
    repo = InMemoryJourneyEventRepository()
    repo.append(
        event(
            JourneyEventKind.BENEFICIARY,
            BeneficiarySubtype.CREATED.value,
            minutes_ago=10,
            customer_id="other-customer",
            beneficiary_id="b1",
        )
    )
    f = JourneyFeatureBuilder(repo).build(
        "tenant-a",
        "synthetic-customer",
        as_of=T0,
        windows=JourneyWindows(),
    )
    assert f.events == ()


def test_duplicate_append_is_ignored() -> None:
    repo = InMemoryJourneyEventRepository()
    e = event(
        JourneyEventKind.AUTHENTICATION,
        AuthenticationSubtype.LOGIN_FAILED.value,
        minutes_ago=5,
    )
    assert repo.append(e) is True
    assert repo.append(e) is False
    assert (
        len(
            repo.recent(
                "tenant-a",
                "synthetic-customer",
                as_of=T0,
                since=T0 - timedelta(hours=1),
            )
        )
        == 1
    )


def test_new_device_and_credential_change_features() -> None:
    f = build(
        [
            event(
                JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
                minutes_ago=40,
                device_id="device-x",
            ),
            event(
                JourneyEventKind.ACCOUNT_SECURITY,
                "credential_changed",
                minutes_ago=30,
            ),
            event(
                JourneyEventKind.ACCOUNT_SECURITY,
                "profile_changed",
                minutes_ago=25,
            ),
            event(
                JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.SESSION_ANOMALY.value,
                minutes_ago=8,
                device_id="device-x",
            ),
        ]
    )
    assert f.new_device and f.new_device_at is not None
    assert f.credential_change and f.credential_changed_at is not None
    assert f.security_profile_change is True
    assert f.session_anomaly is True
