from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gasha.journey.events import (
    AuthenticationSubtype,
    BeneficiarySubtype,
    JourneyEvent,
    JourneyEventKind,
)

T0 = datetime(2026, 2, 20, 9, 0, 0, tzinfo=UTC)


def event(**kwargs) -> JourneyEvent:
    defaults = {
        "tenant_id": "tenant-a",
        "event_id": uuid4(),
        "kind": JourneyEventKind.AUTHENTICATION,
        "subtype": AuthenticationSubtype.LOGIN_FAILED.value,
        "occurred_at": T0,
        "customer_id": "synthetic-customer",
        "correlation_id": "synthetic-corr",
    }
    return JourneyEvent(**(defaults | kwargs))


def test_authentication_event_minimal_shape() -> None:
    e = event()
    assert e.schema_version == "journey-event-1"
    assert e.received_at is None
    assert e.session_id is None


def test_subtype_must_match_kind() -> None:
    with pytest.raises(ValidationError):
        event(subtype=BeneficiarySubtype.CREATED.value)


def test_beneficiary_events_require_beneficiary_id() -> None:
    with pytest.raises(ValidationError):
        event(
            kind=JourneyEventKind.BENEFICIARY,
            subtype=BeneficiarySubtype.CREATED.value,
        )
    ok = event(
        kind=JourneyEventKind.BENEFICIARY,
        subtype=BeneficiarySubtype.CREATED.value,
        beneficiary_id="synthetic-beneficiary",
    )
    assert ok.beneficiary_id == "synthetic-beneficiary"


def test_device_session_events_require_device_id() -> None:
    with pytest.raises(ValidationError):
        event(
            kind=JourneyEventKind.DEVICE_SESSION,
            subtype="session_started",
        )


def test_occurred_and_received_are_distinct() -> None:
    late = T0
    e = event(occurred_at=T0, received_at=T0.replace(hour=12))
    assert e.occurred_at == late
    assert e.received_at is not None and e.received_at > e.occurred_at


def test_optional_fields_stay_optional() -> None:
    e = event(account_id=None, session_id=None, device_id=None)
    assert e.account_id is None
