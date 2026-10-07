from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import NAMESPACE_URL, uuid5

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.journey.events import (
    AuthenticationSubtype,
    BeneficiarySubtype,
    DeviceSessionSubtype,
    JourneyEvent,
    JourneyEventKind,
    TransactionSubtype,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
)
from gasha.poc.journey_replay import JourneyReplayItem

JOURNEY_CAMPAIGN_BASE = datetime(2026, 2, 21, 9, 0, 0, tzinfo=UTC)


def _jevent(
    scenario: str,
    name: str,
    kind: JourneyEventKind,
    subtype: str,
    *,
    tenant_id: str,
    customer_id: str,
    at: datetime,
    session_id: str | None = None,
    device_id: str | None = None,
    beneficiary_id: str | None = None,
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id=tenant_id,
        event_id=uuid5(NAMESPACE_URL, f"gasha://uc3/{scenario}/{name}"),
        kind=kind,
        subtype=subtype,
        occurred_at=at,
        customer_id=customer_id,
        session_id=session_id,
        device_id=device_id,
        beneficiary_id=beneficiary_id,
        correlation_id=f"uc3-{scenario}",
    )


def _payment_event(
    scenario: str, tenant_id: str, customer_id: str, at: datetime
) -> JourneyEvent:
    return _jevent(
        scenario,
        "payment-attempted",
        JourneyEventKind.TRANSACTION,
        TransactionSubtype.PAYMENT_ATTEMPTED.value,
        tenant_id=tenant_id,
        customer_id=customer_id,
        at=at - timedelta(seconds=30),
    )


def _payment(
    scenario: str,
    tenant_id: str,
    customer_id: str,
    at: datetime,
    *,
    amount: str,
    is_fraud: bool,
    intelligence: IntelligenceSnapshot | None = None,
) -> HistoricalTransactionEvent:
    transaction = CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid5(
            NAMESPACE_URL, f"gasha://uc3/{scenario}/transaction"
        ),
        occurred_at=at,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(amount),
        currency="ETB",
        sender_customer_id=customer_id,
        sender_account_id=f"sim-account-{scenario}",
        beneficiary_id=f"sim-beneficiary-{scenario}",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="sim-destination",
        correlation_id=f"uc3-{scenario}",
    )
    return HistoricalTransactionEvent(
        transaction=transaction,
        intelligence=intelligence or IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(
            is_fraud=is_fraud, label_source="synthetic-uc3-campaign"
        ),
    )


def uc3_journey_campaign(
    *,
    tenant_id: str = "tenant-a",
    base_time: datetime = JOURNEY_CAMPAIGN_BASE,
) -> tuple[JourneyReplayItem, ...]:
    """Deterministic UC-03 multi-event campaign.

    Six fraud/legitimate scenarios with deliberately ambiguous signal
    levels — not every ATO pattern is detectable and legitimate account
    changes stay below alerting territory.
    """

    t = base_time
    items: list[JourneyReplayItem] = []

    def at(minutes: int) -> datetime:
        return t + timedelta(minutes=minutes)

    def add(*events: JourneyReplayItem) -> None:
        items.extend(events)

    # Scenario 1 — full ATO: failures -> login -> new device ->
    # credential change -> beneficiary -> payment.
    c = "sim-ato-full"
    add(
        _jevent("ato-full", "f1", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-140)),
        _jevent("ato-full", "f2", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-135)),
        _jevent("ato-full", "ok", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_SUCCESS.value,
                tenant_id=tenant_id, customer_id=c, at=at(-120)),
        _jevent("ato-full", "dev", JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-100),
                device_id="sim-device-ato"),
        _jevent("ato-full", "cred", JourneyEventKind.ACCOUNT_SECURITY,
                "credential_changed",
                tenant_id=tenant_id, customer_id=c, at=at(-80)),
        _jevent("ato-full", "ben", JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-40),
                beneficiary_id="sim-beneficiary-ato-full"),
        _payment_event("ato-full", tenant_id, c, at(-5)),
        _payment("ato-full", tenant_id, c, at(-5),
                 amount="6800.00", is_fraud=True,
                 intelligence=IntelligenceSnapshot(
                     relationship_risk=0.55)),
    )

    # Scenario 2 — device-change takeover: new device -> anomaly ->
    # beneficiary -> payment.
    c = "sim-ato-device"
    add(
        _jevent("ato-device", "dev", JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-90),
                device_id="sim-device-ato2"),
        _jevent("ato-device", "anom", JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.SESSION_ANOMALY.value,
                tenant_id=tenant_id, customer_id=c, at=at(-70),
                device_id="sim-device-ato2"),
        _jevent("ato-device", "ben", JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-30),
                beneficiary_id="sim-beneficiary-ato-device"),
        _payment_event("ato-device", tenant_id, c, at(-4)),
        _payment("ato-device", tenant_id, c, at(-4),
                 amount="5200.00", is_fraud=True,
                 intelligence=IntelligenceSnapshot(
                     relationship_risk=0.50)),
    )

    # Scenario 3 — auth attack -> login -> payment (no device/beneficiary
    # evidence: journey participates but stays moderate).
    c = "sim-ato-auth"
    add(
        _jevent("ato-auth", "f1", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-28)),
        _jevent("ato-auth", "f2", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-24)),
        _jevent("ato-auth", "ok", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_SUCCESS.value,
                tenant_id=tenant_id, customer_id=c, at=at(-20)),
        _payment_event("ato-auth", tenant_id, c, at(-2)),
        _payment("ato-auth", tenant_id, c, at(-2),
                 amount="900.00", is_fraud=True),
    )

    # Scenario 4 — profile change -> beneficiary -> transfer.
    c = "sim-ato-profile"
    add(
        _jevent("ato-profile", "prof",
                JourneyEventKind.ACCOUNT_SECURITY, "profile_changed",
                tenant_id=tenant_id, customer_id=c, at=at(-75)),
        _jevent("ato-profile", "ben", JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-45),
                beneficiary_id="sim-beneficiary-ato-profile"),
        _payment_event("ato-profile", tenant_id, c, at(-6)),
        _payment("ato-profile", tenant_id, c, at(-6),
                 amount="3400.00", is_fraud=True,
                 intelligence=IntelligenceSnapshot(
                     transaction_risk=0.40)),
    )

    # Scenario 5 — new device -> beneficiary -> mule recipient payment.
    c = "sim-ato-mule"
    add(
        _jevent("ato-mule", "dev", JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-55),
                device_id="sim-device-mule"),
        _jevent("ato-mule", "ben", JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-35),
                beneficiary_id="sim-beneficiary-ato-mule"),
        _payment_event("ato-mule", tenant_id, c, at(-3)),
        _payment("ato-mule", tenant_id, c, at(-3),
                 amount="4100.00", is_fraud=True,
                 intelligence=IntelligenceSnapshot(network_risk=0.90)),
    )

    # Legitimate lookalikes ------------------------------------------------
    c = "sim-legit-newphone"
    add(
        _jevent("legit-newphone", "dev",
                JourneyEventKind.DEVICE_SESSION,
                DeviceSessionSubtype.NEW_DEVICE_OBSERVED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-200),
                device_id="sim-device-newphone"),
        _payment_event("legit-newphone", tenant_id, c, at(-1)),
        _payment("legit-newphone", tenant_id, c, at(-1),
                 amount="640.00", is_fraud=False),
    )
    c = "sim-legit-reset"
    add(
        _jevent("legit-reset", "cred",
                JourneyEventKind.ACCOUNT_SECURITY, "credential_changed",
                tenant_id=tenant_id, customer_id=c, at=at(-30)),
        _payment_event("legit-reset", tenant_id, c, at(-1)),
        _payment("legit-reset", tenant_id, c, at(-1),
                 amount="410.00", is_fraud=False),
    )
    c = "sim-legit-family"
    add(
        _jevent("legit-family", "ben", JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                tenant_id=tenant_id, customer_id=c,
                at=at(-3000), beneficiary_id="sim-beneficiary-family"),
        _payment_event("legit-family", tenant_id, c, at(-1)),
        _payment("legit-family", tenant_id, c, at(-1),
                 amount="1200.00", is_fraud=False),
    )
    c = "sim-legit-typo"
    add(
        _jevent("legit-typo", "f1", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_FAILED.value,
                tenant_id=tenant_id, customer_id=c, at=at(-10)),
        _jevent("legit-typo", "ok", JourneyEventKind.AUTHENTICATION,
                AuthenticationSubtype.LOGIN_SUCCESS.value,
                tenant_id=tenant_id, customer_id=c, at=at(-9)),
        _payment_event("legit-typo", tenant_id, c, at(-1)),
        _payment("legit-typo", tenant_id, c, at(-1),
                 amount="220.00", is_fraud=False),
    )
    c = "sim-legit-profile"
    add(
        _jevent("legit-profile", "prof",
                JourneyEventKind.ACCOUNT_SECURITY, "profile_changed",
                tenant_id=tenant_id, customer_id=c, at=at(-200)),
        _payment_event("legit-profile", tenant_id, c, at(-1)),
        _payment("legit-profile", tenant_id, c, at(-1),
                 amount="380.00", is_fraud=False),
    )
    c = "sim-legit-urgent"
    add(
        _payment("legit-urgent", tenant_id, c, at(-1),
                 amount="7200.00", is_fraud=False,
                 intelligence=IntelligenceSnapshot(
                     transaction_risk=0.74)),
    )

    return tuple(items)
