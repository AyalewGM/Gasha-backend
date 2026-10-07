from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from gasha.ingestion.contracts import InboundBankEvent

SIMULATOR_SOURCE_SYSTEM = "synthetic-core-banking"
SIMULATOR_SCHEMA_VERSION = "1.0"

SIMULATOR_BASE_TIME = datetime(2026, 2, 20, 8, 0, 0, tzinfo=UTC)


class SyntheticBankSimulator:
    """A synthetic bank emitting provider-schema payment events.

    Not a real bank adapter — the payload shape is the reference-json
    schema consumed by ``ReferenceJsonAdapter``. Scenarios cover normal
    traffic plus the social-engineering patterns from Epic 2/3 so the
    shadow pipeline can be exercised end-to-end exactly as production
    ingestion would receive it.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "tenant-a",
        base_time: datetime = SIMULATOR_BASE_TIME,
        source_system: str = SIMULATOR_SOURCE_SYSTEM,
    ) -> None:
        self.tenant_id = tenant_id
        self._time = base_time
        self.source_system = source_system

    def _next_time(self) -> datetime:
        self._time = self._time + timedelta(minutes=15)
        return self._time

    def event(
        self,
        name: str,
        *,
        amount: str = "500.00",
        intelligence: dict[str, float] | None = None,
        beneficiary_type: str = "external",
        operating_mode: str = "shadow",
        evidence_reason_codes: tuple[str, ...] = (),
        customer_id: str | None = None,
    ) -> InboundBankEvent:
        at = self._next_time()
        customer = customer_id or f"sim-customer-{name}"
        payload: dict[str, object] = {
            "event_id": str(
                uuid5(
                    NAMESPACE_URL,
                    f"gasha://sim/{self.tenant_id}/{name}",
                )
            ),
            "occurred_at": at.isoformat(),
            "channel": "mobile",
            "transaction_type": "transfer",
            "amount": amount,
            "currency": "ETB",
            "sender_customer_id": customer,
            "sender_account_id": f"sim-account-{name}",
            "beneficiary_id": f"sim-beneficiary-{name}",
            "beneficiary_type": beneficiary_type,
            "correlation_id": f"sim-corr-{name}",
            "operating_mode": operating_mode,
        }
        if beneficiary_type == "external":
            payload["destination_institution_id"] = "sim-destination"
        if intelligence:
            payload["intelligence"] = intelligence
        if evidence_reason_codes:
            payload["evidence_reason_codes"] = list(evidence_reason_codes)
        return InboundBankEvent(
            tenant_id=self.tenant_id,
            source_system=self.source_system,
            schema_version=SIMULATOR_SCHEMA_VERSION,
            payload=payload,
            received_at=at,
            correlation_id=str(payload["correlation_id"]),
        )

    def scenario_events(self) -> tuple[InboundBankEvent, ...]:
        """The standard mixed scenario stream for E2E testing."""

        return (
            self.event("normal-payment-1", amount="320.00"),
            self.event(
                "new-beneficiary-large",
                amount="4800.00",
                intelligence={
                    "relationship_risk": 0.82,
                    "transaction_risk": 0.71,
                },
                evidence_reason_codes=("NEW_BENEFICIARY",),
            ),
            self.event(
                "velocity-burst",
                amount="950.00",
                intelligence={"velocity_risk": 0.88},
            ),
            self.event(
                "coached-scam",
                amount="6200.00",
                intelligence={
                    "device_session_risk": 0.93,
                    "relationship_risk": 0.72,
                },
                evidence_reason_codes=(
                    "ACTIVE_CALL_DURING_PAYMENT",
                    "POSSIBLE_LIVE_COACHING_PATTERN",
                ),
            ),
            self.event(
                "remote-access-scam",
                amount="5500.00",
                intelligence={"device_session_risk": 0.97},
                evidence_reason_codes=("REMOTE_ACCESS_INDICATOR",),
            ),
            self.event(
                "mule-aggregation",
                amount="2750.00",
                intelligence={
                    "beneficiary_risk": 0.90,
                    "network_risk": 0.96,
                },
                evidence_reason_codes=(
                    "INTERNAL_GRAPH_BENEFICIARY_FAN_IN",
                    "INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER",
                ),
            ),
            self.event(
                "ambiguous-legit",
                amount="7200.00",
                intelligence={
                    "transaction_risk": 0.72,
                    "device_session_risk": 0.40,
                },
            ),
            self.event("normal-payment-2", amount="180.00"),
        )

    def journey_event(
        self,
        name: str,
        *,
        kind: str,
        subtype: str,
        customer_id: str,
        account_id: str | None = None,
        session_id: str | None = None,
        device_id: str | None = None,
        beneficiary_id: str | None = None,
    ) -> InboundBankEvent:
        """An asynchronous UC-03 journey event in the provider schema."""

        at = self._next_time()
        payload: dict[str, object] = {
            "event_id": str(
                uuid5(
                    NAMESPACE_URL,
                    f"gasha://sim/{self.tenant_id}/journey/{name}",
                )
            ),
            "occurred_at": at.isoformat(),
            "kind": kind,
            "subtype": subtype,
            "customer_id": customer_id,
            "correlation_id": f"sim-corr-{name}",
        }
        for key, value in (
            ("account_id", account_id),
            ("session_id", session_id),
            ("device_id", device_id),
            ("beneficiary_id", beneficiary_id),
        ):
            if value is not None:
                payload[key] = value
        return InboundBankEvent(
            tenant_id=self.tenant_id,
            source_system=self.source_system,
            schema_version=SIMULATOR_SCHEMA_VERSION,
            payload=payload,
            received_at=at,
            correlation_id=str(payload["correlation_id"]),
        )

    def ato_scenario(
        self, name: str = "ato-takeover"
    ) -> tuple[InboundBankEvent, ...]:
        """A UC-03 account-takeover stream in delivery order.

        Asynchronous journey events (auth failures -> login -> new
        device -> credential change -> beneficiary creation) arrive
        first; the final synchronous payment for the same customer must
        be scored through the normal ingestion path — the journey
        context must not be bypassed.
        """

        customer = f"sim-customer-{name}"
        account = f"sim-account-{name}"
        device = f"sim-device-{name}"
        beneficiary = f"sim-beneficiary-{name}"
        session = f"sim-session-{name}"
        return (
            self.journey_event(
                f"{name}-fail-1",
                kind="authentication",
                subtype="login_failed",
                customer_id=customer,
                account_id=account,
                session_id=session,
            ),
            self.journey_event(
                f"{name}-fail-2",
                kind="authentication",
                subtype="login_failed",
                customer_id=customer,
                account_id=account,
                session_id=session,
            ),
            self.journey_event(
                f"{name}-login",
                kind="authentication",
                subtype="login_success",
                customer_id=customer,
                account_id=account,
                session_id=session,
            ),
            self.journey_event(
                f"{name}-device",
                kind="device_session",
                subtype="new_device_observed",
                customer_id=customer,
                account_id=account,
                session_id=session,
                device_id=device,
            ),
            self.journey_event(
                f"{name}-credential",
                kind="account_security",
                subtype="credential_changed",
                customer_id=customer,
                account_id=account,
                session_id=session,
            ),
            self.journey_event(
                f"{name}-beneficiary",
                kind="beneficiary",
                subtype="beneficiary_created",
                customer_id=customer,
                account_id=account,
                beneficiary_id=beneficiary,
            ),
            self.journey_event(
                f"{name}-attempt",
                kind="transaction",
                subtype="payment_attempted",
                customer_id=customer,
                account_id=account,
                beneficiary_id=beneficiary,
            ),
            self.event(
                f"{name}-payment",
                amount="5600.00",
                customer_id=customer,
            ),
        )


def is_journey_inbound(event: InboundBankEvent) -> bool:
    """Distinguishes journey-category inbound events from payments."""

    return "kind" in event.payload


def stream(simulator: SyntheticBankSimulator) -> Iterator[InboundBankEvent]:
    yield from simulator.scenario_events()
