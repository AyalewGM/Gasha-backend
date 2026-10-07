from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, NoReturn
from uuid import UUID

from pydantic import ValidationError

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.contracts import (
    AdapterMetadata,
    FraudEventEnvelope,
    InboundBankEvent,
)
from gasha.ingestion.errors import (
    EventRejection,
    RejectionReason,
    RejectionRecord,
    payload_fingerprint,
)
from gasha.journey.events import (
    JourneyEvent,
    JourneyEventEnvelope,
    JourneyEventKind,
)

REFERENCE_SCHEMA_VERSION = "1.0"

_REQUIRED_IDENTIFIER_FIELDS = (
    "sender_customer_id",
    "sender_account_id",
    "beneficiary_id",
    "correlation_id",
)

_INTELLIGENCE_FIELDS = frozenset(IntelligenceSnapshot.model_fields)


class ReferenceJsonAdapter:
    """Synthetic reference adapter for the documented `reference-json/1.0` schema.

    This is not a real bank integration — it exists so the ingestion path
    can be exercised end-to-end without any approved bank schema. Field
    names inside ``payload`` are the reference contract:

        event_id, occurred_at, channel, transaction_type, amount,
        currency, sender_customer_id, sender_account_id, beneficiary_id,
        beneficiary_type, destination_institution_id?, device_id?,
        correlation_id, intelligence?, signal_policy_versions?,
        evidence_reason_codes?, operating_mode?

    Required-field violations are typed rejections; malformed optional
    intelligence is treated as unavailable rather than rejected or
    fabricated.
    """

    adapter_type = "reference-json"
    adapter_version = "1.0.0"
    supported_schema_versions = frozenset({REFERENCE_SCHEMA_VERSION})

    def __init__(
        self,
        *,
        supported_currencies: Sequence[str] | None = None,
        default_operating_mode: OperatingMode = OperatingMode.SHADOW,
    ) -> None:
        self._supported_currencies = (
            frozenset(supported_currencies)
            if supported_currencies is not None
            else None
        )
        self._default_mode = default_operating_mode

    def adapt(self, event: InboundBankEvent) -> FraudEventEnvelope:
        reject = self._rejector(event)

        if event.schema_version not in self.supported_schema_versions:
            reject(
                RejectionReason.UNSUPPORTED_SCHEMA_VERSION,
                f"schema {event.schema_version!r} not in "
                f"{sorted(self.supported_schema_versions)}",
            )
        if not isinstance(event.payload, Mapping):
            reject(RejectionReason.INVALID_SCHEMA, "payload must be a mapping")

        payload = event.payload
        event_id = self._event_id(payload.get("event_id"), reject)
        occurred_at = self._timestamp(payload.get("occurred_at"), reject)
        amount = self._amount(payload.get("amount"), reject)
        currency = self._currency(payload.get("currency"), reject)

        for field in _REQUIRED_IDENTIFIER_FIELDS:
            if not payload.get(field):
                reject(
                    RejectionReason.MISSING_REQUIRED_IDENTIFIER,
                    f"missing required field {field!r}",
                )
        for field in ("channel", "transaction_type"):
            if not payload.get(field):
                reject(
                    RejectionReason.INVALID_SCHEMA,
                    f"missing required field {field!r}",
                )

        try:
            transaction = CanonicalTransaction(
                tenant_id=event.tenant_id,
                event_id=event_id,
                occurred_at=occurred_at,
                channel=str(payload["channel"]),
                transaction_type=str(payload["transaction_type"]),
                amount=amount,
                currency=currency,
                sender_customer_id=str(payload["sender_customer_id"]),
                sender_account_id=str(payload["sender_account_id"]),
                beneficiary_id=str(payload["beneficiary_id"]),
                beneficiary_type=BeneficiaryType(
                    payload.get("beneficiary_type") or BeneficiaryType.UNKNOWN
                ),
                destination_institution_id=payload.get(
                    "destination_institution_id"
                ),
                device_id=payload.get("device_id"),
                correlation_id=str(payload["correlation_id"]),
            )
        except (ValidationError, ValueError) as exc:
            reject(RejectionReason.NORMALIZATION_FAILURE, str(exc))

        operating_mode = self._default_mode
        requested_mode = payload.get("operating_mode")
        if requested_mode:
            try:
                operating_mode = OperatingMode(requested_mode)
            except ValueError:
                reject(
                    RejectionReason.INVALID_SCHEMA,
                    f"unknown operating_mode {requested_mode!r}",
                )

        return FraudEventEnvelope(
            tenant_id=event.tenant_id,
            event_id=event_id,
            operating_mode=operating_mode,
            received_at=event.received_at,
            correlation_id=transaction.correlation_id,
            canonical_transaction=transaction,
            intelligence=self._intelligence(payload.get("intelligence")),
            signal_policy_versions=tuple(
                payload.get("signal_policy_versions") or ()
            ),
            evidence_reason_codes=tuple(
                payload.get("evidence_reason_codes") or ()
            ),
            adapter=AdapterMetadata(
                source_system=event.source_system,
                adapter_type=self.adapter_type,
                adapter_version=self.adapter_version,
                schema_version=event.schema_version,
                normalized_at=datetime.now(UTC),
            ),
        )

    def _rejector(
        self, event: InboundBankEvent
    ) -> Callable[[RejectionReason, str], NoReturn]:
        def reject(reason: RejectionReason, detail: str) -> NoReturn:
            raise EventRejection(
                RejectionRecord(
                    reason=reason,
                    detail=detail,
                    tenant_id=event.tenant_id or None,
                    event_id=(
                        str(event.payload.get("event_id"))
                        if isinstance(event.payload, Mapping)
                        else None
                    ),
                    source_system=event.source_system,
                    schema_version=event.schema_version,
                    adapter_version=self.adapter_version,
                    payload_fingerprint=(
                        payload_fingerprint(event.payload)
                        if isinstance(event.payload, Mapping)
                        else None
                    ),
                )
            )

        return reject

    def _event_id(
        self,
        value: Any,
        reject: Callable[[RejectionReason, str], NoReturn],
    ) -> UUID:
        if value is None:
            reject(
                RejectionReason.MISSING_REQUIRED_IDENTIFIER,
                "missing event_id",
            )
        try:
            return UUID(str(value))
        except ValueError:
            reject(
                RejectionReason.MISSING_REQUIRED_IDENTIFIER,
                f"event_id {value!r} is not a valid UUID",
            )

    def _timestamp(
        self,
        value: Any,
        reject: Callable[[RejectionReason, str], NoReturn],
    ) -> datetime:
        if not isinstance(value, str):
            reject(RejectionReason.INVALID_TIMESTAMP, "occurred_at missing")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            reject(
                RejectionReason.INVALID_TIMESTAMP,
                f"occurred_at {value!r} is not ISO-8601",
            )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed

    def _amount(
        self,
        value: Any,
        reject: Callable[[RejectionReason, str], NoReturn],
    ) -> Decimal:
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError):
            reject(RejectionReason.INVALID_AMOUNT, f"amount {value!r} invalid")
        if amount <= 0:
            reject(
                RejectionReason.INVALID_AMOUNT,
                f"amount {value!r} must be positive",
            )
        return amount

    def _currency(
        self,
        value: Any,
        reject: Callable[[RejectionReason, str], NoReturn],
    ) -> str:
        currency = str(value or "").upper()
        if len(currency) != 3 or not currency.isalpha():
            reject(
                RejectionReason.INVALID_SCHEMA,
                f"currency {value!r} must be a 3-letter code",
            )
        if (
            self._supported_currencies is not None
            and currency not in self._supported_currencies
        ):
            reject(
                RejectionReason.UNSUPPORTED_CURRENCY,
                f"currency {currency!r} is not supported",
            )
        return currency

    def adapt_journey(self, event: InboundBankEvent) -> JourneyEventEnvelope:
        """Normalize a `journey` payload into a JourneyEventEnvelope.

        Payload keys map to ``JourneyEvent`` fields:
        event_id, occurred_at, kind, subtype, customer_id, account_id?,
        session_id?, device_id?, beneficiary_id?, correlation_id?,
        received_at?.
        """
        reject = self._rejector(event)
        if event.schema_version not in self.supported_schema_versions:
            reject(
                RejectionReason.UNSUPPORTED_SCHEMA_VERSION,
                f"schema {event.schema_version!r} not in "
                f"{sorted(self.supported_schema_versions)}",
            )
        if not isinstance(event.payload, Mapping):
            reject(RejectionReason.INVALID_SCHEMA, "payload must be a mapping")

        payload = event.payload
        try:
            kind = JourneyEventKind(str(payload.get("kind") or ""))
        except (TypeError, ValueError):
            reject(
                RejectionReason.INVALID_SCHEMA,
                f"unknown journey kind {payload.get('kind')!r}",
            )
        try:
            journey_event = JourneyEvent(
                tenant_id=event.tenant_id,
                event_id=self._event_id(payload.get("event_id"), reject),
                kind=kind,
                subtype=str(payload.get("subtype") or ""),
                occurred_at=self._timestamp(
                    payload.get("occurred_at"), reject
                ),
                received_at=event.received_at,
                correlation_id=payload.get("correlation_id"),
                customer_id=str(payload.get("customer_id") or ""),
                account_id=payload.get("account_id"),
                session_id=payload.get("session_id"),
                device_id=payload.get("device_id"),
                beneficiary_id=payload.get("beneficiary_id"),
            )
        except (ValidationError, ValueError) as exc:
            reject(RejectionReason.NORMALIZATION_FAILURE, str(exc))

        return JourneyEventEnvelope(
            tenant_id=event.tenant_id,
            event_id=journey_event.event_id,
            received_at=event.received_at,
            correlation_id=journey_event.correlation_id,
            adapter=AdapterMetadata(
                source_system=event.source_system,
                adapter_type=self.adapter_type,
                adapter_version=self.adapter_version,
                schema_version=event.schema_version,
                normalized_at=datetime.now(UTC),
            ),
            event=journey_event,
        )

    def _intelligence(self, value: Any) -> IntelligenceSnapshot:
        """Malformed optional intelligence degrades to unavailable."""

        if not isinstance(value, Mapping):
            return IntelligenceSnapshot()
        try:
            return IntelligenceSnapshot(
                **{
                    key: value[key]
                    for key in _INTELLIGENCE_FIELDS
                    if key in value
                }
            )
        except ValidationError:
            return IntelligenceSnapshot()
