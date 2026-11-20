"""Synthetic-only, read-only shadow-copy adapter for #146 / Epic #41.

This is an *explicitly installed fixture adapter*, NOT an authenticated Dashen
connector, bank data-source attestation, or permission to use production data.
It accepts only canonical transaction fields from an approved synthetic copy.
Bank decisions, risk assertions, evidence reasons and operating-mode controls
cannot enter through this boundary. No calls to a payment system are possible.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime, timezone
from typing import NoReturn
from uuid import UUID
from zoneinfo import ZoneInfo

from pydantic_core import TzInfo

from gasha.domain.models import BeneficiaryType, IntelligenceSnapshot, OperatingMode
from gasha.ingestion.contracts import (
    AdapterMetadata,
    FraudEventEnvelope,
    InboundBankEvent,
)
from gasha.ingestion.errors import EventRejection, RejectionReason, RejectionRecord
from gasha.ingestion.reference import ReferenceJsonAdapter

SHADOW_COPY_SCHEMA = "synthetic-shadow-copy-v1"
_AMOUNT = re.compile(r"(?:0|[1-9][0-9]{0,14})(?:\.[0-9]{1,6})?\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_REQUIRED = frozenset(
    {
        "event_id",
        "occurred_at",
        "channel",
        "transaction_type",
        "amount",
        "currency",
        "sender_customer_id",
        "sender_account_id",
        "beneficiary_id",
        "beneficiary_type",
        "correlation_id",
    }
)
_OPTIONAL = frozenset({"destination_institution_id", "device_id"})
_ALLOWED = _REQUIRED | _OPTIONAL
_IDENTIFIERS = (
    "event_id",
    "channel",
    "transaction_type",
    "sender_customer_id",
    "sender_account_id",
    "beneficiary_id",
    "beneficiary_type",
    "correlation_id",
)


class SyntheticShadowCopyAdapter:
    """Normalize a pseudonymous fixture into an immutable SHADOW envelope.

    The protected Bank adapter/transport/identity composition must be designed
    and authorized independently; simply registering this class cannot grant
    tenant access or connect a Bank source.
    """

    adapter_type = "synthetic-shadow-copy"
    adapter_version = "1.0.0"
    supported_schema_versions = frozenset({SHADOW_COPY_SCHEMA})

    def __init__(self, *, source_system: str = "synthetic-shadow-copy") -> None:
        if type(source_system) is not str or _TOKEN.fullmatch(source_system) is None:
            raise ValueError("bounded synthetic source identifier required")
        self._source_system = source_system
        self._reference = ReferenceJsonAdapter(
            default_operating_mode=OperatingMode.SHADOW
        )

    def _reject(
        self, event: InboundBankEvent, reason: RejectionReason, detail: str
    ) -> NoReturn:
        # Never echo raw payloads, identifiers, free text, or exception messages.
        raise EventRejection(
            RejectionRecord(
                reason=reason,
                detail=detail,
                tenant_id=event.tenant_id,
                source_system=event.source_system,
                schema_version=event.schema_version,
                adapter_version=self.adapter_version,
            )
        )

    def adapt(self, event: InboundBankEvent) -> FraudEventEnvelope:
        if type(event) is not InboundBankEvent:
            raise TypeError("typed inbound event required")
        if event.source_system != self._source_system:
            self._reject(event, RejectionReason.INVALID_SCHEMA, "unrecognized source")
        if event.schema_version not in self.supported_schema_versions:
            self._reject(
                event, RejectionReason.UNSUPPORTED_SCHEMA_VERSION, "unsupported copy schema"
            )
        if type(event.payload) is not dict:
            self._reject(event, RejectionReason.INVALID_SCHEMA, "plain payload object required")
        raw: Mapping[str, object] = event.payload
        if set(raw) != set(raw).intersection(_ALLOWED):
            self._reject(event, RejectionReason.INVALID_SCHEMA, "unrecognized or authoritative fields")
        if not _REQUIRED.issubset(raw):
            self._reject(event, RejectionReason.INVALID_SCHEMA, "required copy fields absent")

        for field in _IDENTIFIERS:
            value = raw[field]
            if type(value) is not str or _TOKEN.fullmatch(value) is None:
                self._reject(event, RejectionReason.INVALID_SCHEMA, "invalid copy identifier")
        # Validate exact downstream types before delegating, including identifiers
        # which the general bounded-token grammar deliberately allows.
        try:
            UUID(str(raw["event_id"]))
        except ValueError:
            self._reject(event, RejectionReason.INVALID_SCHEMA, "invalid copy event id")
        try:
            BeneficiaryType(str(raw["beneficiary_type"]))
        except ValueError:
            self._reject(event, RejectionReason.INVALID_SCHEMA, "invalid beneficiary category")

        for field in _OPTIONAL:
            value = raw.get(field)
            if value is not None and (
                type(value) is not str or _TOKEN.fullmatch(value) is None
            ):
                self._reject(event, RejectionReason.INVALID_SCHEMA, "invalid optional reference")

        amount = raw["amount"]
        if type(amount) is not str or _AMOUNT.fullmatch(amount) is None:
            self._reject(event, RejectionReason.INVALID_AMOUNT, "bounded decimal string required")
        if not any(char in "123456789" for char in amount):
            self._reject(event, RejectionReason.INVALID_AMOUNT, "positive amount required")
        currency = raw["currency"]
        if type(currency) is not str or _CURRENCY.fullmatch(currency) is None:
            self._reject(event, RejectionReason.INVALID_SCHEMA, "ISO currency code required")

        occurred_text = raw["occurred_at"]
        if type(occurred_text) is not str or len(occurred_text) > 40:
            self._reject(event, RejectionReason.INVALID_TIMESTAMP, "bounded event clock required")
        try:
            occurred = datetime.fromisoformat(occurred_text)
        except ValueError:
            self._reject(event, RejectionReason.INVALID_TIMESTAMP, "invalid event clock")
            raise AssertionError("unreachable")
        if occurred.tzinfo is None:
            self._reject(event, RejectionReason.INVALID_TIMESTAMP, "event clock must be aware")
        received = event.received_at
        if (
            type(received) is not datetime
            or type(received.tzinfo) not in (timezone, ZoneInfo, TzInfo)
        ):
            self._reject(event, RejectionReason.INVALID_TIMESTAMP, "receipt clock required")
        if type(received.tzinfo) is TzInfo:
            # Pydantic's JSON decoder produces its exact fixed-offset TzInfo.
            # Reparse its ISO offset into stdlib timezone before delegating.
            # Never call an arbitrary user-supplied tzinfo implementation.
            try:
                received = datetime.fromisoformat(received.isoformat())
            except (ValueError, OverflowError):
                self._reject(event, RejectionReason.INVALID_TIMESTAMP, "invalid receipt clock")
        if received.utcoffset() is None:
            self._reject(event, RejectionReason.INVALID_TIMESTAMP, "receipt clock required")
        if occurred.astimezone(UTC) > received.astimezone(UTC):
            self._reject(event, RejectionReason.INVALID_TIMESTAMP, "event after receipt")

        # The reference normalizer is used only for the typed transaction
        # contract. All attacker/caller-selected authority and signal fields
        # were excluded above; this copy cannot install a mode or risk score.
        mapped = dict(raw)
        mapped["operating_mode"] = OperatingMode.SHADOW.value
        try:
            normalized = self._reference.adapt(
                InboundBankEvent(
                    tenant_id=event.tenant_id,
                    source_system=event.source_system,
                    schema_version="1.0",
                    payload=mapped,
                    received_at=received,
                    correlation_id=event.correlation_id,
                )
            )
        except EventRejection as rejection:
            # The general reference adapter can echo raw payload values in its
            # error message and event_id. Never pass such evidence to dead letters,
            # audit records, or the caller of the synthetic-only boundary.
            self._reject(
                event,
                rejection.record.reason,
                "synthetic copy normalization rejected",
            )
        return FraudEventEnvelope(
            tenant_id=normalized.tenant_id,
            event_id=normalized.event_id,
            operating_mode=OperatingMode.SHADOW,
            received_at=normalized.received_at,
            correlation_id=normalized.correlation_id,
            canonical_transaction=normalized.canonical_transaction,
            intelligence=IntelligenceSnapshot(),
            signal_policy_versions=(),
            evidence_reason_codes=(),
            adapter=AdapterMetadata(
                source_system=event.source_system,
                adapter_type=self.adapter_type,
                adapter_version=self.adapter_version,
                schema_version=SHADOW_COPY_SCHEMA,
                normalized_at=normalized.adapter.normalized_at,
            ),
        )
