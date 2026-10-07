from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from gasha.domain.models import (
    CanonicalTransaction,
    IntelligenceSnapshot,
    OperatingMode,
)


class InboundBankEvent(BaseModel):
    """A raw bank/provider event at the adapter boundary.

    ``payload`` is the provider-specific body. It is never persisted or
    logged by Gasha core — only its fingerprint is retained on rejection.
    """

    model_config = {"arbitrary_types_allowed": True}

    tenant_id: str = Field(min_length=1)
    source_system: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    payload: Mapping[str, Any]
    received_at: datetime | None = None
    correlation_id: str | None = None


class AdapterMetadata(BaseModel):
    """Versioning provenance recorded on every normalized event.

    Bank payload mappings change over time; keeping adapter and schema
    versions on the normalized event keeps historical decisions
    reproducible.
    """

    source_system: str = Field(min_length=1)
    adapter_type: str = Field(min_length=1)
    adapter_version: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    normalized_at: datetime


class FraudEventEnvelope(BaseModel):
    """Versioned envelope separating transport metadata from the payload.

    The canonical transaction is the decision input; ``intelligence``
    carries any already-computed signal components passed through
    normalization. Missing intelligence is valid — it must not be
    fabricated and must not itself raise risk.
    """

    envelope_version: str = Field(default="fraud-event-envelope-1", min_length=1)
    tenant_id: str = Field(min_length=1)
    event_id: UUID
    operating_mode: OperatingMode = OperatingMode.SHADOW
    received_at: datetime | None = None
    correlation_id: str
    canonical_transaction: CanonicalTransaction
    intelligence: IntelligenceSnapshot = IntelligenceSnapshot()
    signal_policy_versions: tuple[str, ...] = ()
    evidence_reason_codes: tuple[str, ...] = ()
    adapter: AdapterMetadata
