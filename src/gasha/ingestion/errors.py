from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RejectionReason(StrEnum):
    """Structured reasons an inbound event is rejected before enrichment."""

    INVALID_SCHEMA = "invalid_schema"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    MISSING_REQUIRED_IDENTIFIER = "missing_required_identifier"
    INVALID_AMOUNT = "invalid_amount"
    INVALID_TIMESTAMP = "invalid_timestamp"
    UNSUPPORTED_CURRENCY = "unsupported_currency"
    TENANT_CONFIGURATION_UNAVAILABLE = "tenant_configuration_unavailable"
    DUPLICATE_CONFLICT = "duplicate_conflict"
    ADAPTER_FAILURE = "adapter_failure"
    NORMALIZATION_FAILURE = "normalization_failure"
    EVALUATION_FAILURE = "evaluation_failure"


def payload_fingerprint(payload: Mapping[str, Any]) -> str:
    """Deterministic content hash — retained instead of the raw payload."""

    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class RejectionRecord(BaseModel):
    """Minimized auditable evidence of a rejected inbound event.

    Deliberately contains no raw payload, customer identifiers, or account
    numbers — only the fingerprint needed to correlate a resubmission.
    """

    reason: RejectionReason
    detail: str
    tenant_id: str | None = None
    event_id: str | None = None
    source_system: str | None = None
    schema_version: str | None = None
    adapter_version: str | None = None
    payload_fingerprint: str | None = None
    rejected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EventRejection(Exception):
    """Raised by adapters/validation when an event must be rejected."""

    def __init__(self, record: RejectionRecord) -> None:
        super().__init__(f"{record.reason.value}: {record.detail}")
        self.record = record
