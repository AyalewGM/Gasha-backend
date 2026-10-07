from __future__ import annotations

import logging
from typing import Any

# The only fields a structured operational log record may carry. Customer
# names, account/card/phone numbers, credentials, tokens and raw bank
# payloads are structurally excluded — the record builder accepts no
# arbitrary fields.
_LOG_FIELDS = frozenset(
    {
        "tenant_id",
        "event_id",
        "correlation_id",
        "component",
        "operation",
        "outcome",
        "error_category",
        "latency_ms",
    }
)


def build_log_record(
    *,
    component: str,
    operation: str,
    outcome: str,
    tenant_id: str | None = None,
    event_id: str | None = None,
    correlation_id: str | None = None,
    error_category: str | None = None,
    latency_ms: float | None = None,
) -> dict[str, Any]:
    """Builds a whitelisted structured log record.

    There is deliberately no ``**extra`` parameter: nothing outside the
    allowed operational fields can reach the log record.
    """

    record: dict[str, Any] = {
        "component": component,
        "operation": operation,
        "outcome": outcome,
    }
    optional = {
        "tenant_id": tenant_id,
        "event_id": event_id,
        "correlation_id": correlation_id,
        "error_category": error_category,
        "latency_ms": latency_ms,
    }
    for key, value in optional.items():
        if value is not None and key in _LOG_FIELDS:
            record[key] = value
    return record


def log_operation(
    logger: logging.Logger,
    record: dict[str, Any],
    *,
    level: int = logging.INFO,
) -> None:
    """Emits a whitelisted record, dropping any unexpected keys."""

    sanitized = {
        key: value for key, value in record.items() if key in _LOG_FIELDS
    }
    logger.log(level, "gasha_operation", extra=sanitized)
