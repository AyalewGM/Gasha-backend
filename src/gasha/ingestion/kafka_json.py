from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.service import DeadLetterSink
from gasha.ingestion.transport import BatchConsumer


class JsonEventConsumer:
    """Decodes JSON transport records into ``InboundBankEvent``.

    Wire contract: each record value is a JSON object with the
    ``InboundBankEvent`` fields — ``tenant_id``, ``source_system``,
    ``schema_version``, ``payload`` and optional ``received_at`` /
    ``correlation_id``.

    A malformed record is dead-lettered and skipped rather than raised:
    a poison record can never stall its partition or crash the consume
    loop. ``commit`` is delegated to the wrapped consumer so callers keep
    at-least-once semantics.
    """

    def __init__(
        self,
        consumer: BatchConsumer,
        *,
        dead_letters: DeadLetterSink,
    ) -> None:
        self._consumer = consumer
        self._dead_letters = dead_letters

    def poll_events(self, *, max_events: int = 1) -> tuple[InboundBankEvent, ...]:
        events: list[InboundBankEvent] = []
        for record in self._consumer.poll_batch(max_records=max_events):
            event = self._decode(record.value)
            if event is not None:
                events.append(event)
        return tuple(events)

    def commit(self) -> None:
        self._consumer.commit()

    def _decode(self, raw: bytes) -> InboundBankEvent | None:
        detail: str
        body: Any
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            detail = f"record value is not valid JSON: {type(exc).__name__}"
            self._dead_letters.put(
                RejectionRecord(
                    reason=RejectionReason.INVALID_SCHEMA,
                    detail=detail,
                )
            )
            return None

        if not isinstance(body, Mapping):
            self._dead_letters.put(
                RejectionRecord(
                    reason=RejectionReason.INVALID_SCHEMA,
                    detail="record value must be a JSON object",
                )
            )
            return None

        try:
            return InboundBankEvent.model_validate(body)
        except ValidationError as exc:
            self._dead_letters.put(
                RejectionRecord(
                    reason=RejectionReason.INVALID_SCHEMA,
                    detail=f"record failed event validation: {exc.error_count()} error(s)",
                    tenant_id=(
                        str(body["tenant_id"]) if body.get("tenant_id") else None
                    ),
                    source_system=(
                        str(body["source_system"])
                        if body.get("source_system")
                        else None
                    ),
                    schema_version=(
                        str(body["schema_version"])
                        if body.get("schema_version")
                        else None
                    ),
                )
            )
            return None
