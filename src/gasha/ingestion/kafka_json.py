from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.service import DeadLetterSink
from gasha.ingestion.transport import BatchConsumer, ConsumedRecord, EventBatch


class JsonEventConsumer:
    """Decodes JSON transport records into ``InboundBankEvent``.

    Wire contract: each record value is a JSON object with the
    ``InboundBankEvent`` fields — ``tenant_id``, ``source_system``,
    ``schema_version``, ``payload`` and optional ``received_at`` /
    ``correlation_id``.

    A malformed record is dead-lettered (with its transport coordinates as
    replay evidence) and skipped rather than raised: a poison record can
    never stall its partition or crash the consume loop. ``commit`` is
    delegated to the wrapped consumer so callers keep at-least-once
    semantics, and ``poll_batch`` reports the raw consumed count so a
    malformed-only batch is still acknowledged exactly once.
    """

    def __init__(
        self,
        consumer: BatchConsumer,
        *,
        dead_letters: DeadLetterSink,
    ) -> None:
        self._consumer = consumer
        self._dead_letters = dead_letters

    def poll_batch(self, *, max_events: int = 1) -> EventBatch:
        records = self._consumer.poll_batch(max_records=max_events)
        events: list[InboundBankEvent] = []
        for record in records:
            event = self._decode(record)
            if event is not None:
                events.append(event)
        return EventBatch(tuple(events), len(records))

    def commit(self) -> None:
        self._consumer.commit()

    def _decode(self, record: ConsumedRecord) -> InboundBankEvent | None:
        raw = record.value
        try:
            body: Any = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._dead_letters.put(
                RejectionRecord(
                    reason=RejectionReason.INVALID_SCHEMA,
                    detail=(
                        f"record value is not valid JSON: "
                        f"{type(exc).__name__}"
                    ),
                    topic=record.topic,
                    partition=record.partition,
                    offset=record.offset,
                )
            )
            return None

        if not isinstance(body, Mapping):
            self._dead_letters.put(
                RejectionRecord(
                    reason=RejectionReason.INVALID_SCHEMA,
                    detail="record value must be a JSON object",
                    topic=record.topic,
                    partition=record.partition,
                    offset=record.offset,
                )
            )
            return None

        try:
            return InboundBankEvent.model_validate(body)
        except ValidationError as exc:
            self._dead_letters.put(
                RejectionRecord(
                    reason=RejectionReason.INVALID_SCHEMA,
                    detail=(
                        f"record failed event validation: "
                        f"{exc.error_count()} error(s)"
                    ),
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
                    topic=record.topic,
                    partition=record.partition,
                    offset=record.offset,
                )
            )
            return None
