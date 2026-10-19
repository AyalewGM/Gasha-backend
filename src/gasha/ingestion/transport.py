from __future__ import annotations

from typing import Protocol

from gasha.ingestion.contracts import InboundBankEvent


class ConsumedRecord(Protocol):
    """A single record pulled from the event transport.

    Vendor-neutral shape: the byte payload plus the transport coordinates
    needed for observability. Vendor clients (confluent-kafka, kafka-python,
    MSK, RabbitMQ) are wrapped at the composition root to satisfy this.
    """

    @property
    def value(self) -> bytes: ...

    @property
    def topic(self) -> str | None: ...

    @property
    def partition(self) -> int | None: ...

    @property
    def offset(self) -> int | None: ...


class EventBatch:
    """One transport poll: decoded events plus the consumed-record count.

    ``records_consumed`` counts every record pulled, including records that
    failed decoding — a malformed-only batch must still be committable, or
    the partition replays (and re-dead-letters) the same records forever.
    """

    def __init__(
        self,
        events: tuple[InboundBankEvent, ...],
        records_consumed: int,
    ) -> None:
        self.events = events
        self.records_consumed = records_consumed

    def __bool__(self) -> bool:
        return self.records_consumed > 0


class BatchConsumer(Protocol):
    """At-least-once batch consumer with an explicit commit point.

    ``poll_batch`` returns records without acknowledging them; ``commit``
    acknowledges everything polled so far. Offsets therefore advance only
    after the caller has fully processed the batch.
    """

    def poll_batch(self, *, max_records: int) -> tuple[ConsumedRecord, ...]:
        """Returns up to ``max_records`` pending records, oldest first."""
        ...

    def commit(self) -> None:
        """Acknowledges all records returned by prior ``poll_batch`` calls."""
        ...
