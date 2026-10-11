from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol

from gasha.ingestion.transport import ConsumedRecord

if TYPE_CHECKING:
    from confluent_kafka import Consumer, Message


class _Consumer(Protocol):
    """Minimal surface of ``confluent_kafka.Consumer`` this adapter uses."""

    def consume(self, num_messages: int, timeout: float) -> list[Message]: ...

    def commit(self, asynchronous: bool = False) -> None: ...

    def close(self) -> None: ...


class _Record:
    def __init__(self, message: Message) -> None:
        self._message = message

    @property
    def value(self) -> bytes:
        raw: bytes = self._message.value()
        return raw

    @property
    def topic(self) -> str | None:
        topic: str = self._message.topic()
        return topic

    @property
    def offset(self) -> int | None:
        offset: int = self._message.offset()
        return offset


class ConfluentKafkaConsumer:
    """``BatchConsumer`` over ``confluent_kafka.Consumer``.

    Thin deployment-edge binding: librdkafka transport errors are skipped
    (librdkafka already retried them internally), broker-fatal errors
    propagate, and ``commit`` is a synchronous offset commit so callers
    keep at-least-once semantics.
    """

    def __init__(
        self,
        consumer: Consumer | _Consumer,
        *,
        poll_timeout_s: float = 1.0,
    ) -> None:
        self._consumer = consumer
        self._poll_timeout_s = poll_timeout_s

    @classmethod
    def build(
        cls,
        *,
        bootstrap_servers: str,
        group_id: str,
        topics: Sequence[str],
        poll_timeout_s: float = 1.0,
        **config: object,
    ) -> ConfluentKafkaConsumer:
        """Creates the vendor client and subscribes to ``topics``.

        Kept at the composition root: importing ``confluent_kafka`` here
        is the only place Gasha touches a messaging library.
        """
        from confluent_kafka import Consumer

        consumer = Consumer(
            {
                "bootstrap.servers": bootstrap_servers,
                "group.id": group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
                **config,
            }
        )
        consumer.subscribe(list(topics))
        return cls(consumer, poll_timeout_s=poll_timeout_s)

    def poll_batch(self, *, max_records: int) -> tuple[ConsumedRecord, ...]:
        records: list[ConsumedRecord] = []
        for message in self._consumer.consume(
            num_messages=max_records, timeout=self._poll_timeout_s
        ):
            error = message.error()
            if error is None:
                records.append(_Record(message))
            elif error.fatal():
                raise RuntimeError(f"fatal kafka error: {error}")
            # Non-fatal transport errors (e.g. partition EOF) are skipped.
        return tuple(records)

    def commit(self) -> None:
        self._consumer.commit(asynchronous=False)

    def close(self) -> None:
        self._consumer.close()
