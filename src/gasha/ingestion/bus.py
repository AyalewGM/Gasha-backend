from __future__ import annotations

from collections import deque
from typing import Protocol

from gasha.ingestion.contracts import InboundBankEvent


class FraudEventPublisher(Protocol):
    """Port for pushing inbound bank events onto the ingestion stream.

    Implementations (Kafka/MSK/RabbitMQ/etc.) live behind adapters;
    Gasha core never imports a messaging vendor client.
    """

    def publish(self, event: InboundBankEvent) -> None: ...


class FraudEventConsumer(Protocol):
    """Port for pulling inbound bank events for ingestion."""

    def poll(self, *, max_events: int = 1) -> tuple[InboundBankEvent, ...]:
        """Returns up to ``max_events`` pending events, oldest first."""
        ...


class InMemoryEventBus:
    """Deterministic in-memory bus implementing both ports.

    Reference/test implementation — a stand-in for the real bank platform
    transport, with identical semantics (FIFO per bus instance).
    """

    def __init__(self) -> None:
        self._queue: deque[InboundBankEvent] = deque()

    def publish(self, event: InboundBankEvent) -> None:
        self._queue.append(event)

    def poll(self, *, max_events: int = 1) -> tuple[InboundBankEvent, ...]:
        batch: list[InboundBankEvent] = []
        while self._queue and len(batch) < max_events:
            batch.append(self._queue.popleft())
        return tuple(batch)

    def __len__(self) -> int:
        return len(self._queue)
