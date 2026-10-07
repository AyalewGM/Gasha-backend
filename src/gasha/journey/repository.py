from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from gasha.journey.events import JourneyEvent


class JourneyEventRepository(Protocol):
    """Provider-neutral port for tenant-scoped journey event history.

    Core journey logic never depends on PostgreSQL/Redis/Kafka/etc. —
    production storage implements this contract.
    """

    def append(self, event: JourneyEvent) -> bool:
        """Stores an event. Returns False for a duplicate
        ``(tenant_id, event_id)`` — the original is preserved."""
        ...

    def recent(
        self,
        tenant_id: str,
        customer_id: str,
        *,
        as_of: datetime,
        since: datetime,
    ) -> tuple[JourneyEvent, ...]:
        """Returns events with ``since <= occurred_at <= as_of``,
        ordered by business time (``occurred_at``), never arrival order.
        """
        ...


class InMemoryJourneyEventRepository:
    """Deterministic reference implementation for tests/local runs."""

    def __init__(self) -> None:
        self._events: dict[tuple[str, UUID], JourneyEvent] = {}

    def append(self, event: JourneyEvent) -> bool:
        key = (event.tenant_id, event.event_id)
        if key in self._events:
            return False
        self._events[key] = event
        return True

    def recent(
        self,
        tenant_id: str,
        customer_id: str,
        *,
        as_of: datetime,
        since: datetime,
    ) -> tuple[JourneyEvent, ...]:
        matches = [
            event
            for event in self._events.values()
            if event.tenant_id == tenant_id
            and event.customer_id == customer_id
            and since <= event.occurred_at <= as_of
        ]
        matches.sort(key=lambda e: e.occurred_at)
        return tuple(matches)
