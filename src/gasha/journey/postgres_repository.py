from __future__ import annotations

from datetime import datetime

from gasha.journey.events import JourneyEvent
from gasha.postgres import Connection


class PostgresJourneyEventRepository:
    """PostgreSQL adapter for tenant-scoped journey events.

    ``append`` is idempotent on ``(tenant_id, event_id)`` — an exact
    duplicate returns False and never overwrites. ``recent`` serves
    bounded windowed queries ordered by business time (``occurred_at``),
    never arrival order, matching the in-memory contract.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def append(self, event: JourneyEvent) -> bool:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO journey_events (
                    tenant_id, event_id, customer_id, kind,
                    occurred_at, event_json
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    event.tenant_id,
                    str(event.event_id),
                    event.customer_id,
                    event.kind.value,
                    event.occurred_at,
                    event.model_dump_json(),
                ),
            )
            inserted = cursor.fetchone() is not None
        self._connection.commit()
        return inserted

    def recent(
        self,
        tenant_id: str,
        customer_id: str,
        *,
        as_of: datetime,
        since: datetime,
    ) -> tuple[JourneyEvent, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT event_json
                FROM journey_events
                WHERE tenant_id = %s AND customer_id = %s
                  AND occurred_at >= %s AND occurred_at <= %s
                ORDER BY occurred_at ASC
                """,
                (tenant_id, customer_id, since, as_of),
            )
            rows = cursor.fetchall()
        return tuple(
            JourneyEvent.model_validate_json(str(row["event_json"]))
            for row in rows
        )
