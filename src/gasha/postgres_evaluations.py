from __future__ import annotations

from uuid import UUID

from gasha.orchestration import ShadowEvaluationRecord
from gasha.postgres import Connection


class PostgresShadowEvaluationRepository:
    """PostgreSQL adapter for persisted shadow/enforcing evaluations.

    First write wins on ``(tenant_id, event_id)`` — a resubmitted
    evaluation returns the originally persisted record, matching the
    in-memory contract.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> ShadowEvaluationRecord | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT record_json
                FROM shadow_evaluations
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ShadowEvaluationRecord.model_validate_json(
            str(row["record_json"])
        )

    def save(self, record: ShadowEvaluationRecord) -> ShadowEvaluationRecord:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO shadow_evaluations (
                    tenant_id, event_id, record_json, persisted_at
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    record.event.tenant_id,
                    str(record.event.event_id),
                    record.model_dump_json(),
                    record.persisted_at,
                ),
            )
        self._connection.commit()

        persisted = self.get(record.event.tenant_id, record.event.event_id)
        if persisted is None:
            raise RuntimeError(
                "shadow evaluation save completed without a record"
            )
        return persisted
