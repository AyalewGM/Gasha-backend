from __future__ import annotations

import json
from uuid import UUID

from gasha.decision.audit import DecisionAuditRecord
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


class PostgresEvaluationPersistence:
    """Atomic persistence boundary for one evaluation's two artifacts.

    The decision audit (``fraud_decision_audit``) and the shadow
    evaluation record (``shadow_evaluations``) are written in a single
    transaction: either both commit or neither does, so a retry after a
    mid-save failure can never observe half-persisted evidence. Both
    inserts are first-write-wins on ``(tenant_id, event_id)``, keeping
    the originally persisted pair intact on replay.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def save(
        self,
        record: ShadowEvaluationRecord,
        audit: DecisionAuditRecord,
    ) -> ShadowEvaluationRecord:
        decision = audit.decision
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO fraud_decision_audit (
                        tenant_id, event_id, decision_json,
                        signal_policy_versions_json, evidence_json,
                        decided_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, event_id) DO NOTHING
                    """,
                    (
                        decision.tenant_id,
                        str(decision.event_id),
                        decision.model_dump_json(),
                        json.dumps(audit.signal_policy_versions),
                        json.dumps(
                            [
                                item.model_dump(mode="json")
                                for item in audit.evidence
                            ]
                        ),
                        decision.decided_at,
                    ),
                )
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
        except Exception:
            self._connection.rollback()
            raise

        persisted = PostgresShadowEvaluationRepository(
            self._connection
        ).get(record.event.tenant_id, record.event.event_id)
        if persisted is None:
            raise RuntimeError(
                "atomic evaluation save completed without a record"
            )
        return persisted
