from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

from gasha.cases.evaluation_alerts import PostgresEvaluationAlertWriter
from gasha.decision.audit import DecisionAuditRecord
from gasha.ingestion.lease import LeaseLostError, current_evaluation_lease
from gasha.orchestration import ShadowEvaluationRecord
from gasha.postgres import Connection
from gasha.tenant_scope import require_tenant


class PostgresShadowEvaluationRepository:
    """PostgreSQL adapter for persisted shadow/enforcing evaluations.

    First write wins on ``(tenant_id, event_id)`` — a resubmitted
    evaluation returns the originally persisted record, matching the
    in-memory contract.
    """

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None
    ) -> None:
        self._tenant_ids = tenant_ids
        self._connection = connection

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> ShadowEvaluationRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
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
        require_tenant(record.event.tenant_id, self._tenant_ids)
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

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None,
        require_lease: bool = False,
        alerts: PostgresEvaluationAlertWriter | None = None,
    ) -> None:
        self._alerts = alerts
        self._require_lease = require_lease
        self._tenant_ids = tenant_ids
        self._connection = connection

    def save(
        self,
        record: ShadowEvaluationRecord,
        audit: DecisionAuditRecord,
    ) -> ShadowEvaluationRecord:
        decision = audit.decision
        require_tenant(record.event.tenant_id, self._tenant_ids)
        require_tenant(decision.tenant_id, self._tenant_ids)
        if (decision.tenant_id, decision.event_id) != (record.event.tenant_id, record.event.event_id):
            raise ValueError("audit and evaluation identity mismatch")
        if self._alerts is not None and (
            getattr(self._connection, "autocommit", None) is not False
            or decision != record.evaluation.decision
            or record.event.tenant_id != self._alerts.tenant_id
        ):
            raise ValueError("alert persistence requires a matching tenant-bound transaction")
        try:
            with self._connection.cursor() as cursor:
                lease = current_evaluation_lease.get()
                if self._require_lease:
                    if lease is None or (lease.tenant_id, lease.event_id) != (
                        record.event.tenant_id, record.event.event_id
                    ):
                        raise LeaseLostError("missing or mismatched evaluation claim")
                    cursor.execute(
                        """SELECT lease_token FROM pending_evaluations
                        WHERE tenant_id = %s AND event_id = %s
                          AND lease_token = %s
                        FOR UPDATE""",
                        (lease.tenant_id, str(lease.event_id), lease.token),
                    )
                    if cursor.fetchone() is None:
                        raise LeaseLostError("evaluation claim superseded")
                    # Check database time after acquiring the lock: a lock wait
                    # may itself have outlived the lease window.
                    cursor.execute(
                        """SELECT lease_token FROM pending_evaluations
                        WHERE tenant_id = %s AND event_id = %s
                          AND lease_token = %s AND leased_until > clock_timestamp()""",
                        (lease.tenant_id, str(lease.event_id), lease.token),
                    )
                    if cursor.fetchone() is None:
                        raise LeaseLostError("evaluation claim expired")
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
                audit_inserted = cursor.rowcount == 1
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
                inserted = cursor.rowcount == 1
            if self._alerts is not None and inserted != audit_inserted:
                raise ValueError("alert persistence found incomplete decision evidence")
            if self._alerts is not None and inserted:
                self._alerts.append(self._connection, record, at=datetime.now(UTC))
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

