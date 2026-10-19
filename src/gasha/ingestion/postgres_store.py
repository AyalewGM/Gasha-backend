from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.errors import RejectionRecord
from gasha.ingestion.outcome_ingestion import IncumbentOutcomeRecord
from gasha.ingestion.pending import PendingEvaluationRecord
from gasha.ingestion.service import IngestionRecord
from gasha.poc.outcomes import OutcomeRecord
from gasha.postgres import Connection


class PostgresIngestionStore:
    """PostgreSQL idempotency store keyed by (tenant_id, event_id).

    First write wins — a resubmitted event returns the originally
    accepted record so conflicting payloads never overwrite.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> IngestionRecord | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT envelope_json, payload_fingerprint, accepted_at
                FROM ingestion_records
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return IngestionRecord(
            envelope=FraudEventEnvelope.model_validate_json(
                str(row["envelope_json"])
            ),
            payload_fingerprint=str(row["payload_fingerprint"]),
            accepted_at=_as_datetime(row["accepted_at"]),
        )

    def save(self, record: IngestionRecord) -> IngestionRecord:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ingestion_records (
                    tenant_id, event_id, envelope_json,
                    payload_fingerprint, accepted_at
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    record.envelope.tenant_id,
                    str(record.envelope.event_id),
                    record.envelope.model_dump_json(),
                    record.payload_fingerprint,
                    record.accepted_at,
                ),
            )
        self._connection.commit()

        persisted = self.get(
            record.envelope.tenant_id, record.envelope.event_id
        )
        if persisted is None:
            raise RuntimeError(
                "ingestion save completed without a record"
            )
        return persisted


class PostgresDeadLetterSink:
    """Append-only dead-letter sink for rejected inbound events."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def put(self, record: RejectionRecord) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO dead_letters (
                    tenant_id, event_id, record_json, rejected_at
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    record.tenant_id,
                    record.event_id,
                    record.model_dump_json(),
                    record.rejected_at,
                ),
            )
        self._connection.commit()


class PostgresOutcomeStore:
    """PostgreSQL append-only outcome and incumbent-control history.

    Every submission is a new row — ``id`` ordering preserves append
    order per ``(tenant_id, event_id)`` so transitions remain auditable
    and the T0 decision is never mutated.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[OutcomeRecord, ...]:
        rows = self._history("outcome_records", tenant_id, event_id)
        return tuple(
            OutcomeRecord.model_validate_json(str(row["record_json"]))
            for row in rows
        )

    def incumbent_outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[IncumbentOutcomeRecord, ...]:
        rows = self._history(
            "incumbent_outcome_records", tenant_id, event_id
        )
        return tuple(
            IncumbentOutcomeRecord.model_validate_json(
                str(row["record_json"])
            )
            for row in rows
        )

    def append(self, record: OutcomeRecord) -> None:
        self._append(
            "outcome_records",
            record.tenant_id,
            record.event_id,
            record.model_dump_json(),
            record.confirmed_at,
        )

    def append_incumbent(self, record: IncumbentOutcomeRecord) -> None:
        self._append(
            "incumbent_outcome_records",
            record.tenant_id,
            record.event_id,
            record.model_dump_json(),
            record.recorded_at,
        )

    def _history(
        self, table: str, tenant_id: str, event_id: UUID
    ) -> list[Mapping[str, object]]:
        # Table names are internal constants, never user input.
        with self._connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT record_json
                FROM {table}
                WHERE tenant_id = %s AND event_id = %s
                ORDER BY id ASC
                """,
                (tenant_id, str(event_id)),
            )
            return cursor.fetchall()

    def _append(
        self,
        table: str,
        tenant_id: str,
        event_id: UUID,
        record_json: str,
        recorded_at: datetime | None,
    ) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO {table} (
                    tenant_id, event_id, record_json, recorded_at
                )
                VALUES (%s, %s, %s, %s)
                """,
                (tenant_id, str(event_id), record_json, recorded_at),
            )
        self._connection.commit()


def _as_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    raise TypeError(f"expected datetime, got {type(value).__name__}")


class PostgresPendingEvaluationStore:
    """PostgreSQL pending-evaluation ledger keyed by (tenant_id, event_id).

    Rows survive process restarts, so acknowledged-but-unevaluated
    events are recovered autonomously — no transport redelivery needed.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def enqueue(
        self, event: FraudEventEnvelope, *, enqueued_at: datetime
    ) -> PendingEvaluationRecord:
        key = (event.tenant_id, event.event_id)
        record = PendingEvaluationRecord(
            event=event,
            enqueued_at=enqueued_at,
            next_attempt_at=enqueued_at,
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO pending_evaluations (
                    tenant_id, event_id, record_json,
                    attempts, next_attempt_at, enqueued_at
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    event.tenant_id,
                    str(event.event_id),
                    record.model_dump_json(),
                    0,
                    enqueued_at,
                    enqueued_at,
                ),
            )
        self._connection.commit()
        existing = self._get(*key)
        assert existing is not None
        return existing

    def due(
        self, now: datetime, *, limit: int = 100
    ) -> tuple[PendingEvaluationRecord, ...]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT record_json
                FROM pending_evaluations
                WHERE next_attempt_at <= %s
                ORDER BY enqueued_at ASC
                LIMIT %s
                """,
                (now, limit),
            )
            rows = cursor.fetchall()
        return tuple(
            PendingEvaluationRecord.model_validate_json(
                str(row["record_json"])
            )
            for row in rows
        )

    def reschedule(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        error: str,
        next_attempt_at: datetime,
    ) -> PendingEvaluationRecord:
        record = self._get(tenant_id, event_id)
        if record is None:
            raise KeyError(
                f"no pending evaluation for tenant {tenant_id!r} "
                f"event {event_id}"
            )
        updated = record.model_copy(
            update={
                "attempts": record.attempts + 1,
                "next_attempt_at": next_attempt_at,
                "last_error": error,
            }
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE pending_evaluations
                SET record_json = %s,
                    attempts = %s,
                    next_attempt_at = %s,
                    last_error = %s
                WHERE tenant_id = %s AND event_id = %s
                """,
                (
                    updated.model_dump_json(),
                    updated.attempts,
                    next_attempt_at,
                    error,
                    tenant_id,
                    str(event_id),
                ),
            )
        self._connection.commit()
        return updated

    def complete(self, tenant_id: str, event_id: UUID) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM pending_evaluations
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, str(event_id)),
            )
        self._connection.commit()

    def _get(
        self, tenant_id: str, event_id: UUID
    ) -> PendingEvaluationRecord | None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT record_json
                FROM pending_evaluations
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return PendingEvaluationRecord.model_validate_json(
            str(row["record_json"])
        )
