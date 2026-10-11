from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.errors import RejectionRecord
from gasha.ingestion.outcome_ingestion import IncumbentOutcomeRecord
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
