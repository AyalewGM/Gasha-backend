from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from gasha.domain.models import DecisionPolicy
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.errors import RejectionRecord
from gasha.ingestion.outcome_ingestion import IncumbentOutcomeRecord
from gasha.ingestion.pending import PendingEvaluationRecord
from gasha.ingestion.service import IngestionRecord
from gasha.poc.outcomes import OutcomeRecord
from gasha.postgres import Connection
from gasha.tenant_scope import require_tenant


class PostgresIngestionStore:
    """PostgreSQL idempotency store keyed by (tenant_id, event_id).

    First write wins — a resubmitted event returns the originally
    accepted record so conflicting payloads never overwrite.
    """

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None
    ) -> None:
        self._tenant_ids = tenant_ids
        self._connection = connection

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> IngestionRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
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
        require_tenant(record.envelope.tenant_id, self._tenant_ids)
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

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None
    ) -> None:
        self._tenant_ids = tenant_ids
        self._connection = connection

    def put(self, record: RejectionRecord) -> None:
        if record.tenant_id is not None:
            require_tenant(record.tenant_id, self._tenant_ids)
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

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None
    ) -> None:
        self._tenant_ids = tenant_ids
        self._connection = connection

    def outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[OutcomeRecord, ...]:
        require_tenant(tenant_id, self._tenant_ids)
        rows = self._history("outcome_records", tenant_id, event_id)
        return tuple(
            OutcomeRecord.model_validate_json(str(row["record_json"]))
            for row in rows
        )

    def incumbent_outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[IncumbentOutcomeRecord, ...]:
        require_tenant(tenant_id, self._tenant_ids)
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
        require_tenant(tenant_id, self._tenant_ids)
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
        require_tenant(tenant_id, self._tenant_ids)
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

    ``tenant_ids`` is the worker's authorized tenant scope — claims and
    mutations never touch rows outside it (``None`` = unrestricted).
    ``worker_id``/``lease_ttl`` implement atomic work ownership: ``due``
    claims due rows in one ``FOR UPDATE SKIP LOCKED`` statement, and
    ``reschedule``/``complete`` only mutate rows still leased to this
    worker.
    """

    def __init__(
        self,
        connection: Connection,
        *,
        tenant_ids: tuple[str, ...] | None = None,
        worker_id: str | None = None,
        lease_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        self._connection = connection
        self._tenant_ids = tenant_ids
        self._worker_id = worker_id or (
            f"{socket.gethostname()}-{os.getpid()}"
        )
        self._lease_ttl = lease_ttl

    def enqueue(
        self,
        event: FraudEventEnvelope,
        *,
        enqueued_at: datetime,
        policy: DecisionPolicy | None = None,
    ) -> PendingEvaluationRecord:
        require_tenant(event.tenant_id, self._tenant_ids)
        key = (event.tenant_id, event.event_id)
        record = PendingEvaluationRecord(
            event=event,
            policy=policy,
            enqueued_at=enqueued_at,
            next_attempt_at=enqueued_at,
            claim_token=str(uuid4()),
            leased_by=self._worker_id,
            leased_until=enqueued_at + self._lease_ttl,
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO pending_evaluations (
                    tenant_id, event_id, record_json,
                    attempts, next_attempt_at, enqueued_at,
                    leased_by, leased_until, lease_token
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    event.tenant_id,
                    str(event.event_id),
                    record.model_dump_json(),
                    0,
                    enqueued_at,
                    enqueued_at,
                    self._worker_id,
                    enqueued_at + self._lease_ttl,
                    record.claim_token,
                ),
            )
        self._connection.commit()
        existing = self._get(*key)
        assert existing is not None
        return existing

    def due(
        self, now: datetime, *, limit: int = 100
    ) -> tuple[PendingEvaluationRecord, ...]:
        """Atomically claims up to ``limit`` due rows for this worker.

        One ``UPDATE ... FOR UPDATE SKIP LOCKED ... RETURNING`` — each
        due, in-scope, unleased row is stamped ``leased_by``/``leased_until``
        in the same statement, so concurrent workers can never claim the
        same row.
        """
        tenant_ids = (
            list(self._tenant_ids) if self._tenant_ids is not None else None
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE pending_evaluations AS pe
                SET leased_by = %s, leased_until = %s, lease_token = gen_random_uuid()
                WHERE (pe.tenant_id, pe.event_id) IN (
                    SELECT tenant_id, event_id
                    FROM pending_evaluations
                    WHERE next_attempt_at <= %s
                      AND (%s::text[] IS NULL OR tenant_id = ANY(%s))
                      AND (leased_until IS NULL
                           OR leased_until <= %s)
                    ORDER BY enqueued_at ASC
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING pe.record_json, pe.leased_by, pe.leased_until, pe.lease_token
                """,
                (
                    self._worker_id,
                    now + self._lease_ttl,
                    now,
                    tenant_ids,
                    tenant_ids,
                    now,
                    limit,
                ),
            )
            rows = cursor.fetchall()
        self._connection.commit()
        return tuple(
            PendingEvaluationRecord.model_validate_json(
                str(row["record_json"])
            ).model_copy(
                update={"leased_by": row["leased_by"], "leased_until": row["leased_until"], "claim_token": str(row["lease_token"]) if row["lease_token"] is not None else None}
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
        owner: str | None = None,
        claim_token: str | None = None,
        now: datetime | None = None,
    ) -> PendingEvaluationRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
        if not claim_token:
            return None
        record = self._get(tenant_id, event_id, lock=True)
        if record is None:
            self._connection.commit()
            return None
        updated = record.model_copy(
            update={
                "attempts": record.attempts + 1,
                "next_attempt_at": next_attempt_at,
                "last_error": error,
                "leased_by": None,
                "leased_until": None,
                "claim_token": None,
            }
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE pending_evaluations
                SET record_json = %s,
                    attempts = %s,
                    next_attempt_at = %s,
                    last_error = %s,
                    leased_by = NULL, leased_until = NULL, lease_token = NULL
                WHERE tenant_id = %s AND event_id = %s
                  AND leased_by = %s AND lease_token = %s
                  AND leased_until > clock_timestamp()
                """,
                (
                    updated.model_dump_json(),
                    updated.attempts,
                    next_attempt_at,
                    error,
                    tenant_id,
                    str(event_id),
                    owner,
                    claim_token,
                ),
            )
            applied = cursor.rowcount > 0
        self._connection.commit()
        return updated if applied else None

    def complete(
        self,
        tenant_id: str,
        event_id: UUID,
        *,
        owner: str | None = None,
        claim_token: str | None = None,
        now: datetime | None = None,
    ) -> None:
        require_tenant(tenant_id, self._tenant_ids)
        self._get(tenant_id, event_id, lock=True)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM pending_evaluations
                WHERE tenant_id = %s AND event_id = %s
                  AND leased_by = %s AND lease_token = %s
                  AND leased_until > clock_timestamp()
                """,
                (tenant_id, str(event_id), owner, claim_token),
            )
        self._connection.commit()

    def _get(
        self, tenant_id: str, event_id: UUID, *, lock: bool = False
    ) -> PendingEvaluationRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT record_json, leased_by, leased_until, lease_token
                FROM pending_evaluations
                WHERE tenant_id = %s AND event_id = %s
                """ + (" FOR UPDATE" if lock else ""),
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return PendingEvaluationRecord.model_validate_json(
            str(row["record_json"])
        ).model_copy(
            update={"leased_by": row["leased_by"], "leased_until": row["leased_until"], "claim_token": str(row["lease_token"]) if row["lease_token"] is not None else None}
        )

