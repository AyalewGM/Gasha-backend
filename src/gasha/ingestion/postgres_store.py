from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from pydantic_core import TzInfo

from gasha.domain.models import DecisionPolicy
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.errors import RejectionReason, RejectionRecord
from gasha.ingestion.outcome_ingestion import IncumbentOutcomeRecord
from gasha.ingestion.pending import PendingEvaluationRecord
from gasha.ingestion.service import DeadLetterSink, IngestionRecord
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


def _restored_pending_clock(
    value: datetime | None, *, optional: bool = False, allow_naive: bool = False
) -> datetime | None:
    """Recover a fixed-offset DB JSON clock without executing arbitrary tzinfo.

    Pydantic v2 decodes persisted JSON offsets into its exact `TzInfo` type.
    The Gasha synthetic receipt-time feature engine permits only stdlib
    `datetime.timezone`, so preserve the validated clock's ISO representation
    while restoring that trusted concrete type. Never call custom callbacks.
    """
    if value is None and optional:
        return None
    if type(value) is not datetime:
        raise ValueError("invalid persisted pending timestamp")
    if value.tzinfo is None:
        # Only the legacy synthetic reference adapter may preserve a naive
        # inbound receipt clock. Never reinterpret it as UTC or allow it on
        # the strict synthetic-shadow-copy receipt-time feature path.
        if allow_naive:
            return value
        raise ValueError("invalid persisted pending timestamp")
    if type(value.tzinfo) not in (timezone, TzInfo):
        raise ValueError("invalid persisted pending timestamp")
    if type(value.tzinfo) is TzInfo:
        try:
            value = datetime.fromisoformat(value.isoformat())
        except (ValueError, OverflowError) as exc:
            raise ValueError("invalid persisted pending timestamp") from exc
    if value.utcoffset() is None:
        raise ValueError("naive persisted pending timestamp")
    return value


def _restored_pending_record(
    raw: str, *, tenant_id: str, event_id: str,
    adapter_type: str | None, adapter_schema_version: str | None,
) -> PendingEvaluationRecord:
    """Bind mutable pending JSON to SQL identity and enqueue-time adapter policy.

    Older rows lacking an independently stored adapter contract fail closed;
    self-asserted JSON metadata must never activate naive clock permission.
    """
    record = PendingEvaluationRecord.model_validate_json(raw)
    event = record.event
    transaction = event.canonical_transaction
    if (
        not adapter_type or not adapter_schema_version
        or event.adapter.adapter_type != adapter_type
        or event.adapter.schema_version != adapter_schema_version
        or event.tenant_id != tenant_id
        or str(event.event_id) != event_id
        or transaction.tenant_id != tenant_id
        or str(transaction.event_id) != event_id
    ):
        raise ValueError("persisted pending identity or adapter mismatch")
    received = _restored_pending_clock(
        event.received_at, optional=True,
        allow_naive=(
            adapter_type == "reference-json"
            and adapter_schema_version == "1.0"
        ),
    )
    occurred = _restored_pending_clock(transaction.occurred_at)
    normalized = _restored_pending_clock(event.adapter.normalized_at)
    restored = event.model_copy(update={
        "received_at": received,
        "canonical_transaction": transaction.model_copy(update={"occurred_at": occurred}),
        "adapter": event.adapter.model_copy(update={"normalized_at": normalized}),
    })
    return record.model_copy(update={"event": restored})


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
                    adapter_type, adapter_schema_version,
                    attempts, next_attempt_at, enqueued_at,
                    leased_by, leased_until, lease_token
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    event.tenant_id,
                    str(event.event_id),
                    record.model_dump_json(),
                    event.adapter.adapter_type,
                    event.adapter.schema_version,
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
        """Claim due rows, isolating invalid persisted records within one transaction.

        A malformed JSON clock or mismatched identity must not strand a
        healthy neighbor after the lease write commits. A poison record is
        terminalized with a minimized durable dead-letter; its raw JSON and
        exception text never enter rejection evidence. Unexpected DB errors
        roll the entire claim/quarantine transaction back.
        """
        tenant_ids = (
            list(self._tenant_ids) if self._tenant_ids is not None else None
        )
        claimed: list[PendingEvaluationRecord] = []
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE pending_evaluations AS pe
                    SET leased_by = %s, leased_until = %s,
                        lease_token = gen_random_uuid()
                    WHERE (pe.tenant_id, pe.event_id) IN (
                        SELECT tenant_id, event_id
                        FROM pending_evaluations
                        WHERE NOT terminal AND next_attempt_at <= %s
                          AND (%s::text[] IS NULL OR tenant_id = ANY(%s))
                          AND (leased_until IS NULL OR leased_until <= %s)
                        ORDER BY enqueued_at ASC
                        LIMIT %s
                        FOR UPDATE SKIP LOCKED
                    )
                    RETURNING pe.tenant_id, pe.event_id, pe.record_json,
                              pe.adapter_type, pe.adapter_schema_version,
                              pe.leased_by, pe.leased_until, pe.lease_token,
                              pe.terminal
                    """,
                    (
                        self._worker_id, now + self._lease_ttl, now,
                        tenant_ids, tenant_ids, now, limit,
                    ),
                )
                for row in cursor.fetchall():
                    tenant_id = str(row["tenant_id"])
                    event_id = str(row["event_id"])
                    require_tenant(tenant_id, self._tenant_ids)
                    try:
                        record = _restored_pending_record(
                            str(row["record_json"]),
                            tenant_id=tenant_id, event_id=event_id,
                            adapter_type=(
                                str(row["adapter_type"])
                                if row["adapter_type"] is not None else None
                            ),
                            adapter_schema_version=(
                                str(row["adapter_schema_version"])
                                if row["adapter_schema_version"] is not None else None
                            ),
                        )
                    except (ValueError, TypeError):
                        # The database row identity is authoritative for this
                        # *synthetic* ledger; never trust the corrupt JSON for
                        # scope, event identity, raw details or provenance.
                        cursor.execute(
                            """
                            UPDATE pending_evaluations AS pe
                            SET terminal = TRUE, attempts = pe.attempts + 1,
                                last_error = 'InvalidPendingRecord',
                                leased_by = NULL, leased_until = NULL,
                                lease_token = NULL
                            WHERE pe.tenant_id = %s AND pe.event_id = %s
                              AND pe.leased_by = %s AND pe.lease_token = %s
                              AND NOT pe.terminal
                              AND NOT EXISTS (
                                  SELECT 1 FROM shadow_evaluations AS se
                                  WHERE se.tenant_id = pe.tenant_id
                                    AND se.event_id = pe.event_id
                              )
                            """,
                            (
                                tenant_id, event_id, self._worker_id,
                                str(row["lease_token"]),
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise RuntimeError("pending quarantine state conflict")
                        rejection = RejectionRecord(
                            reason=RejectionReason.INVALID_SCHEMA,
                            detail="invalid persisted pending record",
                            tenant_id=tenant_id, event_id=event_id,
                            rejected_at=now,
                        )
                        cursor.execute(
                            """
                            INSERT INTO dead_letters
                                (tenant_id, event_id, record_json, rejected_at)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (
                                tenant_id, event_id, rejection.model_dump_json(),
                                rejection.rejected_at,
                            ),
                        )
                        continue
                    claimed.append(record.model_copy(update={
                        "leased_by": row["leased_by"],
                        "leased_until": row["leased_until"],
                        "claim_token": (
                            str(row["lease_token"])
                            if row["lease_token"] is not None else None
                        ),
                        "terminal": bool(row["terminal"]),
                    }))
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return tuple(claimed)

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
                SELECT record_json, adapter_type, adapter_schema_version,
                       leased_by, leased_until, lease_token, terminal
                FROM pending_evaluations
                WHERE tenant_id = %s AND event_id = %s
                """ + (" FOR UPDATE" if lock else ""),
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return _restored_pending_record(
            str(row["record_json"]), tenant_id=tenant_id,
            event_id=str(event_id),
            adapter_type=(
                str(row["adapter_type"])
                if row["adapter_type"] is not None else None
            ),
            adapter_schema_version=(
                str(row["adapter_schema_version"])
                if row["adapter_schema_version"] is not None else None
            ),
        ).model_copy(
            update={"leased_by": row["leased_by"], "leased_until": row["leased_until"], "claim_token": str(row["lease_token"]) if row["lease_token"] is not None else None, "terminal": bool(row["terminal"])}
        )


    def terminate(
        self, record: PendingEvaluationRecord, rejection: RejectionRecord, *,
        dead_letters: DeadLetterSink, owner: str, now: datetime,
    ) -> bool:
        """Atomically append terminal evidence and retain an idempotency tombstone.

        PostgreSQL writes its own DLQ in this transaction; the supplied sink
        is used only by the reference store, never as an external callback.
        """
        tenant_id, event_id = record.event.tenant_id, record.event.event_id
        require_tenant(tenant_id, self._tenant_ids)
        if (rejection.tenant_id, rejection.event_id) != (tenant_id, str(event_id)):
            raise ValueError("terminal rejection identity mismatch")
        if not record.claim_token:
            return False
        try:
            current = self._get(tenant_id, event_id, lock=True)
            with self._connection.cursor() as cursor:
                # Read database time after acquiring the row lock. Persistence
                # uses the same lock, serializing success against termination.
                cursor.execute(
                    """SELECT tenant_id FROM pending_evaluations AS pe
                    WHERE tenant_id = %s AND event_id = %s
                      AND leased_by = %s AND lease_token = %s
                      AND leased_until > clock_timestamp() AND NOT terminal
                      AND NOT EXISTS (SELECT 1 FROM shadow_evaluations AS se
                          WHERE se.tenant_id = pe.tenant_id AND se.event_id = pe.event_id)
                    """, (tenant_id, str(event_id), owner, record.claim_token),
                )
                if current is None or cursor.fetchone() is None:
                    self._connection.commit()
                    return False
                terminal = current.model_copy(update={
                    "terminal": True, "claim_token": None, "leased_by": None,
                    "leased_until": None, "attempts": current.attempts + 1,
                })
                cursor.execute(
                    """INSERT INTO dead_letters (tenant_id, event_id, record_json, rejected_at)
                    VALUES (%s, %s, %s, %s)""",
                    (tenant_id, str(event_id), rejection.model_dump_json(), rejection.rejected_at),
                )
                cursor.execute(
                    """UPDATE pending_evaluations SET terminal = TRUE,
                    record_json = %s, attempts = %s,
                    leased_by = NULL, leased_until = NULL, lease_token = NULL
                    WHERE tenant_id = %s AND event_id = %s""",
                    (terminal.model_dump_json(), terminal.attempts, tenant_id, str(event_id)),
                )
            self._connection.commit()
            return True
        except Exception:
            self._connection.rollback()
            raise
