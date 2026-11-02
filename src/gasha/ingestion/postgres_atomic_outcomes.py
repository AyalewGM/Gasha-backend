"""Opt-in, transactional outcome + terminal security-audit writer (#42/#43).

This is an inactive bank-neutral PostgreSQL composition candidate, NOT an
authorized bank outcome endpoint. Only an installed verifier, trusted source
adapter, least-privilege scoped connection and independent deployment approval
can supply its inputs. The protected API continues to reject outcome writes.
This module does not certify provenance, reconcile Bank actions or enforce.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from uuid import UUID, uuid4

from gasha.ingestion.outcome_ingestion import (
    IncumbentOutcomeRecord,
    OutcomeSubmission,
    SubmissionStatus,
)
from gasha.poc.outcomes import OutcomeRecord
from gasha.postgres import Connection
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    TrustedPrincipal,
    authorize,
    tenant_audit_ref,
)

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SCHEMA = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
_KINDS = frozenset(("gasha", "incumbent"))


class AtomicOutcomeRejected(ValueError):
    """Untrusted input, corrupt history, or unavailable atomic outcome boundary."""


def _instant(value: object) -> datetime:
    if type(value) is not datetime or value.utcoffset() is None:
        raise AtomicOutcomeRejected("timezone-aware trusted clock required")
    return value.astimezone(UTC)


def _snapshot(record: OutcomeRecord | IncumbentOutcomeRecord) -> dict[str, object]:
    # Model copies can bypass validation; never persist a corrupted copy.
    validated: OutcomeRecord | IncumbentOutcomeRecord
    if type(record) is OutcomeRecord:
        gasha_record = OutcomeRecord.model_validate(record.model_dump(mode="python"))
        source = gasha_record.outcome_source
        timestamp = gasha_record.confirmed_at
        validated = gasha_record
    elif type(record) is IncumbentOutcomeRecord:
        incumbent_record = IncumbentOutcomeRecord.model_validate(
            record.model_dump(mode="python")
        )
        source = incumbent_record.source_system
        timestamp = incumbent_record.recorded_at
        validated = incumbent_record
    else:
        raise AtomicOutcomeRejected("typed outcome record required")
    if (
        type(validated.tenant_id) is not str
        or _TOKEN.fullmatch(validated.tenant_id) is None
        or type(source) is not str
        or _TOKEN.fullmatch(source) is None
        or type(validated.event_id) is not UUID
    ):
        raise AtomicOutcomeRejected("canonical tenant/source/event identity required")
    if timestamp is not None:
        _instant(timestamp)
    return validated.model_dump(mode="json")


def _fingerprint(kind: str, snapshot: Mapping[str, object]) -> str:
    payload = {
        "domain": "gasha-atomic-outcome-v1",
        "kind": kind,
        "record": dict(snapshot),
    }
    canonical = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(canonical.encode("utf-8")).hexdigest()


class PostgresAtomicOutcomeWriter:
    """Opt-in per-installation append-only writer with transaction-bound audit.

    The caller supplies one dedicated non-autocommit connection per concurrent
    call and an already authenticated trusted principal. The DB migrator and
    permissions are separate; this component is not wired to FastAPI.
    """

    def __init__(
        self, connection: Connection, *, installation_schema: str, tenant_id: str
    ) -> None:
        if (
            type(installation_schema) is not str
            or _SCHEMA.fullmatch(installation_schema) is None
            or type(tenant_id) is not str
            or _TOKEN.fullmatch(tenant_id) is None
        ):
            raise AtomicOutcomeRejected("trusted installation configuration required")
        if getattr(connection, "autocommit", None) is not False:
            raise AtomicOutcomeRejected("transactional connection required")
        self._connection = connection
        self._schema = f'"{installation_schema}"'
        self._tenant_id = tenant_id

    def submit(
        self, record: OutcomeRecord, *, principal: TrustedPrincipal, now: datetime
    ) -> OutcomeSubmission:
        return self._write(record, principal=principal, now=now, kind="gasha")

    def submit_incumbent(
        self, record: IncumbentOutcomeRecord, *, principal: TrustedPrincipal,
        now: datetime,
    ) -> OutcomeSubmission:
        return self._write(record, principal=principal, now=now, kind="incumbent")

    def _write(
        self, record: OutcomeRecord | IncumbentOutcomeRecord, *,
        principal: TrustedPrincipal, now: datetime, kind: str,
    ) -> OutcomeSubmission:
        if type(principal) is not TrustedPrincipal or kind not in _KINDS:
            raise AtomicOutcomeRejected("trusted principal and outcome kind required")
        at = _instant(now)
        if principal.expires_at.astimezone(UTC) <= at:
            raise AtomicOutcomeRejected("expired principal")
        snapshot = _snapshot(record)
        tenant = snapshot["tenant_id"]
        event = snapshot["event_id"]
        if tenant != self._tenant_id or type(event) is not str:
            raise AtomicOutcomeRejected("configured tenant or event mismatch")
        capability = (
            Capability.OUTCOME_SUBMIT if kind == "gasha"
            else Capability.INCUMBENT_OUTCOME_SUBMIT
        )
        # This must be performed on a principal supplied by a trusted verifier,
        # never on a role/tenant copied from HTTP. No DB side effects on denial.
        try:
            authorize(principal, tenant_id=self._tenant_id, capability=capability)
        except AuthorizationRejected as exc:
            raise AtomicOutcomeRejected("tenant/capability denied") from exc
        measured_at = snapshot.get("confirmed_at" if kind == "gasha" else "recorded_at")
        if measured_at is not None:
            observed = datetime.fromisoformat(str(measured_at)).astimezone(UTC)
            if observed > at:
                raise AtomicOutcomeRejected("future-dated outcome assertion")
        digest = _fingerprint(kind, snapshot)
        event_id = UUID(event)
        try:
            with self._connection.cursor() as cursor:
                # The unique scope/fingerprint key serializes competing exact
                # duplicates. Distinct corrections append instead of overwrite.
                cursor.execute(
                    f"""INSERT INTO {self._schema}.poc_atomic_outcomes
                    (tenant_id, event_id, outcome_kind, record_digest, record_json,
                     recorded_at)
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                    ON CONFLICT (tenant_id, event_id, outcome_kind, record_digest)
                    DO NOTHING RETURNING id""",
                    (
                        tenant, event_id, kind, digest,
                        dumps(snapshot, sort_keys=True, separators=(",", ":")), at,
                    ),
                )
                inserted = cursor.fetchone() is not None
                cursor.execute(
                    f"""SELECT record_digest, record_json
                    FROM {self._schema}.poc_atomic_outcomes
                    WHERE tenant_id = %s AND event_id = %s AND outcome_kind = %s
                    ORDER BY id""",
                    (tenant, event_id, kind),
                )
                rows = cursor.fetchall()
                history: list[OutcomeRecord | IncumbentOutcomeRecord] = []
                for row in rows:
                    raw = row["record_json"]
                    if (
                        type(raw) is not dict
                        or raw.get("tenant_id") != tenant
                        or raw.get("event_id") != str(event_id)
                        or row["record_digest"] != _fingerprint(kind, raw)
                    ):
                        raise AtomicOutcomeRejected("stored outcome integrity mismatch")
                    parsed = (
                        OutcomeRecord.model_validate(raw) if kind == "gasha"
                        else IncumbentOutcomeRecord.model_validate(raw)
                    )
                    history.append(parsed)
                if not history:
                    raise AtomicOutcomeRejected("stored outcome history unavailable")
                # Terminal audit is in the SAME database transaction as the
                # outcome. Audit failure must roll back the newly inserted row.
                cursor.execute(
                    f"""INSERT INTO {self._schema}.security_audit_events (
                    occurred_at, action, result, actor_ref, tenant_ref,
                    reason, attempt_ref, event_ref, context_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        at, capability.value, "succeeded", principal.audit_actor,
                        tenant_audit_ref(self._tenant_id),
                        "outcome_accepted" if inserted else "outcome_duplicate",
                        uuid4().hex,
                        sha256(f"{tenant}\0{event_id}".encode()).hexdigest(), "",
                    ),
                )
            self._connection.commit()
            status = SubmissionStatus.ACCEPTED if inserted else SubmissionStatus.DUPLICATE
            if kind == "gasha":
                return OutcomeSubmission(
                    status=status,
                    history=tuple(item for item in history if isinstance(item, OutcomeRecord)),
                )
            return OutcomeSubmission(
                status=status,
                incumbent_history=tuple(
                    item for item in history if isinstance(item, IncumbentOutcomeRecord)
                ),
            )
        except Exception:
            self._connection.rollback()
            raise
