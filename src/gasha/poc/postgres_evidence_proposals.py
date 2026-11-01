"""Opt-in #49 PostgreSQL proposal ledger with atomic redacted audit.

NOT a Bank-trusted evidence registry or approval authority: the packet, identity
and artifact reader must originate from separately trusted Bank composition.
Never consume this adapter as a readiness decision, expose it to untrusted HTTP,
or use its events as authority for enforcement or stage promotion.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from uuid import UUID, uuid4

from gasha.poc.evidence_identity import EvidencePacket
from gasha.poc.evidence_lifecycle import (
    EvidenceAction,
    EvidenceLifecycle,
    EvidenceTransition,
    LifecycleRejected,
    TrustedArtifactReader,
    propose_transition,
)
from gasha.postgres import Connection
from gasha.security.access import (
    Capability,
    TrustedPrincipal,
    authorize,
    tenant_audit_ref,
)

_ACTION_CAPABILITY: dict[EvidenceAction, Capability] = {
    EvidenceAction.SUBMIT: Capability.EVIDENCE_SUBMIT,
    EvidenceAction.VERIFY: Capability.EVIDENCE_VERIFY,
    EvidenceAction.APPROVE: Capability.STAGE_APPROVE,
    EvidenceAction.REVOKE_EVIDENCE: Capability.EVIDENCE_REVOKE,
    EvidenceAction.REVOKE_APPROVAL: Capability.APPROVAL_REVOKE,
}


class EvidenceLedgerRejected(ValueError):
    """Stale, corrupt, mismatched or untrusted stored proposal history."""


def _packet_payload(packet: EvidencePacket) -> dict[str, object]:
    return {
        "binding": packet.binding._identity(),
        "evaluator_version": packet.evaluator_version,
        "records": [
            record._identity()
            for record in sorted(packet.records, key=lambda value: value.evidence_id.int)
        ],
    }


def _event_payload(event: EvidenceTransition) -> dict[str, str | None]:
    return {
        "action": event.action.value,
        "actor_ref": event.actor_ref,
        "at": event.at.astimezone(UTC).isoformat(timespec="microseconds"),
        "packet_digest": event.packet_digest,
        "evidence_id": str(event.evidence_id) if event.evidence_id else None,
    }


def _load_history(
    rows: list[Mapping[str, object]], packet: EvidencePacket
) -> EvidenceLifecycle:
    """Cross-check every SQL column with canonical JSON and contiguous replay."""
    events: list[EvidenceTransition] = []
    for row in rows:
        payload = row["event_json"]
        if not isinstance(payload, dict) or set(payload) != {
            "action", "actor_ref", "at", "packet_digest", "evidence_id",
        }:
            raise EvidenceLedgerRejected("stored evidence event schema mismatch")
        if (
            any(type(payload[key]) is not str for key in (
                "action", "actor_ref", "at", "packet_digest",
            ))
            or (payload["evidence_id"] is not None
                and type(payload["evidence_id"]) is not str)
        ):
            raise EvidenceLedgerRejected("stored evidence event types invalid")
        try:
            event = EvidenceTransition(
                action=EvidenceAction(payload["action"]),
                actor_ref=payload["actor_ref"],
                at=datetime.fromisoformat(payload["at"]),
                packet_digest=payload["packet_digest"],
                evidence_id=(UUID(payload["evidence_id"])
                             if payload["evidence_id"] is not None else None),
            )
        except (TypeError, ValueError, KeyError, OverflowError) as exc:
            raise EvidenceLedgerRejected("invalid stored evidence transition") from exc
        occurred_at = row["occurred_at"]
        if (
            type(row["revision"]) is not int
            or row["revision"] != len(events) + 1
            or row["action"] != event.action.value
            or row["actor_ref"] != event.actor_ref
            or row["evidence_id"] != event.evidence_id
            or not isinstance(occurred_at, datetime)
            or occurred_at.utcoffset() is None
            or occurred_at.astimezone(UTC) != event.at
            or payload != _event_payload(event)
            or event.packet_digest != packet.packet_digest()
        ):
            raise EvidenceLedgerRejected("stored evidence event/SQL integrity mismatch")
        events.append(event)
    try:
        return EvidenceLifecycle(packet=packet, events=tuple(events))
    except LifecycleRejected as exc:
        raise EvidenceLedgerRejected("stored evidence replay invalid") from exc


class PostgresEvidenceProposalLedger:
    """Single-connection, DB-serialized, non-authoritative proposal history.

    One dedicated connection per concurrent call. Never wire to bank endpoints
    without a trusted IdP/reader, tenant-scoped SQL roles and approval controls.
    """

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def apply(
        self,
        packet: EvidencePacket,
        *,
        principal: TrustedPrincipal,
        action: EvidenceAction,
        now: datetime,
        expected_revision: int,
        evidence_id: UUID | None = None,
        artifact_reader: TrustedArtifactReader | None = None,
    ) -> EvidenceLifecycle:
        if type(packet) is not EvidencePacket or type(action) is not EvidenceAction:
            raise EvidenceLedgerRejected("typed packet/action required")
        if type(principal) is not TrustedPrincipal:
            raise EvidenceLedgerRejected("verified principal required")
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise EvidenceLedgerRejected("trusted timezone-aware clock required")
        if type(expected_revision) is not int or expected_revision < 0:
            raise EvidenceLedgerRejected("nonnegative expected revision required")
        if principal.expires_at.astimezone(UTC) <= now.astimezone(UTC):
            raise EvidenceLedgerRejected("expired principal")
        # Check tenant and action BEFORE touching a packet row or artifact reader.
        authorize(
            principal, tenant_id=packet.binding.tenant_id,
            capability=_ACTION_CAPABILITY[action],
        )
        tenant = packet.binding.tenant_id
        installation = packet.binding.installation_id
        digest = packet.packet_digest()
        snapshot = _packet_payload(packet)
        try:
            with self._connection.cursor() as cursor:
                # Inserting the parent row serializes competing first writers by
                # unique key; FOR UPDATE serializes all subsequent transitions.
                # An invalid transition rolls this insert back with its audit.
                cursor.execute(
                    """INSERT INTO poc_evidence_packets
                       (tenant_id, installation_id, packet_digest, packet_json, created_at)
                       VALUES (%s, %s, %s, %s::jsonb, %s)
                       ON CONFLICT DO NOTHING""",
                    (tenant, installation, digest, dumps(snapshot), now),
                )
                cursor.execute(
                    """SELECT packet_json FROM poc_evidence_packets
                       WHERE tenant_id = %s AND installation_id = %s
                         AND packet_digest = %s FOR UPDATE""",
                    (tenant, installation, digest),
                )
                stored = cursor.fetchone()
                if stored is None or stored["packet_json"] != snapshot:
                    raise EvidenceLedgerRejected("stored packet identity mismatch")
                cursor.execute(
                    """SELECT revision, action, actor_ref, occurred_at, evidence_id,
                              event_json FROM poc_evidence_events
                       WHERE tenant_id = %s AND installation_id = %s
                         AND packet_digest = %s ORDER BY revision""",
                    (tenant, installation, digest),
                )
                current = _load_history(cursor.fetchall(), packet)
                if len(current.events) != expected_revision:
                    raise EvidenceLedgerRejected("stale evidence revision")
                proposed = propose_transition(
                    current, principal=principal, action=action, now=now,
                    evidence_id=evidence_id, artifact_reader=artifact_reader,
                )
                event = proposed.events[-1]
                revision = len(proposed.events)
                cursor.execute(
                    """INSERT INTO poc_evidence_events (
                          tenant_id, installation_id, packet_digest, revision,
                          action, actor_ref, occurred_at, evidence_id, event_json
                       ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)""",
                    (
                        tenant, installation, digest, revision, event.action.value,
                        event.actor_ref, event.at, event.evidence_id,
                        dumps(_event_payload(event)),
                    ),
                )
                # Mandatory audit shares the exact transaction. Failure rolls back
                # the event and, for an initial submission, the parent packet.
                cursor.execute(
                    """INSERT INTO security_audit_events (
                          occurred_at, action, result, actor_ref, tenant_ref,
                          reason, attempt_ref, event_ref, context_ref
                       ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        event.at, "evidence." + event.action.value, "allowed",
                        event.actor_ref, tenant_audit_ref(tenant),
                        "proposal_recorded", uuid4().hex,
                        sha256(f"{digest}:{revision}".encode()).hexdigest(),
                        digest.removeprefix("sha256:"),
                    ),
                )
            self._connection.commit()
            return proposed
        except Exception:
            self._connection.rollback()
            raise
