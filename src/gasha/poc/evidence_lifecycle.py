"""Non-authoritative #49 evidence lifecycle *transition proposal* kernel.

This is not a trusted ledger or Bank authorization service. The protected,
Bank-installed service must authenticate and scope all principals, use a trusted
artifact resolver, append transitions atomically with a mandatory redacted audit,
and re-check state under a DB lock before accepting a proposal. Caller-supplied
histories, verification results, or hashes are never trusted evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hmac import compare_digest
from typing import Protocol
from uuid import UUID

from gasha.poc.evidence_identity import (
    EvidencePacket,
    EvidenceRecord,
    assert_packet_current,
)
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    TrustedPrincipal,
    authorize,
)

_ACTOR = re.compile(r"[0-9a-f]{64}\Z")


class LifecycleRejected(ValueError):
    """A proposed evidence transition is inconsistent or unauthorized."""


class EvidenceAction(StrEnum):
    SUBMIT = "submit"
    VERIFY = "verify"
    APPROVE = "approve"
    REVOKE_EVIDENCE = "revoke_evidence"
    REVOKE_APPROVAL = "revoke_approval"


_CAPABILITY = {
    EvidenceAction.SUBMIT: Capability.EVIDENCE_CREATE,
    EvidenceAction.VERIFY: Capability.EVIDENCE_VERIFY,
    EvidenceAction.APPROVE: Capability.EVIDENCE_APPROVE,
    EvidenceAction.REVOKE_EVIDENCE: Capability.EVIDENCE_REVOKE,
    EvidenceAction.REVOKE_APPROVAL: Capability.EVIDENCE_REVOKE,
}


class TrustedArtifactReader(Protocol):
    """Implemented by a privileged trusted *server-side* artifact reader only."""

    def sha256_digest(self, record: EvidenceRecord) -> str: ...


@dataclass(frozen=True, slots=True)
class EvidenceTransition:
    action: EvidenceAction
    actor_ref: str
    at: datetime
    packet_digest: str
    evidence_id: UUID | None = None

    def __post_init__(self) -> None:
        if type(self.action) is not EvidenceAction:
            raise LifecycleRejected("typed action required")
        if type(self.actor_ref) is not str or _ACTOR.fullmatch(self.actor_ref) is None:
            raise LifecycleRejected("pseudonymous actor reference required")
        if not isinstance(self.at, datetime) or self.at.utcoffset() is None:
            raise LifecycleRejected("timezone-aware transition time required")
        object.__setattr__(self, "at", self.at.astimezone(UTC))
        if type(self.packet_digest) is not str or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.packet_digest
        ):
            raise LifecycleRejected("packet digest required")
        if self.evidence_id is not None and type(self.evidence_id) is not UUID:
            raise LifecycleRejected("typed evidence_id required")


@dataclass(frozen=True, slots=True)
class EvidenceLifecycle:
    """Untrusted immutable proposal history, not a stored authorization record."""

    packet: EvidencePacket
    events: tuple[EvidenceTransition, ...] = ()

    def __post_init__(self) -> None:
        _replay(self)


@dataclass(frozen=True, slots=True)
class _State:
    submitted: frozenset[UUID]
    verified_by: dict[UUID, str]
    revoked: frozenset[UUID]
    approved_by: str | None
    approval_revoked: bool
    last_at: datetime | None


def _replay(lifecycle: EvidenceLifecycle) -> _State:
    """Check structural history integrity; cannot authenticate its external origin."""
    if type(lifecycle.packet) is not EvidencePacket:
        raise LifecycleRejected("typed packet required")
    if type(lifecycle.events) is not tuple:
        raise LifecycleRejected("immutable event sequence required")
    records = {r.evidence_id: r for r in lifecycle.packet.records}
    submitted: set[UUID] = set()
    verified_by: dict[UUID, str] = {}
    revoked: set[UUID] = set()
    approved_by: str | None = None
    approval_revoked = False
    last_at: datetime | None = None
    expected_digest = lifecycle.packet.packet_digest()
    for event in lifecycle.events:
        if type(event) is not EvidenceTransition:
            raise LifecycleRejected("typed transition required")
        if event.packet_digest != expected_digest:
            raise LifecycleRejected("packet identity changed")
        if last_at is not None and event.at < last_at:
            raise LifecycleRejected("transition clock moved backward")
        last_at = event.at
        if event.action in (
            EvidenceAction.SUBMIT, EvidenceAction.VERIFY, EvidenceAction.REVOKE_EVIDENCE
        ):
            if event.evidence_id not in records:
                raise LifecycleRejected("unknown evidence reference")
            assert event.evidence_id is not None  # Checked above.
            record = records[event.evidence_id]
            if event.action is EvidenceAction.SUBMIT:
                if event.evidence_id in submitted or event.actor_ref != record.collector_actor_ref:
                    raise LifecycleRejected("duplicate submission or collector mismatch")
                submitted.add(event.evidence_id)
            elif event.action is EvidenceAction.VERIFY:
                if (
                    event.evidence_id not in submitted
                    or event.evidence_id in verified_by
                    or event.evidence_id in revoked
                    or event.actor_ref == record.collector_actor_ref
                ):
                    raise LifecycleRejected("invalid independent verification")
                assert_packet_current(lifecycle.packet, expected=lifecycle.packet.binding, now=event.at)
                verified_by[event.evidence_id] = event.actor_ref
            else:
                if event.evidence_id not in submitted or event.evidence_id in revoked:
                    raise LifecycleRejected("invalid evidence revocation")
                revoked.add(event.evidence_id)
                # Revoking any constituent evidence invalidates its packet approval.
                if approved_by is not None:
                    approval_revoked = True
        else:
            if event.evidence_id is not None:
                raise LifecycleRejected("approval action cannot reference one evidence record")
            if event.action is EvidenceAction.APPROVE:
                if (
                    approved_by is not None
                    or revoked
                    or set(verified_by) != set(records)
                    or event.actor_ref in {r.collector_actor_ref for r in records.values()}
                    or event.actor_ref in set(verified_by.values())
                ):
                    raise LifecycleRejected("independent verified approval required")
                assert_packet_current(lifecycle.packet, expected=lifecycle.packet.binding, now=event.at)
                approved_by = event.actor_ref
            elif event.action is EvidenceAction.REVOKE_APPROVAL:
                if approved_by is None or approval_revoked:
                    raise LifecycleRejected("no active approval to revoke")
                approval_revoked = True
            else:
                raise LifecycleRejected("unknown evidence action")
    return _State(
        frozenset(submitted), verified_by, frozenset(revoked), approved_by,
        approval_revoked, last_at,
    )


def propose_transition(
    lifecycle: EvidenceLifecycle,
    *,
    principal: TrustedPrincipal,
    action: EvidenceAction,
    now: datetime,
    evidence_id: UUID | None = None,
    artifact_reader: TrustedArtifactReader | None = None,
) -> EvidenceLifecycle:
    """Propose one checked transition; do not persist or grant authority.

    The caller must inject a trusted principal and, for verification, a reader
    bound server-side to the actual artifact. This module cannot prove the caller
    followed that rule. Atomic audit/persistence/CAS and installation-level
    authorization are intentionally OUTSIDE this inert kernel.
    """
    if type(lifecycle) is not EvidenceLifecycle or type(action) is not EvidenceAction:
        raise LifecycleRejected("typed lifecycle and action required")
    if type(principal) is not TrustedPrincipal:
        raise LifecycleRejected("verified principal required")
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise LifecycleRejected("timezone-aware trusted clock required")
    current = now.astimezone(UTC)
    if principal.expires_at.astimezone(UTC) <= current:
        raise LifecycleRejected("expired principal")
    try:
        authorize(
            principal, tenant_id=lifecycle.packet.binding.tenant_id,
            capability=_CAPABILITY[action],
        )
    except AuthorizationRejected as exc:
        raise LifecycleRejected("tenant or capability denied") from exc
    state = _replay(lifecycle)
    if state.last_at is not None and current < state.last_at:
        raise LifecycleRejected("transition clock moved backward")
    if action in (EvidenceAction.SUBMIT, EvidenceAction.VERIFY, EvidenceAction.APPROVE):
        assert_packet_current(lifecycle.packet, expected=lifecycle.packet.binding, now=current)
    if action is EvidenceAction.VERIFY:
        record = next(
            (r for r in lifecycle.packet.records if r.evidence_id == evidence_id), None
        )
        if record is None or artifact_reader is None:
            raise LifecycleRejected("verified artifact reader and evidence required")
        # The reader must be supplied by trusted deployment composition, not JSON.
        try:
            observed = artifact_reader.sha256_digest(record)
        except Exception as exc:
            raise LifecycleRejected("artifact verification unavailable") from exc
        if type(observed) is not str or not compare_digest(observed, record.artifact_digest):
            raise LifecycleRejected("artifact digest mismatch")
    event = EvidenceTransition(
        action=action,
        actor_ref=principal.audit_actor,
        at=current,
        packet_digest=lifecycle.packet.packet_digest(),
        evidence_id=evidence_id,
    )
    # __post_init__ reconstructs the whole history and rejects invalid order,
    # missing verification, self-approval, duplicate/replayed transitions, etc.
    return EvidenceLifecycle(lifecycle.packet, lifecycle.events + (event,))
