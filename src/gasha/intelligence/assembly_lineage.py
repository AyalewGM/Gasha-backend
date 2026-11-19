"""Offline-only point-in-time intelligence assembly with externally verified issuance.

No default authority is supplied: callers must inject a trusted issuer/verifier.
A self-asserted envelope, caller-supplied receipt time or matching digest is NOT
authentication. This port is not wired into the protected API or Bank serving.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel

_VERSION = "gasha-assembly-lineage-v1"


@dataclass(frozen=True, slots=True)
class OriginalDecisionContext:
    tenant_id: str
    event_id: UUID
    decision_id: str
    occurred_at: datetime
    received_at: datetime
    dataset_epoch: str
    dataset_seal: str
    attestation: str

    @property
    def cutoff(self) -> datetime:
        return self.received_at.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ProviderEvidence:
    source: str
    source_version: str
    tenant_id: str
    event_id: UUID
    decision_id: str
    dataset_epoch: str
    dataset_seal: str
    as_of: datetime
    observed_at: datetime
    available_at: datetime
    payload_digest: str
    attestation: str
    payload: object


class AssemblyAuthority(Protocol):
    """Trusted server adapter verifies actual issuance, not just field equality."""

    def verify_context(self, context: OriginalDecisionContext) -> bool: ...

    def verify_evidence(
        self, evidence: ProviderEvidence, context: OriginalDecisionContext
    ) -> bool: ...


def canonical_bytes(value: object) -> bytes:
    """Deterministic encoding for immutable evidence identities, not a signature."""
    if isinstance(value, BaseModel):
        payload: object = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        payload = asdict(value)
    else:
        raise TypeError("unsupported evidence payload")
    return dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def payload_digest(value: object) -> str:
    return sha256(_VERSION.encode() + b"\n" + canonical_bytes(value)).hexdigest()


def context_identity(context: OriginalDecisionContext) -> bytes:
    return dumps(
        {
            "version": _VERSION,
            "tenant": context.tenant_id,
            "event": str(context.event_id),
            "decision": context.decision_id,
            "occurred": context.occurred_at.astimezone(UTC).isoformat(),
            "received": context.received_at.astimezone(UTC).isoformat(),
            "epoch": context.dataset_epoch,
            "seal": context.dataset_seal,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def evidence_identity(evidence: ProviderEvidence) -> bytes:
    return dumps(
        {
            "version": _VERSION,
            "source": evidence.source,
            "source_version": evidence.source_version,
            "tenant": evidence.tenant_id,
            "event": str(evidence.event_id),
            "decision": evidence.decision_id,
            "epoch": evidence.dataset_epoch,
            "seal": evidence.dataset_seal,
            "as_of": evidence.as_of.astimezone(UTC).isoformat(),
            "observed": evidence.observed_at.astimezone(UTC).isoformat(),
            "available": evidence.available_at.astimezone(UTC).isoformat(),
            "digest": evidence.payload_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def aware(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def context_matches(
    context: OriginalDecisionContext, transaction_tenant: str,
    transaction_event: UUID, transaction_time: datetime
) -> bool:
    if type(context) is not OriginalDecisionContext:
        return False
    if not all(aware(t) for t in (context.occurred_at, context.received_at, transaction_time)):
        return False
    return (
        context.tenant_id == transaction_tenant
        and context.event_id == transaction_event
        and context.occurred_at.astimezone(UTC) == transaction_time.astimezone(UTC)
        and context.received_at >= context.occurred_at
        and all(
            isinstance(s, str) and 0 < len(s) <= 128 and s.isascii()
            and all(c.isalnum() or c in "._:-" for c in s)
            for s in (context.tenant_id, context.decision_id, context.dataset_epoch, context.dataset_seal)
        )
        and isinstance(context.attestation, str)
        and len(context.attestation) >= 32
    )


def verified(
    evidence: object,
    source: str,
    payload_type: type,
    context: OriginalDecisionContext,
    authority: AssemblyAuthority,
) -> bool:
    if type(evidence) is not ProviderEvidence:
        return False
    item = evidence
    if type(item.payload) is not payload_type or item.source != source:
        return False
    if not all(aware(t) for t in (item.as_of, item.observed_at, item.available_at)):
        return False
    if not (
        item.tenant_id == context.tenant_id
        and item.event_id == context.event_id
        and item.decision_id == context.decision_id
        and item.dataset_epoch == context.dataset_epoch
        and item.dataset_seal == context.dataset_seal
        and item.as_of.astimezone(UTC) == context.cutoff
        and item.observed_at <= item.available_at <= context.cutoff
        and isinstance(item.source_version, str)
        and 0 < len(item.source_version) <= 128
        and isinstance(item.attestation, str)
        and len(item.attestation) >= 32
    ):
        return False
    try:
        return (
            item.payload_digest == payload_digest(item.payload)
            and authority.verify_evidence(item, context) is True
        )
    except Exception:  # noqa: BLE001
        # Verification outages or malformed provider evidence cannot grant trust.
        return False
