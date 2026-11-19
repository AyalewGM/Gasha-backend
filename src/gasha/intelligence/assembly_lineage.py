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

from gasha.domain.models import CanonicalTransaction

_VERSION = "gasha-assembly-lineage-v2"
_TX_VERSION = "gasha-canonical-transaction-v1"
_POLICY_VERSION = "gasha-effective-policy-v1"


@dataclass(frozen=True, slots=True)
class EffectivePolicySnapshot:
    role: str
    schema: str
    version: str
    content: str
    digest: str


@dataclass(frozen=True, slots=True)
class OriginalDecisionContext:
    tenant_id: str
    event_id: UUID
    decision_id: str
    occurred_at: datetime
    received_at: datetime
    dataset_epoch: str
    dataset_seal: str
    transaction_digest: str
    policy_snapshots: tuple[EffectivePolicySnapshot, ...]
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
    policy_digest: str | None = None


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


def exact_amount(value: object) -> str:
    """Exact canonical Decimal formatting independent of global precision."""
    from decimal import Decimal

    if type(value) is not Decimal or not value.is_finite() or value <= 0:
        raise ValueError("finite positive Decimal required")
    sign, digits_tuple, exponent = value.as_tuple()
    if sign or not isinstance(exponent, int) or len(digits_tuple) > 40 or abs(exponent) > 40:
        raise ValueError("amount beyond canonical bounds")
    digits = "".join(str(d) for d in digits_tuple).lstrip("0") or "0"
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    point = len(digits) + exponent
    if point > 30 or point < -12:
        raise ValueError("amount magnitude/scale beyond canonical bounds")
    if point <= 0:
        return "0." + "0" * -point + digits
    if point >= len(digits):
        return digits + "0" * (point - len(digits))
    return digits[:point] + "." + digits[point:]


def transaction_digest(transaction: CanonicalTransaction) -> str:
    if type(transaction) is not CanonicalTransaction or not aware(transaction.occurred_at):
        raise ValueError("typed aware canonical transaction required")
    data = transaction.model_dump(mode="json")
    data["amount"] = exact_amount(transaction.amount)
    data["occurred_at"] = transaction.occurred_at.astimezone(UTC).isoformat()
    return sha256(dumps(
        {"version": _TX_VERSION, "data": data},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def policy_snapshot(role: str, policy: BaseModel) -> EffectivePolicySnapshot:
    content = canonical_bytes(policy).decode()
    schema = type(policy).__name__
    digest = sha256(
        (_POLICY_VERSION + "\n" + role + "\n" + schema + "\n" + content).encode()
    ).hexdigest()
    return EffectivePolicySnapshot(
        role=role, schema=schema, version=str(policy.model_dump()["policy_version"]),
        content=content, digest=digest,
    )


def verified_policy_snapshot(
    snapshot: EffectivePolicySnapshot, role: str, expected_type: type[BaseModel]
) -> BaseModel | None:
    if (
        type(snapshot) is not EffectivePolicySnapshot
        or snapshot.role != role or snapshot.schema != expected_type.__name__
        or type(snapshot.content) is not str or len(snapshot.content) > 16384
    ):
        return None
    try:
        restored = expected_type.model_validate_json(snapshot.content)
        return (
            restored if policy_snapshot(role, restored) == snapshot else None
        )
    except Exception:  # noqa: BLE001
        return None


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
            "transaction_digest": context.transaction_digest,
            "policy_snapshots": [asdict(p) for p in context.policy_snapshots],
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
            "policy_digest": evidence.policy_digest,
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
    context: OriginalDecisionContext, transaction: CanonicalTransaction
) -> bool:
    if type(context) is not OriginalDecisionContext:
        return False
    if not all(aware(t) for t in (context.occurred_at, context.received_at, transaction.occurred_at)):
        return False
    try:
        bound_transaction = context.transaction_digest == transaction_digest(transaction)
    except (ValueError, TypeError):
        return False
    return (
        context.tenant_id == transaction.tenant_id
        and context.event_id == transaction.event_id
        and context.occurred_at.astimezone(UTC) == transaction.occurred_at.astimezone(UTC)
        and bound_transaction
        and type(context.policy_snapshots) is tuple
        and len(context.policy_snapshots) == 5
        and {p.role for p in context.policy_snapshots}
            == {"assembly", "social", "graph", "session", "journey"}
        and context.received_at.astimezone(UTC) >= context.occurred_at.astimezone(UTC)
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
        and item.observed_at.astimezone(UTC) <= item.available_at.astimezone(UTC) <= context.cutoff
        and isinstance(item.source_version, str)
        and 0 < len(item.source_version) <= 128
        and isinstance(item.attestation, str)
        and len(item.attestation) >= 32
        and (
            item.policy_digest == next(
                p.digest for p in context.policy_snapshots if p.role == "journey"
            ) if source == "journey" else item.policy_digest is None
        )
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
