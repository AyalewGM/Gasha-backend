"""Immutable, non-authoritative evidence identity kernel for the #49 authority plane.

This does not authenticate collectors, verify artifacts, persist records, grant
stage approvals or consume the caller-asserted #54 readiness evaluator. Even a
matching digest is NOT evidence of provenance, approval or Bank authorization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.poc.readiness import EvidenceArea, Stage

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ACTOR = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceIdentityRejected(ValueError):
    """Invalid or mismatched evidence identity; do not treat as verified."""


def _tag(name: str, value: object) -> None:
    if type(value) is not str or _TAG.fullmatch(value) is None:
        raise EvidenceIdentityRejected(f"{name} must be a bounded opaque reference")


def _digest(name: str, value: object) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise EvidenceIdentityRejected(f"{name} must be a sha256 digest")


def _time(name: str, value: object) -> datetime:
    # Validate the concrete clock implementation before calling timezone hooks:
    # datetime subclasses and custom tzinfo objects can execute caller code.
    if not isinstance(value, datetime) or type(value) is not datetime:
        raise EvidenceIdentityRejected(f"{name} must be an allowed timezone-aware datetime")
    if type(value.tzinfo) not in (timezone, ZoneInfo):
        raise EvidenceIdentityRejected(f"{name} must be an allowed timezone-aware datetime")
    if value.utcoffset() is None:
        raise EvidenceIdentityRejected(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


class UseCase(str):
    """Only explicit UC-01/02/03 identifiers are accepted in an evidence scope."""

    UC_01 = "uc-01"
    UC_02 = "uc-02"
    UC_03 = "uc-03"


_USES = frozenset((UseCase.UC_01, UseCase.UC_02, UseCase.UC_03))


@dataclass(frozen=True, slots=True)
class EvidenceBinding:
    tenant_id: str
    installation_id: str
    stage: Stage
    use_case: str
    commit_sha: str
    image_digest: str
    dataset_digest: str
    config_version: str
    policy_version: str
    rule_version: str
    signal_version: str
    adapter_version: str
    window_start: datetime
    window_end: datetime

    def __post_init__(self) -> None:
        for name in (
            "tenant_id", "installation_id", "config_version", "policy_version",
            "rule_version", "signal_version", "adapter_version",
        ):
            _tag(name, getattr(self, name))
        if type(self.stage) is not Stage:
            raise EvidenceIdentityRejected("stage must be a Stage enum")
        if type(self.use_case) is not str or self.use_case not in _USES:
            raise EvidenceIdentityRejected("use_case must be an explicit UC identifier")
        if type(self.commit_sha) is not str or _HEX40.fullmatch(self.commit_sha) is None:
            raise EvidenceIdentityRejected("commit_sha must be a lowercase Git SHA")
        _digest("image_digest", self.image_digest)
        _digest("dataset_digest", self.dataset_digest)
        start = _time("window_start", self.window_start)
        end = _time("window_end", self.window_end)
        if start > end:
            raise EvidenceIdentityRejected("window_end precedes window_start")
        # Dataclass equality must compare UTC instants, not ambiguous local walls.
        # A fall-back fold=0 versus fold=1 differs even with shared ZoneInfo.
        object.__setattr__(self, "window_start", start)
        object.__setattr__(self, "window_end", end)

    def _identity(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id,
            "installation_id": self.installation_id,
            "stage": self.stage.value,
            "use_case": self.use_case,
            "commit_sha": self.commit_sha,
            "image_digest": self.image_digest,
            "dataset_digest": self.dataset_digest,
            "config_version": self.config_version,
            "policy_version": self.policy_version,
            "rule_version": self.rule_version,
            "signal_version": self.signal_version,
            "adapter_version": self.adapter_version,
            "window_start": _iso(self.window_start),
            "window_end": _iso(self.window_end),
        }


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: UUID
    binding: EvidenceBinding
    area: EvidenceArea
    artifact_ref: str
    artifact_digest: str
    source_system: str
    collector_actor_ref: str
    collected_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if type(self.evidence_id) is not UUID:
            raise EvidenceIdentityRejected("evidence_id must be a UUID")
        if type(self.binding) is not EvidenceBinding:
            raise EvidenceIdentityRejected("binding must be a typed immutable scope")
        if type(self.area) is not EvidenceArea:
            raise EvidenceIdentityRejected("area must be an EvidenceArea enum")
        _tag("artifact_ref", self.artifact_ref)
        _digest("artifact_digest", self.artifact_digest)
        _tag("source_system", self.source_system)
        if (
            type(self.collector_actor_ref) is not str
            or _ACTOR.fullmatch(self.collector_actor_ref) is None
        ):
            raise EvidenceIdentityRejected("collector_actor_ref must be pseudonymous")
        collected = _time("collected_at", self.collected_at)
        expires = _time("expires_at", self.expires_at)
        if collected < _time("window_end", self.binding.window_end):
            raise EvidenceIdentityRejected("collection predates observation window end")
        if expires <= collected:
            raise EvidenceIdentityRejected("expiry must follow collection")
        object.__setattr__(self, "collected_at", collected)
        object.__setattr__(self, "expires_at", expires)

    def _identity(self) -> dict[str, str]:
        return {
            "evidence_id": str(self.evidence_id),
            "area": self.area.value,
            "artifact_ref": self.artifact_ref,
            "artifact_digest": self.artifact_digest,
            "source_system": self.source_system,
            "collector_actor_ref": self.collector_actor_ref,
            "collected_at": _iso(self.collected_at),
            "expires_at": _iso(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class EvidencePacket:
    """An immutable content identity, NOT a verified or approved evidence packet."""

    binding: EvidenceBinding
    evaluator_version: str
    records: tuple[EvidenceRecord, ...]

    def __post_init__(self) -> None:
        if type(self.binding) is not EvidenceBinding:
            raise EvidenceIdentityRejected("binding must be a typed immutable scope")
        _tag("evaluator_version", self.evaluator_version)
        if type(self.records) is not tuple or not self.records:
            raise EvidenceIdentityRejected("records must be a nonempty immutable tuple")
        ids: set[UUID] = set()
        for record in self.records:
            if type(record) is not EvidenceRecord:
                raise EvidenceIdentityRejected("records must contain EvidenceRecord values")
            if record.binding != self.binding:
                raise EvidenceIdentityRejected("cross-scope or mismatched record")
            if record.evidence_id in ids:
                raise EvidenceIdentityRejected("duplicate evidence_id")
            ids.add(record.evidence_id)

    def packet_digest(self) -> str:
        """Content fingerprint only; reject corrupted nested runtime values first."""
        checked = _revalidated_packet(self)
        identity: dict[str, object] = {
            "domain": "gasha-evidence-packet-identity-v1",
            "binding": checked.binding._identity(),
            "evaluator_version": checked.evaluator_version,
            "records": [
                record._identity()
                for record in sorted(checked.records, key=lambda entry: entry.evidence_id.int)
            ],
        }
        payload = dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return "sha256:" + sha256(payload.encode("utf-8")).hexdigest()


def _revalidated_binding(value: EvidenceBinding) -> EvidenceBinding:
    """Re-run construction checks; frozen instances may be mutated via object.__setattr__."""
    if type(value) is not EvidenceBinding:
        raise EvidenceIdentityRejected("typed evidence binding required")
    try:
        return replace(value)
    except AttributeError:
        raise EvidenceIdentityRejected("missing evidence binding attribute") from None


def _revalidated_packet(packet: EvidencePacket) -> EvidencePacket:
    """Validate nested shape before fingerprint or freshness; this does not attest origin."""
    if type(packet) is not EvidencePacket:
        raise EvidenceIdentityRejected("typed packet required")
    try:
        if type(packet.records) is not tuple:
            raise EvidenceIdentityRejected("records must be a nonempty immutable tuple")
        scope = _revalidated_binding(packet.binding)
        records: list[EvidenceRecord] = []
        for record in packet.records:
            if type(record) is not EvidenceRecord:
                raise EvidenceIdentityRejected("records must contain EvidenceRecord values")
            records.append(replace(record, binding=_revalidated_binding(record.binding)))
        return EvidencePacket(scope, packet.evaluator_version, tuple(records))
    except AttributeError:
        raise EvidenceIdentityRejected("missing packet or record attribute") from None


def assert_packet_current(
    packet: EvidencePacket, *, expected: EvidenceBinding, now: datetime
) -> None:
    """Mechanical scope/freshness check, NOT artifact verification or approval.

    Must never be used as a bank-readiness gate or as proof of evidence origin.
    """
    if type(packet) is not EvidencePacket or type(expected) is not EvidenceBinding:
        raise EvidenceIdentityRejected("typed packet and expected binding required")
    checked = _revalidated_packet(packet)
    scope = _revalidated_binding(expected)
    current = _time("now", now)
    if checked.binding != scope:
        raise EvidenceIdentityRejected("evidence binding mismatch")
    for record in checked.records:
        if record.binding != scope:
            raise EvidenceIdentityRejected("record binding mismatch")
        if _time("collected_at", record.collected_at) > current:
            raise EvidenceIdentityRejected("future-dated evidence")
        if _time("expires_at", record.expires_at) <= current:
            raise EvidenceIdentityRejected("expired evidence")
