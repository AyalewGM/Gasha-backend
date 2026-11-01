"""Issue #44: inert, version-pinned risk-list matching reference kernel.

This is an internal-only policy *proposal*. It does not authenticate a source,
perform list administration, change DecisionService, or authorize BLOCK/HOLD.
The Bank must approve conflict precedence and supply immutable, authenticated
snapshots before any production decision-path integration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from json import dumps
from uuid import UUID

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class RiskListRejected(ValueError):
    """Malformed, out-of-scope or untrustworthy reference risk-list input."""


class RiskListKind(StrEnum):
    ALLOW = "allow"
    WATCH = "watch"
    BLOCK = "block"


class SubjectKind(StrEnum):
    BANK = "bank"
    CUSTOMER = "customer"
    ACCOUNT = "account"
    BENEFICIARY = "beneficiary"


def _tag(value: object, name: str) -> None:
    if type(value) is not str or _TAG.fullmatch(value) is None:
        raise RiskListRejected(f"{name} must be an opaque version/scope token")


def _time(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise RiskListRejected(f"{name} must be timezone aware")
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class RiskListSubject:
    """Bank-tokenized reference; never use a raw or merely unsalted PII hash."""

    kind: SubjectKind
    token: str

    def __post_init__(self) -> None:
        if type(self.kind) is not SubjectKind:
            raise RiskListRejected("typed subject kind required")
        if type(self.token) is not str or _TOKEN.fullmatch(self.token) is None:
            raise RiskListRejected("bank-tokenized 64-character opaque subject required")


@dataclass(frozen=True, slots=True)
class RiskListEntry:
    entry_id: UUID
    kind: RiskListKind
    subject: RiskListSubject
    effective_from: datetime
    effective_until: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.entry_id) is not UUID or type(self.kind) is not RiskListKind:
            raise RiskListRejected("typed entry identity and list kind required")
        if type(self.subject) is not RiskListSubject:
            raise RiskListRejected("typed subject reference required")
        start = _time(self.effective_from, "effective_from")
        end = None if self.effective_until is None else _time(
            self.effective_until, "effective_until"
        )
        revoked = None if self.revoked_at is None else _time(self.revoked_at, "revoked_at")
        if end is not None and end <= start:
            raise RiskListRejected("effective interval must be positive")
        object.__setattr__(self, "effective_from", start)
        object.__setattr__(self, "effective_until", end)
        object.__setattr__(self, "revoked_at", revoked)

    def active_at(self, instant: datetime) -> bool:
        """Half-open effective interval; revocation takes effect inclusively."""
        at = _time(instant, "event_at")
        return (
            self.effective_from <= at
            and (self.effective_until is None or at < self.effective_until)
            and (self.revoked_at is None or at < self.revoked_at)
        )


@dataclass(frozen=True, slots=True)
class RiskListSnapshot:
    tenant_id: str
    list_version: str
    policy_version: str
    published_at: datetime
    entries: tuple[RiskListEntry, ...]

    def __post_init__(self) -> None:
        _tag(self.tenant_id, "tenant_id")
        _tag(self.list_version, "list_version")
        _tag(self.policy_version, "policy_version")
        object.__setattr__(self, "published_at", _time(self.published_at, "published_at"))
        if type(self.entries) is not tuple:
            raise RiskListRejected("immutable tuple of entries required")
        ids: set[UUID] = set()
        for entry in self.entries:
            if type(entry) is not RiskListEntry:
                raise RiskListRejected("typed entries required")
            if entry.entry_id in ids:
                raise RiskListRejected("duplicate list entry identity")
            ids.add(entry.entry_id)

    def digest(self) -> str:
        """Content fingerprint only, not evidence of list authority or origin."""
        body = {
            "domain": "gasha-risk-list-snapshot-reference-v1",
            "tenant_id": self.tenant_id,
            "list_version": self.list_version,
            "policy_version": self.policy_version,
            "published_at": _iso(self.published_at),
            "entries": [
                {
                    "entry_id": str(entry.entry_id),
                    "kind": entry.kind.value,
                    "subject_kind": entry.subject.kind.value,
                    "subject_token": entry.subject.token,
                    "effective_from": _iso(entry.effective_from),
                    "effective_until": (
                        None if entry.effective_until is None else _iso(entry.effective_until)
                    ),
                    "revoked_at": None if entry.revoked_at is None else _iso(entry.revoked_at),
                }
                for entry in sorted(self.entries, key=lambda item: item.entry_id.int)
            ],
        }
        canonical = dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return "sha256:" + sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RiskListMatch:
    """Provisional list match: never a payment decision or release authority."""

    kind: RiskListKind | None
    reason_codes: tuple[str, ...]
    matched_entry_ids: tuple[UUID, ...]
    list_version: str
    policy_version: str
    snapshot_digest: str

    @property
    def enforcement_activated(self) -> bool:
        return False


# PROVISIONAL precedence, not a Bank-approved action policy. The returned kind
# is advisory; it NEVER overrides fraud scoring or issues a payment HOLD/BLOCK.
_RANK = {RiskListKind.ALLOW: 1, RiskListKind.WATCH: 2, RiskListKind.BLOCK: 3}
_REASON = {
    RiskListKind.ALLOW: "RISK_LIST_ALLOW_MATCH",
    RiskListKind.WATCH: "RISK_LIST_WATCH_MATCH",
    RiskListKind.BLOCK: "RISK_LIST_BLOCK_MATCH",
}


def match_reference_snapshot(
    snapshot: RiskListSnapshot,
    *,
    expected_tenant: str,
    expected_list_version: str,
    expected_policy_version: str,
    event_at: datetime,
    subjects: tuple[RiskListSubject, ...],
) -> RiskListMatch:
    """Match only an explicitly pinned synthetic snapshot at an as-of instant.

    The caller-provided snapshot/scope cannot establish Bank authorization;
    do not wire this helper to protected APIs or decision enforcement.
    """
    if type(snapshot) is not RiskListSnapshot:
        raise RiskListRejected("typed snapshot required")
    _tag(expected_tenant, "expected_tenant")
    _tag(expected_list_version, "expected_list_version")
    _tag(expected_policy_version, "expected_policy_version")
    at = _time(event_at, "event_at")
    if (
        snapshot.tenant_id != expected_tenant
        or snapshot.list_version != expected_list_version
        or snapshot.policy_version != expected_policy_version
    ):
        raise RiskListRejected("snapshot scope or version mismatch")
    if snapshot.published_at > at:
        raise RiskListRejected("snapshot was not published at event time")
    if type(subjects) is not tuple or any(type(subject) is not RiskListSubject for subject in subjects):
        raise RiskListRejected("immutable typed subjects required")
    if len(set(subjects)) != len(subjects):
        raise RiskListRejected("duplicate subject reference")
    subject_set = set(subjects)
    selected = tuple(sorted(
        (entry for entry in snapshot.entries
         if entry.subject in subject_set and entry.active_at(at)),
        key=lambda entry: entry.entry_id.int,
    ))
    kind = max((entry.kind for entry in selected), key=_RANK.__getitem__, default=None)
    return RiskListMatch(
        kind=kind,
        reason_codes=(_REASON[kind],) if kind is not None else ("RISK_LIST_NO_MATCH",),
        matched_entry_ids=tuple(entry.entry_id for entry in selected),
        list_version=snapshot.list_version,
        policy_version=snapshot.policy_version,
        snapshot_digest=snapshot.digest(),
    )
