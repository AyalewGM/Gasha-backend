"""Issue #147: inert tenant configuration kernel (slice 1).

Validates versioned tenant configuration entries and their lifecycle
transitions. This kernel authenticates nothing, writes nothing, selects no
runtime policy and grants no authority. An explicitly installed, trusted
provisioning writer and a separately approved durable store are required
before any row exists; a trusted reader plus independent review are required
before any decision path resolves configuration through it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timezone
from enum import StrEnum
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from math import isfinite
from typing import Any, cast
from zoneinfo import ZoneInfo

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REF = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA = "gasha-tenant-config-v1"
_DECISION_POLICY_KEYS = frozenset(
    {
        "configuration_version",
        "policy_version",
        "rule_version",
        "model_version",
        "monitor_threshold",
        "review_threshold",
        "hold_threshold",
        "block_threshold",
    }
)
_POLICY_VERSION_FIELDS = (
    "configuration_version",
    "policy_version",
    "rule_version",
)
_THRESHOLD_FIELDS = (
    "monitor_threshold",
    "review_threshold",
    "hold_threshold",
    "block_threshold",
)
_KNOWN_DETECTORS = frozenset(
    {
        "social_engineering",
        "behavioral_session",
        "internal_graph",
        "journey",
    }
)


class TenantConfigRejected(ValueError):
    """Malformed, inconsistent or untrustworthy tenant configuration input."""


class ConfigKind(StrEnum):
    DECISION_POLICY = "decision_policy"
    DETECTOR_POLICY_BUNDLE = "detector_policy_bundle"


class ConfigLifecycle(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"


def _tag(name: str, value: object) -> None:
    if type(value) is not str or _TAG.fullmatch(value) is None:
        raise TenantConfigRejected(f"{name} must be a bounded opaque tag")


def _ref(name: str, value: object) -> None:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise TenantConfigRejected(f"{name} must be a 64-hex opaque reference")


def _time(name: str, value: object) -> datetime:
    # Validate the concrete clock implementation before any timezone hook:
    # datetime subclasses and custom tzinfo objects can execute caller code.
    # type() checks, not isinstance(), reject forged __class__ properties.
    if type(value) is not datetime:
        raise TenantConfigRejected(f"{name} must be a trusted timezone-aware datetime")
    if type(value.tzinfo) not in (timezone, ZoneInfo):
        raise TenantConfigRejected(f"{name} must use an allowed clock")
    if value.utcoffset() is None:
        raise TenantConfigRejected(f"{name} must be timezone aware")
    return value.astimezone(UTC)


def _optional_time(name: str, value: object) -> datetime | None:
    return None if value is None else _time(name, value)


def _canonical(payload: object) -> str:
    try:
        return dumps(
            payload, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise TenantConfigRejected("configuration content must be finite JSON") from exc


def _number(name: str, value: object) -> float:
    # type(True) is bool, not int — the membership test already rejects JSON
    # booleans and hostile numeric subclasses.
    if type(value) not in (int, float):
        raise TenantConfigRejected(f"{name} must be a numeric risk score")
    try:
        numeric = float(cast("int | float", value))
    except OverflowError as exc:
        raise TenantConfigRejected(f"{name} exceeds a finite risk score") from exc
    if not isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise TenantConfigRejected(f"{name} must be within [0, 1]")
    return numeric


def _validate_decision_policy(payload: object) -> None:
    if type(payload) is not dict or frozenset(payload) != _DECISION_POLICY_KEYS:
        raise TenantConfigRejected(
            "decision_policy content must carry exactly the DecisionPolicy fields"
        )
    for field in _POLICY_VERSION_FIELDS:
        _tag(field, payload[field])
    model_version = payload["model_version"]
    if model_version is not None:
        _tag("model_version", model_version)
    thresholds = [_number(name, payload[name]) for name in _THRESHOLD_FIELDS]
    if thresholds != sorted(thresholds) or len(set(thresholds)) != len(thresholds):
        raise TenantConfigRejected("decision thresholds must be strictly increasing")


def _scalar(name: str, value: object) -> None:
    # v1 detector parameters are bounded to JSON scalars; nested structures
    # require a later contract revision, not silent acceptance.
    if type(value) not in (str, int, float, bool, type(None)):
        raise TenantConfigRejected(f"{name} must be a scalar parameter")
    if type(value) is float and not isfinite(value):
        raise TenantConfigRejected(f"{name} must be a finite JSON number")


def _validate_detector_bundle(payload: object) -> None:
    if type(payload) is not dict or not payload:
        raise TenantConfigRejected("detector_policy_bundle must be a non-empty object")
    unknown = frozenset(payload) - _KNOWN_DETECTORS
    if unknown:
        raise TenantConfigRejected(f"unrecognized detector policies: {sorted(unknown)}")
    for detector, policy in payload.items():
        if type(policy) is not dict or "policy_version" not in policy:
            raise TenantConfigRejected(f"{detector} policy must carry a policy_version")
        _tag(f"{detector}.policy_version", policy["policy_version"])
        if len(policy) < 2:
            raise TenantConfigRejected(f"{detector} policy must declare parameters")
        for key, value in policy.items():
            if type(key) is not str or _TAG.fullmatch(key) is None:
                raise TenantConfigRejected(f"{detector} parameter names must be tags")
            if key != "policy_version":
                _scalar(f"{detector}.{key}", value)


def canonical_content(config_kind: ConfigKind, payload: object) -> str:
    """Validate a payload for ``config_kind`` and return its canonical JSON."""
    if type(config_kind) is not ConfigKind:
        raise TenantConfigRejected("typed configuration kind required")
    if config_kind is ConfigKind.DECISION_POLICY:
        _validate_decision_policy(payload)
    else:
        _validate_detector_bundle(payload)
    return _canonical(payload)


def content_digest(config_kind: ConfigKind, canonical_json: str) -> str:
    """Domain-separated digest binding a kind to its canonical content bytes."""
    if type(config_kind) is not ConfigKind:
        raise TenantConfigRejected("typed configuration kind required")
    if type(canonical_json) is not str or not canonical_json:
        raise TenantConfigRejected("canonical content required")
    preimage = _canonical(
        {
            "schema": _SCHEMA,
            "config_kind": str(config_kind),
            "content_json": canonical_json,
        }
    )
    return sha256(preimage.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TenantConfigEntry:
    """One immutable-content configuration row and its lifecycle fields."""

    tenant_id: str
    config_kind: ConfigKind
    version: int
    lifecycle: ConfigLifecycle
    content_json: str
    content_digest: str
    created_at: datetime
    created_by_ref: str
    activated_at: datetime | None
    retired_at: datetime | None
    supersedes_version: int | None

    def __post_init__(self) -> None:
        _tag("tenant_id", self.tenant_id)
        if type(self.config_kind) is not ConfigKind:
            raise TenantConfigRejected("typed configuration kind required")
        if type(self.version) is not int or isinstance(self.version, bool) or self.version <= 0:
            raise TenantConfigRejected("version must be a positive integer")
        if type(self.lifecycle) is not ConfigLifecycle:
            raise TenantConfigRejected("typed lifecycle state required")
        created = _time("created_at", self.created_at)
        activated = _optional_time("activated_at", self.activated_at)
        retired = _optional_time("retired_at", self.retired_at)
        _ref("created_by_ref", self.created_by_ref)
        if type(self.content_json) is not str or not self.content_json:
            raise TenantConfigRejected("canonical content required")
        # Stored content must be canonical JSON, not merely parseable, so two
        # byte-distinct spellings cannot share identity.
        try:
            decoded = loads(self.content_json)
        except JSONDecodeError as exc:
            raise TenantConfigRejected("content must be JSON") from exc
        # A matching digest binds bytes, not policy semantics. Validate schema
        # on every stored-row read and on dataclasses.replace() construction.
        if canonical_content(self.config_kind, decoded) != self.content_json:
            raise TenantConfigRejected("content must be canonical and match its kind")
        _ref("content_digest", self.content_digest)
        if self.content_digest != content_digest(self.config_kind, self.content_json):
            raise TenantConfigRejected("content digest does not bind this content")
        if type(self.supersedes_version) is not int and self.supersedes_version is not None:
            raise TenantConfigRejected("supersedes_version must be an integer or None")
        if self.supersedes_version is not None and self.supersedes_version >= self.version:
            raise TenantConfigRejected("a version cannot supersede itself or later")
        if self.lifecycle is ConfigLifecycle.DRAFT:
            if activated is not None or retired is not None or self.supersedes_version is not None:
                raise TenantConfigRejected("draft entries carry no transition fields")
        elif self.lifecycle is ConfigLifecycle.ACTIVE:
            if activated is None or retired is not None:
                raise TenantConfigRejected("active entries require activation only")
            if activated < created:
                raise TenantConfigRejected("activation cannot precede creation")
        else:
            if activated is None or retired is None:
                raise TenantConfigRejected("retired entries keep their full history")
            if activated < created or retired < activated:
                raise TenantConfigRejected("lifecycle instants must be ordered")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "activated_at", activated)
        object.__setattr__(self, "retired_at", retired)


def new_draft(
    *,
    tenant_id: str,
    config_kind: ConfigKind,
    version: int,
    payload: object,
    created_at: datetime,
    created_by_ref: str,
) -> TenantConfigEntry:
    """Construct a validated DRAFT entry for a provisioning writer to persist."""
    canonical = canonical_content(config_kind, payload)
    return TenantConfigEntry(
        tenant_id=tenant_id,
        config_kind=config_kind,
        version=version,
        lifecycle=ConfigLifecycle.DRAFT,
        content_json=canonical,
        content_digest=content_digest(config_kind, canonical),
        created_at=created_at,
        created_by_ref=created_by_ref,
        activated_at=None,
        retired_at=None,
        supersedes_version=None,
    )


def plan_activation(
    *,
    candidate: TenantConfigEntry,
    incumbent: TenantConfigEntry | None,
    at: datetime,
) -> tuple[TenantConfigEntry | None, TenantConfigEntry]:
    """Validate an activation and return ``(retired_incumbent, activated)``.

    The caller must persist both rows atomically. The first activation of a
    ``(tenant, kind)`` passes ``incumbent=None`` and yields ``(None, active)``.
    """
    now = _time("at", at)
    if type(candidate) is not TenantConfigEntry:
        raise TenantConfigRejected("typed candidate required")
    if candidate.lifecycle is not ConfigLifecycle.DRAFT:
        raise TenantConfigRejected("only a draft can be activated")
    if now < candidate.created_at:
        raise TenantConfigRejected("activation cannot precede creation")
    if incumbent is None:
        if candidate.version != 1:
            raise TenantConfigRejected("first activation requires version 1")
        activated = replace(
            candidate,
            lifecycle=ConfigLifecycle.ACTIVE,
            activated_at=now,
        )
        return None, activated
    if type(incumbent) is not TenantConfigEntry:
        raise TenantConfigRejected("typed incumbent required")
    if (
        incumbent.tenant_id != candidate.tenant_id
        or incumbent.config_kind is not candidate.config_kind
    ):
        raise TenantConfigRejected("incumbent must share tenant and config kind")
    if incumbent.lifecycle is not ConfigLifecycle.ACTIVE:
        raise TenantConfigRejected("incumbent must currently be active")
    if candidate.version <= incumbent.version:
        raise TenantConfigRejected("activation must advance the version")
    incumbent_activated = incumbent.activated_at
    if incumbent_activated is None or now < incumbent_activated:
        raise TenantConfigRejected("cannot retire an incumbent before it activated")
    retired = replace(incumbent, lifecycle=ConfigLifecycle.RETIRED, retired_at=now)
    activated = replace(
        candidate,
        lifecycle=ConfigLifecycle.ACTIVE,
        activated_at=now,
        supersedes_version=incumbent.version,
    )
    return retired, activated


def plan_retirement(*, entry: TenantConfigEntry, at: datetime) -> TenantConfigEntry:
    """Validate retirement of an ACTIVE entry (e.g. decommissioning a kind)."""
    now = _time("at", at)
    if type(entry) is not TenantConfigEntry:
        raise TenantConfigRejected("typed entry required")
    if entry.lifecycle is not ConfigLifecycle.ACTIVE:
        raise TenantConfigRejected("only an active entry can be retired")
    activated_at = entry.activated_at
    if activated_at is None or now < activated_at:
        raise TenantConfigRejected("cannot retire before activation")
    return replace(entry, lifecycle=ConfigLifecycle.RETIRED, retired_at=now)


def decode_row(row: object) -> TenantConfigEntry:
    """Decode and fully re-validate a stored row before trusting any field."""
    if not isinstance(row, Mapping):
        raise TenantConfigRejected("stored row required")
    fields = (
        "tenant_id",
        "config_kind",
        "version",
        "lifecycle",
        "content_json",
        "content_digest",
        "created_at",
        "created_by_ref",
        "activated_at",
        "retired_at",
        "supersedes_version",
    )
    try:
        values: dict[str, Any] = {name: row[name] for name in fields}
    except KeyError as exc:
        raise TenantConfigRejected(f"stored row missing {exc.args[0]}") from exc
    try:
        values["config_kind"] = ConfigKind(values["config_kind"])
        values["lifecycle"] = ConfigLifecycle(values["lifecycle"])
    except ValueError as exc:
        raise TenantConfigRejected("stored row carries unknown kind or lifecycle") from exc
    # JSONB drivers may return parsed objects; re-canonicalize so the stored
    # digest is still bound to canonical bytes, never to driver formatting.
    content = values["content_json"]
    if isinstance(content, Mapping):
        try:
            values["content_json"] = _canonical(dict(content))
        except (TypeError, ValueError) as exc:
            raise TenantConfigRejected("stored content is not canonical JSON") from exc
    return TenantConfigEntry(**values)


def resolve_active(
    rows: object,
    *,
    tenant_id: str,
    config_kind: ConfigKind,
    at: datetime,
    horizon: datetime | None = None,
) -> TenantConfigEntry:
    """Resolve the single version covering instant ``at``; fail closed.

    ``rows`` are store-provided mappings. Every row is re-validated; a corrupt
    or ambiguous store raises rather than guessing. A historical ``at`` simply
    ignores later activations, keeping replay deterministic. When ``horizon``
    is supplied (the caller's trusted "now"), a same-scope row claiming an
    activation after that instant is corrupt and the whole read is rejected.
    """
    now = _time("at", at)
    trust = _optional_time("horizon", horizon)
    _tag("tenant_id", tenant_id)
    if type(config_kind) is not ConfigKind:
        raise TenantConfigRejected("typed configuration kind required")
    if type(rows) not in (list, tuple):
        raise TenantConfigRejected("stored rows required")
    covering: list[TenantConfigEntry] = []
    for raw in cast("list[object] | tuple[object, ...]", rows):
        # Raw store rows are re-validated; typed entries are already trusted.
        entry = raw if type(raw) is TenantConfigEntry else decode_row(raw)
        if entry.tenant_id != tenant_id or entry.config_kind is not config_kind:
            continue
        activated = entry.activated_at
        if activated is None:
            continue
        if trust is not None and activated > trust:
            raise TenantConfigRejected("store carries a future activation")
        retired_at = entry.retired_at
        if activated <= now and (retired_at is None or now < retired_at):
            covering.append(entry)
    if len(covering) != 1:
        raise TenantConfigRejected("exactly one active configuration must cover the instant")
    return covering[0]


class TenantConfigConflict(TenantConfigRejected):
    """Optimistic uniqueness/lifecycle conflict; no write was committed."""
