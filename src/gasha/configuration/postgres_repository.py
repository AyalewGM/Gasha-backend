"""Issue #147: PostgreSQL tenant configuration store, deliberately not wired.

This opt-in adapter persists entries planned by the inert kernel. It does not
install itself, obtain credentials, or grant authority: the deployer injects a
least-privilege connection owned by a separately authorized provisioning-writer
role for writes and a runtime-reader role for reads. A ``provisioner_ref`` is an
opaque provisioning-identity reference recorded for audit; it is not a runtime
API principal and carries no request-derived authority.

Activation composes kernel validation with a PostgreSQL advisory transaction
lock per (tenant, config kind) scope so retire+activate stays atomic. Lifecycle
transitions and their redacted audit rows commit in ONE transaction; a separate
auto-committing audit sink must not be called here.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from uuid import uuid4
from zoneinfo import ZoneInfo

from gasha.configuration.kernel import (
    ConfigKind,
    ConfigLifecycle,
    TenantConfigConflict,
    TenantConfigEntry,
    TenantConfigRejected,
    decode_row,
    new_draft,
    plan_activation,
    plan_retirement,
    resolve_active,
)
from gasha.postgres import Connection, Cursor
from gasha.security.access import tenant_audit_ref

_REF = re.compile(r"[0-9a-f]{64}\Z")
_COLUMNS = (
    "tenant_id, config_kind, version, lifecycle, content_json, content_digest, "
    "created_at, created_by_ref, activated_at, retired_at, supersedes_version"
)
_SCOPE_SQL = (
    f"SELECT {_COLUMNS} FROM tenant_configurations "
    "WHERE tenant_id = %s AND config_kind = %s ORDER BY version"
)
_AUDIT_SQL = (
    "INSERT INTO security_audit_events ("
    "occurred_at, action, result, actor_ref, tenant_ref, reason, attempt_ref, "
    "event_ref, context_ref"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


def _scope_ref(tenant_id: str, config_kind: ConfigKind) -> str:
    return dumps(
        ["gasha-tenant-config-v1", tenant_id, str(config_kind)],
        separators=(",", ":"),
    )


def _event_ref(entry: TenantConfigEntry) -> str:
    return sha256(
        dumps(
            [
                "gasha-tenant-config-v1",
                entry.tenant_id,
                str(entry.config_kind),
                entry.version,
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _actor_ref(provisioner_ref: object) -> str:
    # The provisioning identity is an opaque reference, never a raw name/PII.
    if type(provisioner_ref) is not str or _REF.fullmatch(provisioner_ref) is None:
        raise TenantConfigRejected("provisioner_ref must be a 64-hex opaque reference")
    return provisioner_ref


def _trusted_at(at: object) -> datetime:
    if (
        type(at) is not datetime
        or type(at.tzinfo) not in (timezone, ZoneInfo)
        or at.utcoffset() is None
    ):
        raise TenantConfigRejected("trusted aware clock required")
    return at.astimezone(UTC)


def _tenant(tenant_id: object) -> str:
    if type(tenant_id) is not str or not tenant_id.strip():
        raise TenantConfigRejected("typed tenant required")
    return tenant_id


def _kind(config_kind: object) -> ConfigKind:
    if type(config_kind) is not ConfigKind:
        raise TenantConfigRejected("typed configuration kind required")
    return config_kind


def _read_scope(
    cursor: Cursor, *, tenant_id: str, config_kind: ConfigKind
) -> tuple[TenantConfigEntry, ...]:
    cursor.execute(_SCOPE_SQL, (tenant_id, str(config_kind)))
    rows = cursor.fetchall()
    return tuple(decode_row(row) for row in rows)


def _active_of(
    entries: tuple[TenantConfigEntry, ...],
) -> TenantConfigEntry | None:
    active = [e for e in entries if e.lifecycle is ConfigLifecycle.ACTIVE]
    if len(active) > 1:
        raise TenantConfigRejected("store carries multiple active rows")
    return active[0] if active else None


class PostgresTenantConfigurationService:
    """Tenant-scoped configuration store; no API, identity or authority source."""

    def __init__(self, connection: Connection) -> None:
        # Advisory transaction locks, lifecycle writes and audit inserts must
        # share ONE transaction. Autocommit would release the lock at each SQL
        # statement and could leave a retired incumbent after audit failure.
        # Unknown connection modes are rejected instead of assumed safe.
        if getattr(connection, "autocommit", None) is not False:
            raise TenantConfigRejected("tenant configuration requires autocommit=False")
        self._connection = connection

    def _lock_scope(self, cursor: Cursor, tenant_id: str, kind: ConfigKind) -> None:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (_scope_ref(tenant_id, kind),),
        )

    def _audit(
        self,
        cursor: Cursor,
        *,
        action: str,
        actor_ref: str,
        tenant_id: str,
        entry: TenantConfigEntry,
        at: datetime,
    ) -> None:
        cursor.execute(
            _AUDIT_SQL,
            (
                at,
                action,
                "allowed",
                actor_ref,
                tenant_audit_ref(tenant_id),
                "tenant_config_lifecycle_committed",
                uuid4().hex,
                _event_ref(entry),
                entry.content_digest,
            ),
        )

    def entries(self, *, tenant_id: str, config_kind: ConfigKind) -> tuple[TenantConfigEntry, ...]:
        """Read a scope's full version history; every row is re-validated."""
        _tenant(tenant_id)
        _kind(config_kind)
        try:
            with self._connection.cursor() as cursor:
                return _read_scope(cursor, tenant_id=tenant_id, config_kind=config_kind)
        finally:
            self._connection.rollback()

    def resolve(
        self,
        *,
        tenant_id: str,
        config_kind: ConfigKind,
        at: datetime,
        horizon: datetime | None = None,
    ) -> TenantConfigEntry:
        """Resolve the version covering ``at``; fails closed like the kernel."""
        at_utc = _trusted_at(at)
        horizon_utc = None if horizon is None else _trusted_at(horizon)
        rows = self.entries(tenant_id=tenant_id, config_kind=config_kind)
        return resolve_active(
            list(rows),
            tenant_id=tenant_id,
            config_kind=config_kind,
            at=at_utc,
            horizon=horizon_utc,
        )

    def create_draft(
        self,
        *,
        provisioner_ref: str,
        tenant_id: str,
        config_kind: ConfigKind,
        payload: object,
        at: datetime,
    ) -> TenantConfigEntry:
        """Mint the next DRAFT version; identical-content replay returns existing."""
        actor = _actor_ref(provisioner_ref)
        tenant = _tenant(tenant_id)
        kind = _kind(config_kind)
        now = _trusted_at(at)
        try:
            with self._connection.cursor() as cursor:
                self._lock_scope(cursor, tenant, kind)
                existing = _read_scope(cursor, tenant_id=tenant, config_kind=kind)
                candidate = new_draft(
                    tenant_id=tenant,
                    config_kind=kind,
                    version=(existing[-1].version + 1) if existing else 1,
                    payload=payload,
                    created_at=now,
                    created_by_ref=actor,
                )
                # Identical replay: an existing draft with the same content is
                # the intended record — no duplicate row and no second audit.
                for entry in existing:
                    if (
                        entry.lifecycle is ConfigLifecycle.DRAFT
                        and entry.content_digest == candidate.content_digest
                    ):
                        self._connection.rollback()
                        return entry
                cursor.execute(
                    f"INSERT INTO tenant_configurations ({_COLUMNS}) VALUES ("
                    "%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s)",
                    (
                        candidate.tenant_id,
                        str(candidate.config_kind),
                        candidate.version,
                        str(candidate.lifecycle),
                        candidate.content_json,
                        candidate.content_digest,
                        candidate.created_at,
                        candidate.created_by_ref,
                        candidate.activated_at,
                        candidate.retired_at,
                        candidate.supersedes_version,
                    ),
                )
                self._audit(
                    cursor,
                    action="tenant_config.draft",
                    actor_ref=actor,
                    tenant_id=tenant,
                    entry=candidate,
                    at=now,
                )
            self._connection.commit()
            return candidate
        except Exception as exc:
            self._connection.rollback()
            if getattr(exc, "sqlstate", None) == "23505":
                raise TenantConfigConflict("configuration version or uniqueness conflict") from exc
            raise

    def activate(
        self,
        *,
        provisioner_ref: str,
        tenant_id: str,
        config_kind: ConfigKind,
        version: int,
        at: datetime,
    ) -> TenantConfigEntry:
        """Atomically retire the incumbent and activate a draft version."""
        actor = _actor_ref(provisioner_ref)
        tenant = _tenant(tenant_id)
        kind = _kind(config_kind)
        now = _trusted_at(at)
        if type(version) is not int or isinstance(version, bool) or version <= 0:
            raise TenantConfigRejected("typed version required")
        try:
            with self._connection.cursor() as cursor:
                self._lock_scope(cursor, tenant, kind)
                entries = _read_scope(cursor, tenant_id=tenant, config_kind=kind)
                candidate = next((e for e in entries if e.version == version), None)
                if candidate is None:
                    raise TenantConfigRejected("no configuration row at version")
                if candidate.lifecycle is ConfigLifecycle.ACTIVE:
                    # Identical replay: already active, no second audit.
                    self._connection.rollback()
                    return candidate
                incumbent = _active_of(entries)
                retired, activated = plan_activation(
                    candidate=candidate, incumbent=incumbent, at=now
                )
                for entry in (retired, activated):
                    if entry is None:
                        continue
                    cursor.execute(
                        "UPDATE tenant_configurations SET lifecycle = %s, "
                        "activated_at = %s, retired_at = %s, "
                        "supersedes_version = %s WHERE tenant_id = %s AND "
                        "config_kind = %s AND version = %s",
                        (
                            str(entry.lifecycle),
                            entry.activated_at,
                            entry.retired_at,
                            entry.supersedes_version,
                            entry.tenant_id,
                            str(entry.config_kind),
                            entry.version,
                        ),
                    )
                self._audit(
                    cursor,
                    action="tenant_config.activate",
                    actor_ref=actor,
                    tenant_id=tenant,
                    entry=activated,
                    at=now,
                )
            self._connection.commit()
            return activated
        except Exception as exc:
            self._connection.rollback()
            if getattr(exc, "sqlstate", None) == "23505":
                raise TenantConfigConflict("configuration activation conflict") from exc
            raise

    def retire(
        self,
        *,
        provisioner_ref: str,
        tenant_id: str,
        config_kind: ConfigKind,
        version: int,
        at: datetime,
    ) -> TenantConfigEntry:
        """Retire an ACTIVE version (e.g. decommissioning a kind for a tenant)."""
        actor = _actor_ref(provisioner_ref)
        tenant = _tenant(tenant_id)
        kind = _kind(config_kind)
        now = _trusted_at(at)
        if type(version) is not int or isinstance(version, bool) or version <= 0:
            raise TenantConfigRejected("typed version required")
        try:
            with self._connection.cursor() as cursor:
                self._lock_scope(cursor, tenant, kind)
                entries = _read_scope(cursor, tenant_id=tenant, config_kind=kind)
                target = next((e for e in entries if e.version == version), None)
                if target is None:
                    raise TenantConfigRejected("no configuration row at version")
                if target.lifecycle is ConfigLifecycle.RETIRED:
                    # Identical replay: already retired, no second audit.
                    self._connection.rollback()
                    return target
                retired = plan_retirement(entry=target, at=now)
                cursor.execute(
                    "UPDATE tenant_configurations SET lifecycle = %s, "
                    "retired_at = %s WHERE tenant_id = %s AND config_kind = %s "
                    "AND version = %s",
                    (
                        str(retired.lifecycle),
                        retired.retired_at,
                        retired.tenant_id,
                        str(retired.config_kind),
                        retired.version,
                    ),
                )
                self._audit(
                    cursor,
                    action="tenant_config.retire",
                    actor_ref=actor,
                    tenant_id=tenant,
                    entry=retired,
                    at=now,
                )
            self._connection.commit()
            return retired
        except Exception as exc:
            self._connection.rollback()
            if getattr(exc, "sqlstate", None) == "23505":
                raise TenantConfigConflict("configuration retirement conflict") from exc
            raise
