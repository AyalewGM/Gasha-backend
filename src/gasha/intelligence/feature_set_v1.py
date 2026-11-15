"""Offline, synthetic-only point-in-time behavioral features for Gasha #145.

No network, storage, ML inference, decisioning or Bank-data access.
Input identifiers must already be approved pseudonyms. Feature counts exclude
the target event; historical events with the target timestamp are excluded.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from json import dumps

FEATURE_VERSION = "gasha-feature-set-v1"
_WINDOW = timedelta(hours=1)


def _utc(name: str, value: object) -> datetime:
    # Never invoke a caller-defined datetime/tzinfo callback.
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        raise ValueError(f"{name} must be an ordinary timezone-aware datetime")
    return value.astimezone(UTC)


def _digest(value: object) -> str:
    return sha256(
        dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ObservedTransfer:
    tenant_id: str
    event_id: str
    account_ref: str
    beneficiary_ref: str | None
    device_ref: str | None
    occurred_at: datetime
    available_at: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "event_id", "account_ref"):
            v = object.__getattribute__(self, name)
            if type(v) is not str or not v or len(v) > 128:
                raise ValueError(f"invalid {name}")
        for name in ("beneficiary_ref", "device_ref"):
            v = object.__getattribute__(self, name)
            if v is not None and (type(v) is not str or not v or len(v) > 128):
                raise ValueError(f"invalid {name}")
        occurred = _utc("occurred_at", object.__getattribute__(self, "occurred_at"))
        available = _utc("available_at", object.__getattribute__(self, "available_at"))
        if available < occurred:
            raise ValueError("availability cannot precede event occurrence")
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "available_at", available)


@dataclass(frozen=True, slots=True)
class FeatureSetV1:
    version: str
    tenant_id: str
    event_id: str
    decision_as_of: datetime
    account_transfers_1h: int
    beneficiary_unique_senders_1h: int | None
    distinct_accounts_on_device_1h: int | None
    sender_beneficiary_seen_before: bool | None
    missing: tuple[str, ...]
    source_fingerprint: str
    computation_fingerprint: str


def _row(e: ObservedTransfer) -> tuple[str, ...]:
    return (
        e.event_id, e.account_ref, e.beneficiary_ref or "",
        e.device_ref or "", e.occurred_at.isoformat(), e.available_at.isoformat(),
    )


def compute_feature_set(
    target: ObservedTransfer,
    history: tuple[ObservedTransfer, ...],
    *,
    decision_as_of: datetime,
) -> FeatureSetV1:
    """Calculate prior-only features from data available at the decision cutoff.

    An event must occur strictly before the target event and be available no
    later than decision_as_of. Exactly 1h before target is included; events
    at target's timestamp are excluded. The target account counts towards
    distinct_accounts_on_device_1h only if it appeared on that device in a
    *prior eligible* observation. Missing optional references remain None.
    """
    if type(target) is not ObservedTransfer or type(history) is not tuple:
        raise ValueError("invalid feature inputs")
    cutoff = _utc("decision_as_of", decision_as_of)
    if not target.occurred_at <= target.available_at <= cutoff:
        raise ValueError("target was not available by decision cutoff")
    seen = {target.event_id}
    previous: list[ObservedTransfer] = []
    for event in history:
        if type(event) is not ObservedTransfer:
            raise ValueError("invalid history observation")
        if event.tenant_id != target.tenant_id:
            raise ValueError("cross-tenant history not permitted")
        if event.event_id in seen:
            raise ValueError("duplicate event identifier")
        seen.add(event.event_id)
        if event.occurred_at < target.occurred_at and event.available_at <= cutoff:
            previous.append(event)
    window = [e for e in previous if target.occurred_at - e.occurred_at <= _WINDOW]
    missing: list[str] = []
    if target.beneficiary_ref is None:
        senders = None
        prior_relation = None
        missing.append("beneficiary_ref")
    else:
        senders = len({
            e.account_ref for e in window if e.beneficiary_ref == target.beneficiary_ref
        })
        prior_relation = any(
            e.account_ref == target.account_ref
            and e.beneficiary_ref == target.beneficiary_ref
            for e in previous
        )
    if target.device_ref is None:
        accounts = None
        missing.append("device_ref")
    else:
        accounts = len({
            e.account_ref for e in window if e.device_ref == target.device_ref
        })
    # No raw account, device or beneficiary identifiers leave the feature output.
    # The fingerprint binds the permitted cohort and availability timestamps.
    source = _digest({
        "version": FEATURE_VERSION, "tenant": target.tenant_id,
        "target": _row(target), "cutoff": cutoff.isoformat(),
        "eligible": sorted(_row(e) for e in previous),
    })
    transfer_count = sum(e.account_ref == target.account_ref for e in window)
    fields = {
        "version": FEATURE_VERSION, "tenant": target.tenant_id,
        "event": target.event_id, "cutoff": cutoff.isoformat(),
        "source": source, "account_transfers_1h": transfer_count,
        "beneficiary_unique_senders_1h": senders,
        "distinct_accounts_on_device_1h": accounts,
        "sender_beneficiary_seen_before": prior_relation,
        "missing": missing,
    }
    return FeatureSetV1(
        version=FEATURE_VERSION, tenant_id=target.tenant_id,
        event_id=target.event_id, decision_as_of=cutoff,
        account_transfers_1h=transfer_count,
        beneficiary_unique_senders_1h=senders,
        distinct_accounts_on_device_1h=accounts,
        sender_beneficiary_seen_before=prior_relation, missing=tuple(missing),
        source_fingerprint=source, computation_fingerprint=_digest(fields),
    )
