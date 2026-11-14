"""Offline, synthetic-only point-in-time behavior features for Gasha #145.

No network, storage, ML inference, decisioning or bank-data access.
Input references MUST be bank-approved pseudonyms before this boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

FEATURE_VERSION = "gasha-feature-set-v1"
_WINDOW = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class ObservedTransfer:
    tenant_id: str
    event_id: str
    account_ref: str
    beneficiary_ref: str | None
    device_ref: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "event_id", "account_ref"):
            v = object.__getattribute__(self, name)
            if type(v) is not str or not v or len(v) > 128:
                raise ValueError(f"invalid {name}")
        for name in ("beneficiary_ref", "device_ref"):
            v = object.__getattribute__(self, name)
            if v is not None and (type(v) is not str or not v or len(v) > 128):
                raise ValueError(f"invalid {name}")
        v = object.__getattribute__(self, "observed_at")
        if type(v) is not datetime or v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("observed_at must be an ordinary timezone-aware datetime")
        object.__setattr__(self, "observed_at", v.astimezone(UTC))


@dataclass(frozen=True, slots=True)
class FeatureSetV1:
    version: str
    tenant_id: str
    event_id: str
    as_of: datetime
    account_transfers_1h: int
    beneficiary_unique_senders_1h: int | None
    distinct_accounts_on_device_1h: int | None
    beneficiary_seen_before: bool | None
    missing: tuple[str, ...]


def compute_feature_set(target: ObservedTransfer, history: tuple[ObservedTransfer, ...]) -> FeatureSetV1:
    """Compute features only from events strictly BEFORE target's event time.

    Boundary at exactly one hour is included; same-timestamp records are
    excluded to avoid indeterminate ordering. Conflicting IDs fail closed.
    Cross-tenant input fails rather than being quietly filtered.
    """
    if type(target) is not ObservedTransfer or type(history) is not tuple:
        raise ValueError("invalid feature inputs")
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
        if event.observed_at < target.observed_at:
            previous.append(event)
    window = [e for e in previous if target.observed_at - e.observed_at <= _WINDOW]
    missing: list[str] = []
    if target.beneficiary_ref is None:
        beneficiary_unique_senders = None
        beneficiary_seen = None
        missing.append("beneficiary_ref")
    else:
        beneficiary_unique_senders = len({
            e.account_ref for e in window if e.beneficiary_ref == target.beneficiary_ref
        })
        beneficiary_seen = any(
            e.account_ref == target.account_ref
            and e.beneficiary_ref == target.beneficiary_ref
            for e in previous
        )
    if target.device_ref is None:
        device_accounts = None
        missing.append("device_ref")
    else:
        device_accounts = len({
            e.account_ref for e in window if e.device_ref == target.device_ref
        })
    return FeatureSetV1(
        version=FEATURE_VERSION,
        tenant_id=target.tenant_id,
        event_id=target.event_id,
        as_of=target.observed_at,
        account_transfers_1h=sum(e.account_ref == target.account_ref for e in window),
        beneficiary_unique_senders_1h=beneficiary_unique_senders,
        distinct_accounts_on_device_1h=device_accounts,
        beneficiary_seen_before=beneficiary_seen,
        missing=tuple(missing),
    )
