"""Non-authoritative historical feature point-in-time lineage (#48).

This validates caller-supplied synthetic source timings and value binding. It does
not attest source systems, authenticate a bank, mature labels, or authorize replay.
The existing historical replay path is deliberately not wired to this helper.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from math import isfinite
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.domain.models import CanonicalTransaction, IntelligenceSnapshot

_SIGNAL_NAMES = frozenset(IntelligenceSnapshot.model_fields)
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class HistoricalLineageRejected(ValueError):
    """Unsafe or insufficient point-in-time evidence; do not replay as verified."""


def _tag(name: str, value: object) -> None:
    if type(value) is not str or _TAG.fullmatch(value) is None:
        raise HistoricalLineageRejected(f"{name} must be an opaque canonical reference")


def _utc(name: str, value: object) -> datetime:
    # Never run caller-defined datetime/tzinfo methods while checking lineage.
    # The source and replay clock contracts accept only built-in/fixed-offset
    # clocks or the standard ZoneInfo implementation, not callback-capable types.
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, ZoneInfo):
        raise HistoricalLineageRejected(f"{name} must be timezone-aware")
    if value.utcoffset() is None:
        raise HistoricalLineageRejected(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class SignalLineage:
    """One named risk score, or an explicitly unavailable signal (never zero)."""

    name: str
    value: float | None
    source_ref: str | None = None
    source_version: str | None = None
    as_of: datetime | None = None
    available_at: datetime | None = None
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        if type(self.name) is not str or self.name not in _SIGNAL_NAMES:
            raise HistoricalLineageRejected("unsupported risk signal name")
        if self.value is None:
            _tag("unavailable_reason", self.unavailable_reason)
            if any(
                item is not None
                for item in (self.source_ref, self.source_version, self.as_of, self.available_at)
            ):
                raise HistoricalLineageRejected("unavailable signal must not claim measured data")
            return
        if type(self.value) is not float or not isfinite(self.value):
            raise HistoricalLineageRejected("risk measurement must be a finite float")
        if not 0.0 <= self.value <= 1.0:
            raise HistoricalLineageRejected("risk measurement outside [0, 1]")
        if self.unavailable_reason is not None:
            raise HistoricalLineageRejected("measured signal cannot also be unavailable")
        _tag("source_ref", self.source_ref)
        _tag("source_version", self.source_version)
        as_of = _utc("as_of", self.as_of)
        available_at = _utc("available_at", self.available_at)
        if as_of > available_at:
            raise HistoricalLineageRejected("feature as-of follows source availability")
        object.__setattr__(self, "as_of", as_of)
        object.__setattr__(self, "available_at", available_at)
        if self.value == 0.0:  # Make -0.0 and +0.0 share an identity.
            object.__setattr__(self, "value", 0.0)

    def _identity(self) -> dict[str, str | float | None]:
        return {
            "name": self.name,
            "value": self.value,
            "source_ref": self.source_ref,
            "source_version": self.source_version,
            "as_of": _iso(self.as_of) if self.as_of is not None else None,
            "available_at": (
                _iso(self.available_at) if self.available_at is not None else None
            ),
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True, slots=True)
class HistoricalFeatureEnvelope:
    """Dataset and event-bound feature lineage, with an explicit decision cutoff.

    ``decision_cutoff`` is a bank/dataset-specific supplied clock, NOT replay
    execution time. Its authenticity is not established by this component.
    """

    tenant_id: str
    event_id: UUID
    dataset_digest: str
    cohort_version: str
    mapping_version: str
    configuration_version: str
    policy_version: str
    signal_policy_version: str
    occurred_at: datetime
    decision_cutoff: datetime
    signals: tuple[SignalLineage, ...]

    def __post_init__(self) -> None:
        for field in (
            "tenant_id", "cohort_version", "mapping_version", "configuration_version",
            "policy_version", "signal_policy_version",
        ):
            _tag(field, getattr(self, field))
        if type(self.event_id) is not UUID:
            raise HistoricalLineageRejected("event_id must be UUID")
        if type(self.dataset_digest) is not str or _DIGEST.fullmatch(self.dataset_digest) is None:
            raise HistoricalLineageRejected("dataset_digest must be sha256")
        occurred = _utc("occurred_at", self.occurred_at)
        cutoff = _utc("decision_cutoff", self.decision_cutoff)
        if cutoff < occurred:
            raise HistoricalLineageRejected("decision cutoff precedes event")
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(self, "decision_cutoff", cutoff)
        if type(self.signals) is not tuple or not self.signals:
            raise HistoricalLineageRejected("signals must be a nonempty immutable tuple")
        seen: set[str] = set()
        for signal in self.signals:
            if type(signal) is not SignalLineage:
                raise HistoricalLineageRejected("untyped signal lineage")
            if signal.name in seen:
                raise HistoricalLineageRejected("duplicate signal provenance")
            seen.add(signal.name)
            if signal.available_at is not None and signal.available_at > cutoff:
                raise HistoricalLineageRejected("post-cutoff feature availability")
            if signal.as_of is not None and signal.as_of > cutoff:
                raise HistoricalLineageRejected("post-cutoff feature as-of")
        if seen != _SIGNAL_NAMES:
            raise HistoricalLineageRejected("missing explicit available/unavailable signal lineage")

    def unavailable_signals(self) -> tuple[str, ...]:
        checked = _validated_copy(self)
        return tuple(sorted(signal.name for signal in checked.signals if signal.value is None))

    def fingerprint(self) -> str:
        """Stable payload identity only, not a trusted data-source attestation."""
        validated = _validated_copy(self)
        payload = {
            "domain": "gasha-historical-feature-lineage-v1",
            "tenant_id": validated.tenant_id,
            "event_id": str(validated.event_id),
            "dataset_digest": validated.dataset_digest,
            "cohort_version": validated.cohort_version,
            "mapping_version": validated.mapping_version,
            "configuration_version": validated.configuration_version,
            "policy_version": validated.policy_version,
            "signal_policy_version": validated.signal_policy_version,
            "occurred_at": _iso(validated.occurred_at),
            "decision_cutoff": _iso(validated.decision_cutoff),
            "signals": [s._identity() for s in sorted(validated.signals, key=lambda item: item.name)],
        }
        canonical = dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return "sha256:" + sha256(canonical.encode("ascii")).hexdigest()



def _assert_fields_present(record: HistoricalFeatureEnvelope | SignalLineage) -> None:
    """Normalize missing slotted fields without masking unrelated programming errors."""
    for field in fields(record):
        try:
            object.__getattribute__(record, field.name)
        except AttributeError:
            raise HistoricalLineageRejected("missing required historical lineage field") from None


def _validated_copy(envelope: HistoricalFeatureEnvelope) -> HistoricalFeatureEnvelope:
    """Recheck caller-held frozen objects and snapshot their validated values.

    Frozen dataclasses do not prohibit object.__setattr__ or an adapter
    bypassing construction validation. Rebuilding every child and the envelope
    prevents post-construction mutation from smuggling future/unavailable
    risk data into a historical assertion or yielding a misleading digest.
    The resulting copy is caller-asserted, never Bank-attested.
    """
    if type(envelope) is not HistoricalFeatureEnvelope:
        raise HistoricalLineageRejected("typed historical envelope required")
    _assert_fields_present(envelope)
    if type(envelope.signals) is not tuple:
        raise HistoricalLineageRejected("signals must be an immutable tuple")
    checked_signals: list[SignalLineage] = []
    for signal in envelope.signals:
        if type(signal) is not SignalLineage:
            raise HistoricalLineageRejected("untyped signal lineage")
        _assert_fields_present(signal)
        checked_signals.append(replace(signal))
    return replace(envelope, signals=tuple(checked_signals))


def assert_historical_snapshot_bound(
    envelope: HistoricalFeatureEnvelope,
    *,
    transaction: CanonicalTransaction,
    snapshot: IntelligenceSnapshot,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> None:
    """Mechanical binding only; never interpret success as verified bank replay.

    An unavailable signal blocks use with the existing numeric-only snapshot,
    whose default zero otherwise loses the distinction between missing and safe.
    """
    if (
        type(envelope) is not HistoricalFeatureEnvelope
        or not isinstance(transaction, CanonicalTransaction)
        or not isinstance(snapshot, IntelligenceSnapshot)
    ):
        raise HistoricalLineageRejected("typed envelope, transaction and snapshot required")
    envelope = _validated_copy(envelope)
    _tag("expected_tenant", expected_tenant)
    if (
        type(expected_dataset_digest) is not str
        or _DIGEST.fullmatch(expected_dataset_digest) is None
    ):
        raise HistoricalLineageRejected("expected dataset digest required")
    if (
        envelope.tenant_id != expected_tenant
        or transaction.tenant_id != expected_tenant
        or envelope.event_id != transaction.event_id
        or envelope.dataset_digest != expected_dataset_digest
        or envelope.occurred_at != _utc("transaction.occurred_at", transaction.occurred_at)
    ):
        raise HistoricalLineageRejected("historical tenant/event/dataset/time scope mismatch")
    if envelope.unavailable_signals():
        raise HistoricalLineageRejected("unavailable telemetry cannot be assumed zero-risk")
    for signal in envelope.signals:
        observed = getattr(snapshot, signal.name)
        if type(observed) is not float or not isfinite(observed) or observed != signal.value:
            raise HistoricalLineageRejected("historical signal value contradicts lineage")
