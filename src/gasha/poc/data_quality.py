"""Issue #48: synthetic, aggregate-only historical data quality inspection.

Not a bank adapter, trusted provenance verifier, point-in-time replay barrier,
readiness authority or payment decision input. Never serialize payload identifiers.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.ingestion.contracts import InboundBankEvent

_SCHEMA_VERSION = "gasha-synthetic-data-quality-2"
_COVERAGE_MATRIX_VERSION = "synthetic-uc-coverage-v2"
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PAYMENT_REQUIRED = (
    "event_id", "occurred_at", "channel", "transaction_type", "amount",
    "currency", "sender_customer_id", "sender_account_id", "beneficiary_id",
    "beneficiary_type", "correlation_id",
)
_JOURNEY_REQUIRED = ("event_id", "occurred_at", "kind", "subtype", "customer_id")
_BENEFICIARY_TYPES = frozenset({"internal", "external", "merchant", "wallet", "unknown"})


class UseCase(StrEnum):
    UC01 = "UC-01"
    UC02 = "UC-02"
    UC03 = "UC-03"


# Provisional reference-json coverage only. Bank-approved source mappings and
# true use-case-required signals must be defined separately in an adapter.
_OPTIONAL_SIGNALS: dict[UseCase, tuple[str, ...]] = {
    UseCase.UC01: ("beneficiary_risk", "relationship_risk"),
    UseCase.UC02: ("beneficiary_risk", "network_risk", "velocity_risk"),
    UseCase.UC03: ("device_session_risk", "journey_risk"),
}


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone aware")
    return value.astimezone(UTC)


def _safe_token(value: object) -> bool:
    return type(value) is str and _SAFE_VERSION.fullmatch(value) is not None


@dataclass(frozen=True)
class DataQualityScope:
    """Caller-asserted, synthetic dataset identity and time range, not attestation."""

    tenant_id: str
    dataset_digest: str
    schema_version: str
    mapping_version: str
    configuration_version: str
    window_start: datetime
    window_end: datetime
    label_cutoff: datetime

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.schema_version, self.mapping_version,
                      self.configuration_version):
            if not _safe_token(value):
                raise ValueError("scope identifier must be a canonical opaque token")
        if type(self.dataset_digest) is not str or not _SHA256.fullmatch(self.dataset_digest):
            raise ValueError("dataset_digest must be lowercase SHA-256 hex")
        if not (_utc(self.window_start) <= _utc(self.window_end) <= _utc(self.label_cutoff)):
            raise ValueError("invalid collection window or label cutoff")


@dataclass(frozen=True)
class QualityObservation:
    """One *pseudonymized* reference event and optional label/alert assertions."""

    use_case: UseCase
    event: InboundBankEvent
    confirmed_fraud: bool | None = None
    confirmed_at: datetime | None = None
    alerted: bool | None = None

    def __post_init__(self) -> None:
        if type(self.use_case) is not UseCase or not isinstance(self.event, InboundBankEvent):
            raise ValueError("invalid quality observation type")
        for value in (self.confirmed_fraud, self.alerted):
            if value is not None and type(value) is not bool:
                raise ValueError("label and alert must be strict booleans or unknown")
        if self.confirmed_at is not None:
            _utc(self.confirmed_at)


@dataclass(frozen=True)
class _Result:
    failed_checks: tuple[str, ...]
    warnings: tuple[str, ...]
    event_id: UUID | None
    occurred_at: datetime | None
    signal_present: tuple[str, ...]
    signal_unavailable: tuple[str, ...]


def _timestamp(value: object) -> datetime | None:
    if type(value) is not str:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return _utc(parsed)
    except ValueError:
        return None


def _valid_text(value: object) -> bool:
    return type(value) is str and bool(value.strip()) and value == value.strip() and all(
        32 <= ord(char) <= 126 for char in value
    )


def _valid_amount(value: object) -> bool:
    if type(value) not in (str, int, Decimal):
        return False
    try:
        amount = Decimal(str(value))
    except (ValueError, InvalidOperation):
        return False
    return amount.is_finite() and amount > 0


def _valid_optional_signal(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return isfinite(value) and 0 <= value <= 1
    except OverflowError:
        return False


def _inspect(scope: DataQualityScope, observation: _OwnedObservation) -> _Result:
    event = observation.event
    payload = event.payload
    codes: set[str] = set()
    warnings: set[str] = set()
    # Frozen records can be modified with object.__setattr__ after validation.
    # Malformed labels/alerts must not contaminate claimed KPI populations.
    if (
        observation.confirmed_fraud is not None
        and type(observation.confirmed_fraud) is not bool
    ):
        codes.add("invalid.confirmed_fraud")
    if observation.alerted is not None and type(observation.alerted) is not bool:
        codes.add("invalid.alerted")
    confirmed_at = observation.confirmed_at
    if confirmed_at is not None and (
        not isinstance(confirmed_at, datetime) or confirmed_at.utcoffset() is None
    ):
        codes.add("invalid.confirmed_at")
    # Normal construction validates a mapping, but Pydantic model_copy(update=...)
    # can bypass that contract in a synthetic adapter. Quarantine the whole
    # invalid body instead of raising during required-field or signal checks.
    # An invalid body cannot supply an event ID for deduplication.
    if not isinstance(payload, Mapping):
        codes.add("invalid.payload")
        # Derived missing/invalid field checks are deliberate, so structural
        # corruption stays visible while the row denominator remains one.
        payload = {}
    required = _JOURNEY_REQUIRED if observation.use_case is UseCase.UC03 else _PAYMENT_REQUIRED
    for name in required:
        if name not in payload or payload[name] is None or payload[name] == "":
            codes.add(f"missing.{name}")
    if event.tenant_id != scope.tenant_id:
        codes.add("tenant_mismatch")
    if event.schema_version != scope.schema_version:
        codes.add("schema_mismatch")
    # The adapter normally validates this at construction, but an unchecked
    # synthetic model_copy can erase or corrupt the claimed source. Reject the
    # record before it can contribute labels, alerts or deduplication identity.
    # This checks shape only; source authenticity remains unverified.
    if not _safe_token(event.source_system):
        codes.add("invalid.source_system")
    raw_id = payload.get("event_id")
    try:
        event_id = UUID(raw_id) if type(raw_id) is str else None
    except ValueError:
        event_id = None
    if event_id is None:
        codes.add("invalid.event_id")
    occurred = _timestamp(payload.get("occurred_at"))
    if occurred is None:
        codes.add("invalid.occurred_at")
    elif not (_utc(scope.window_start) <= occurred <= _utc(scope.window_end)):
        codes.add("event_outside_window")
    received = event.received_at
    # InboundBankEvent normally validates this field, but Pydantic model_copy
    # can carry an unvalidated runtime value from a synthetic adapter. Treat
    # it as a quarantined bad clock rather than aborting the entire report.
    if not isinstance(received, datetime) or received.utcoffset() is None:
        codes.add("invalid.received_at")
    elif occurred is not None:
        at = _utc(received)
        if at < occurred or at > _utc(scope.label_cutoff):
            codes.add("invalid.receipt_order")
    if observation.use_case is UseCase.UC03:
        for name in ("kind", "subtype", "customer_id"):
            if not _valid_text(payload.get(name)):
                codes.add(f"invalid.{name}")
    else:
        for name in ("channel", "transaction_type", "sender_customer_id",
                     "sender_account_id", "beneficiary_id", "correlation_id"):
            if not _valid_text(payload.get(name)):
                codes.add(f"invalid.{name}")
        if not _valid_amount(payload.get("amount")):
            codes.add("invalid.amount")
        currency = payload.get("currency")
        if type(currency) is not str or re.fullmatch(r"[A-Z]{3}", currency) is None:
            codes.add("invalid.currency")
        beneficiary_type = payload.get("beneficiary_type")
        if type(beneficiary_type) is not str or beneficiary_type not in _BENEFICIARY_TYPES:
            codes.add("invalid.beneficiary_type")
        elif beneficiary_type == "external" and not _valid_text(
            payload.get("destination_institution_id")
        ):
            codes.add("missing.destination_institution_id")
    raw_signals = payload.get("intelligence")
    signals = raw_signals if isinstance(raw_signals, Mapping) else {}
    # Distinguish absent telemetry from an explicitly malformed container.
    # Both remain unavailable, but only the latter produces a quality warning.
    if "intelligence" in payload and not isinstance(raw_signals, Mapping):
        warnings.add("invalid_optional.intelligence")
    present: list[str] = []
    unavailable: list[str] = []
    for name in _OPTIONAL_SIGNALS[observation.use_case]:
        if name in signals and _valid_optional_signal(signals[name]):
            present.append(name)
        else:
            unavailable.append(name)
            if name in signals:
                warnings.add(f"invalid_optional.{name}")
    if (
        confirmed_at is not None
        and "invalid.confirmed_at" not in codes
        and occurred is not None
        and _utc(confirmed_at) < occurred
    ):
        codes.add("invalid.label_order")
    return _Result(tuple(sorted(codes)), tuple(sorted(warnings)), event_id, occurred,
                   tuple(present), tuple(unavailable))


def _ratio(numerator: int, denominator: int) -> dict[str, object]:
    return {"count": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None,
            "undefined_reason": None if denominator else "no_records"}


def _freeze_report_value(value: object) -> object:
    """Own a deep immutable snapshot of a synthetic aggregate, not external evidence.

    Only fixed-schema JSON scalar types, mappings and ordered tuples/lists may
    enter a retained report. In particular, arbitrary mutable objects cannot
    bypass the immutable output contract.
    """
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("aggregate report keys must be strings")
        return MappingProxyType({
            key: _freeze_report_value(item) for key, item in value.items()
        })
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_report_value(item) for item in value)
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float and isfinite(value):
        return value
    raise ValueError("aggregate report contains a non-JSON or non-finite value")


def _export_report_value(value: object) -> object:
    """Produce a fresh mutable JSON tree without exposing retained aliases."""
    if isinstance(value, Mapping):
        return {key: _export_report_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_export_report_value(item) for item in value]
    return value


def _scope_binding(scope: DataQualityScope) -> tuple[str, ...]:
    """Canonical synthetic scope identity, not authenticated dataset evidence."""
    return (
        scope.tenant_id, scope.dataset_digest, scope.schema_version,
        scope.mapping_version, scope.configuration_version,
        _utc(scope.window_start).isoformat(),
        _utc(scope.window_end).isoformat(),
        _utc(scope.label_cutoff).isoformat(),
    )


@dataclass(frozen=True)
class DataQualityReport:
    scope: DataQualityScope
    use_cases: tuple[Mapping[str, object], ...]
    _retained_scope_binding: tuple[str, ...] = field(init=False, repr=False, compare=False)
    _retained_use_cases: tuple[Mapping[str, object], ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        # A frozen dataclass does not freeze dicts inside a tuple. Snapshot the
        # caller-owned tree at construction, including direct construction.
        if type(self.scope) is not DataQualityScope:
            raise ValueError("invalid aggregate report scope")
        retained = replace(self.scope)
        object.__setattr__(self, "scope", retained)
        object.__setattr__(self, "_retained_scope_binding", _scope_binding(retained))
        if (type(self.use_cases) is not tuple
                or len(self.use_cases) != len(UseCase)
                or any(not isinstance(row, Mapping) for row in self.use_cases)):
            raise ValueError("invalid aggregate use-case rows")
        frozen_rows = tuple(_freeze_report_value(row) for row in self.use_cases)
        object.__setattr__(self, "use_cases", frozen_rows)
        # A frozen dataclass can still be replaced with object.__setattr__.
        # Retain the *owned immutable tuple* so a later forged aggregate cannot
        # be exported under the original tenant/dataset/version scope.
        object.__setattr__(self, "_retained_use_cases", frozen_rows)

    def to_dict(self) -> dict[str, object]:
        """Reject post-construction scope substitution before exporting counts."""
        # Frozen dataclasses are not a security boundary: object.__setattr__
        # can change the retained report scope, despite defensive input copying.
        try:
            if type(self.scope) is not DataQualityScope:
                raise ValueError("typed retained scope required")
            checked_scope = replace(self.scope)
            if _scope_binding(checked_scope) != self._retained_scope_binding:
                raise ValueError("report scope changed after construction")
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("quality report scope integrity failed") from exc
        try:
            if (
                type(self.use_cases) is not tuple
                or self.use_cases is not self._retained_use_cases
            ):
                raise ValueError("retained aggregate rows were replaced")
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("quality report aggregate integrity failed") from exc
        return {
            "schema_version": _SCHEMA_VERSION,
            "provisional_coverage_matrix_version": _COVERAGE_MATRIX_VERSION,
            "source": "caller_supplied_synthetic_reference_only",
            "bank_data_verified": False,
            "historical_replay_authorized": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
            "scope": {
                "tenant_id": checked_scope.tenant_id,
                "dataset_digest": checked_scope.dataset_digest,
                "source_schema_version": checked_scope.schema_version,
                "mapping_version": checked_scope.mapping_version,
                "configuration_version": checked_scope.configuration_version,
                "window_start": _utc(checked_scope.window_start).isoformat(),
                "window_end": _utc(checked_scope.window_end).isoformat(),
                "label_cutoff": _utc(checked_scope.label_cutoff).isoformat(),
            },
            "use_cases": [_export_report_value(row) for row in self.use_cases],
            "limitations": [
                "Input schema, dataset digest, tenant and label clocks are caller assertions.",
                "No Bank-approved mappings, source attestations, mature cohort or KPI thresholds.",
                "Missing optional signals are unavailable; never synthetic zero-risk.",
                "Not wired to replay, protected API, readiness, deployment or payment paths.",
            ],
        }




def _typed_cohort_value(value: object, *, depth: int = 0) -> tuple[object, ...]:
    """Build a strict, ephemeral identity without Python's bool/int equality.

    Only built-in reference-data types are permitted. All nested mapping keys
    are string-typed and sorted, and no raw values enter aggregate reports.
    Unsupported objects, non-finite numbers and excessive nesting fail closed.
    """
    if depth > 32:
        raise ValueError("cohort identity nesting limit exceeded")
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is str:
        return ("string", value)
    if type(value) is int:
        return ("integer", value)
    if type(value) is float:
        if not isfinite(value):
            raise ValueError("non-finite cohort numeric value")
        return ("float", repr(value))
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("non-finite cohort decimal value")
        return ("decimal", str(value))
    if type(value) is datetime:
        return ("utc_datetime", _utc(value).isoformat())
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("non-string cohort mapping key")
        return ("mapping", tuple(
            (key, _typed_cohort_value(value[key], depth=depth + 1))
            for key in sorted(value)
        ))
    if type(value) is list or type(value) is tuple:
        return (("list" if type(value) is list else "tuple"), tuple(
            _typed_cohort_value(item, depth=depth + 1) for item in value
        ))
    raise ValueError("unsupported cohort identity value")


@dataclass(frozen=True)
class _OwnedObservation:
    """Internal inspected view; no field aliases an untrusted input record."""

    use_case: UseCase
    event: InboundBankEvent
    confirmed_fraud: bool | None
    confirmed_at: datetime | None
    alerted: bool | None


class _SnapshotFailure(ValueError):
    """Reason code for an input that cannot be safely detached."""


def _owned_clock(value: datetime | None) -> datetime | None:
    """Normalize only built-in / zoneinfo clocks, without untrusted tz callbacks."""
    if type(value) is not datetime:
        return value
    zone = value.tzinfo
    if zone is None:
        return value  # _inspect reports the familiar invalid clock code.
    if type(zone) not in (timezone, ZoneInfo):
        raise _SnapshotFailure("invalid.snapshot")
    return _utc(value)


def _owned_value(value: object, *, depth: int = 0, remaining: list[int]) -> object:
    """Copy bounded reference JSON with exact built-in types, never invoke hooks."""
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 32:
        raise _SnapshotFailure("invalid.snapshot")
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float:
        if not isfinite(value):
            raise _SnapshotFailure("invalid.cohort_identity")
        return value
    if type(value) is Decimal:
        if not value.is_finite():
            raise _SnapshotFailure("invalid.cohort_identity")
        return value
    if type(value) is datetime:
        return _owned_clock(value)
    if type(value) is dict:
        if len(value) > 1024 or any(type(key) is not str for key in value):
            raise _SnapshotFailure("invalid.snapshot")
        return {
            key: _owned_value(item, depth=depth + 1, remaining=remaining)
            for key, item in value.items()
        }
    if type(value) in (list, tuple):
        if len(value) > 1024:
            raise _SnapshotFailure("invalid.snapshot")
        copied = (
            _owned_value(item, depth=depth + 1, remaining=remaining)
            for item in value
        )
        return tuple(copied) if type(value) is tuple else list(copied)
    if isinstance(value, (Mapping, Sequence)):
        raise _SnapshotFailure("invalid.snapshot")
    raise _SnapshotFailure("invalid.cohort_identity")


def _owned_observation(observation: QualityObservation) -> _OwnedObservation:
    """Take a single callback-free, bounded snapshot before inspection/identity.

    We reject opaque Mapping subclasses and custom timezone implementations
    instead of trusting their get/iteration/utcoffset methods. Re-read and
    compare exact primitive fields and the detached payload to detect aliases
    changed while copying. This is synthetic caller isolation, not protection
    against privileged concurrent code or trusted Bank source attestation.
    """
    event = observation.event
    uc = observation.use_case
    fraud = observation.confirmed_fraud
    confirmed = observation.confirmed_at
    alerted = observation.alerted
    tenant = event.tenant_id
    source = event.source_system
    schema = event.schema_version
    correlation = event.correlation_id
    received = event.received_at
    original_payload = event.payload
    if type(original_payload) is dict:
        payload: object = _owned_value(original_payload, remaining=[4096])
    elif isinstance(original_payload, Mapping):
        raise _SnapshotFailure("invalid.snapshot")
    else:
        # Preserve existing invalid.payload / required-field diagnostics for
        # malformed adapter-bypass data without retaining mutable list aliases.
        payload = None
    safe_received = _owned_clock(received)
    safe_confirmed = _owned_clock(confirmed)
    if (
        observation.event is not event
        or observation.use_case is not uc
        or observation.confirmed_fraud is not fraud
        or observation.confirmed_at is not confirmed
        or observation.alerted is not alerted
        or event.tenant_id != tenant
        or event.source_system != source
        or event.schema_version != schema
        or event.correlation_id != correlation
        or event.received_at is not received
        or event.payload is not original_payload
    ):
        raise _SnapshotFailure("invalid.snapshot")
    if type(original_payload) is dict:
        # Compare type-tagged values: bool and int must not compare equal.
        if _typed_cohort_value(payload) != _typed_cohort_value(
            _owned_value(original_payload, remaining=[4096])
        ):
            raise _SnapshotFailure("invalid.snapshot")
    owned_event = event.model_copy(update={
        "tenant_id": tenant,
        "source_system": source,
        "schema_version": schema,
        "correlation_id": correlation,
        "received_at": safe_received,
        "payload": payload,
    })
    return _OwnedObservation(uc, owned_event, fraud, safe_confirmed, alerted)


def _accepted_cohort_identity(
    observation: _OwnedObservation, result: _Result
) -> tuple[object, ...]:
    """Ephemeral equality for accepted records, never exported as evidence.

    Event UUID alone cannot settle contradictory transactions, labels or alerts.
    Normalize clocks so equivalent offsets do not become false conflicts.
    """
    received = observation.event.received_at
    occurred = result.occurred_at
    if not isinstance(received, datetime) or occurred is None:
        raise ValueError("accepted identity requires validated event clocks")
    confirmed = observation.confirmed_at
    if confirmed is not None and not isinstance(confirmed, datetime):
        raise ValueError("accepted identity requires validated label clock")
    payload = dict(observation.event.payload)
    payload["occurred_at"] = occurred
    return _typed_cohort_value((
        observation.event.tenant_id,
        observation.event.source_system,
        observation.event.schema_version,
        observation.event.correlation_id,
        _utc(received),
        payload,
        observation.confirmed_fraud,
        _utc(confirmed) if confirmed is not None else None,
        observation.alerted,
    ))


def inspect_reference_quality(
    scope: DataQualityScope, observations: Sequence[QualityObservation]
) -> DataQualityReport:
    """Aggregate checks; never carry event/customer/beneficiary IDs into a report.

    This deliberately does not call the reference adapter because its optional
    intelligence normalizer can produce numeric zero defaults for absent inputs.
    """
    if type(scope) is not DataQualityScope:
        raise ValueError("expected validated DataQualityScope")
    # Revalidate and retain a snapshot so forged/changed caller scope fields
    # cannot silently affect the report after the constructor has run.
    scope = replace(scope)
    counters: dict[UseCase, Counter[str]] = {uc: Counter() for uc in UseCase}
    failures: dict[UseCase, Counter[str]] = {uc: Counter() for uc in UseCase}
    coverage: dict[UseCase, Counter[str]] = {uc: Counter() for uc in UseCase}
    # First inspect the entire batch. A contradictory, otherwise valid
    # same-UUID claim quarantines every such claim rather than letting input
    # order decide the accepted fraud/alert/label denominator. Invalid rows
    # do not reserve IDs or poison separately valid observations.
    inspected: list[tuple[UseCase, _Result, bool | None, datetime | None, bool | None]] = []
    first_claims: dict[tuple[UseCase, UUID], tuple[object, ...]] = {}
    conflicting_ids: set[tuple[UseCase, UUID]] = set()
    for observation in observations:
        if type(observation) is not QualityObservation:
            raise ValueError("expected validated QualityObservation")
        if (
            type(observation.use_case) is not UseCase
            or not isinstance(observation.event, InboundBankEvent)
        ):
            raise ValueError("invalid quality observation type")
        # All validation, deduplication and accounting consume one detached
        # snapshot. Invalid callback-capable inputs are quarantined before any
        # caller-controlled Mapping or timezone method can execute.
        checked_uc = observation.use_case
        try:
            owned = _owned_observation(observation)
        except _SnapshotFailure as exc:
            inspected.append((
                checked_uc, _Result((str(exc),), (), None, None, (), ()),
                None, None, None,
            ))
            continue
        check = _inspect(scope, owned)
        checked_fraud = owned.confirmed_fraud
        checked_confirmed_at = owned.confirmed_at
        checked_alerted = owned.alerted
        inspected.append((
            checked_uc, check, checked_fraud, checked_confirmed_at, checked_alerted
        ))
        if not check.failed_checks and check.event_id is not None:
            key = (checked_uc, check.event_id)
            try:
                claim = _accepted_cohort_identity(owned, check)
            except (ValueError, TypeError, OverflowError, RecursionError):
                # Opaque or malformed nested data cannot be compared safely.
                # Quarantine this claim without poisoning a valid same-ID row.
                inspected[-1] = (
                    checked_uc, replace(check, failed_checks=("invalid.cohort_identity",)),
                    checked_fraud, checked_confirmed_at, checked_alerted,
                )
                continue
            if key not in first_claims:
                first_claims[key] = claim
            elif first_claims[key] != claim:
                conflicting_ids.add(key)
    seen: set[tuple[UseCase, UUID]] = set()
    for uc, check, confirmed_fraud, confirmed_at, alerted in inspected:
        stats = counters[uc]
        stats["total"] += 1
        rejected = set(check.failed_checks)
        if not rejected and check.event_id is not None:
            identity = (uc, check.event_id)
            if identity in conflicting_ids:
                rejected.add("conflicting.event_id")
            elif identity in seen:
                rejected.add("duplicate.event_id")
            else:
                seen.add(identity)
        for code in rejected | set(check.warnings):
            failures[uc][code] += 1
        if rejected:
            stats["rejected"] += 1
            continue
        stats["accepted"] += 1
        for name in check.signal_present:
            coverage[uc][name] += 1
        for name in check.signal_unavailable:
            coverage[uc][f"unavailable.{name}"] += 1
        # Label clock and reference event clock are both untrusted; only an
        # explicitly observed, non-future label may enter accepted counts.
        mature = (
            confirmed_fraud is not None
            and confirmed_at is not None
            and check.occurred_at is not None
            and check.occurred_at <= _utc(confirmed_at) <= _utc(scope.label_cutoff)
        )
        if mature:
            stats["positive" if confirmed_fraud else "negative"] += 1
        else:
            stats["unlabelled"] += 1
        if alerted is None:
            stats["alert_unknown"] += 1
        else:
            stats["alerted" if alerted else "not_alerted"] += 1
    summaries: list[dict[str, object]] = []
    for uc in UseCase:
        stats = counters[uc]
        accepted = stats["accepted"]
        summaries.append({
            "use_case": uc.value,
            "total": stats["total"],
            "accepted": accepted,
            "rejected": stats["rejected"],
            "acceptance": _ratio(accepted, stats["total"]),
            "checks": dict(sorted(failures[uc].items())),
            "labels": {"positive": stats["positive"], "negative": stats["negative"],
                       "unlabelled": stats["unlabelled"]},
            "alerts": {"alerted": stats["alerted"], "not_alerted": stats["not_alerted"],
                       "unknown": stats["alert_unknown"]},
            "optional_signals": {
                name: {"available": _ratio(coverage[uc][name], accepted),
                       "unavailable": coverage[uc][f"unavailable.{name}"]}
                for name in _OPTIONAL_SIGNALS[uc]
            },
            "evaluated_for_bank_kpi": False,
        })
    return DataQualityReport(scope=scope, use_cases=tuple(summaries))
