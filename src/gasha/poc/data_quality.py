"""Issue #48: synthetic, aggregate-only historical data quality inspection.

Not a bank adapter, trusted provenance verifier, point-in-time replay barrier,
readiness authority or payment decision input. Never serialize payload identifiers.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from math import isfinite
from uuid import UUID

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


def _inspect(scope: DataQualityScope, observation: QualityObservation) -> _Result:
    event = observation.event
    payload = event.payload
    codes: set[str] = set()
    warnings: set[str] = set()
    # Normal construction validates a mapping, but Pydantic model_copy(update=...)
    # can bypass that contract in a synthetic adapter. Quarantine the whole
    # invalid body instead of raising during required-field or signal checks.
    # An invalid body cannot supply an event ID for deduplication.
    if not isinstance(payload, Mapping):
        codes.add("invalid.payload")
        payload = {}
    required = _JOURNEY_REQUIRED if observation.use_case is UseCase.UC03 else _PAYMENT_REQUIRED
    for name in required:
        if name not in payload or payload[name] is None or payload[name] == "":
            codes.add(f"missing.{name}")
    if event.tenant_id != scope.tenant_id:
        codes.add("tenant_mismatch")
    if event.schema_version != scope.schema_version:
        codes.add("schema_mismatch")
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
    if received is None or received.utcoffset() is None:
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
        observation.confirmed_at is not None
        and occurred is not None
        and _utc(observation.confirmed_at) < occurred
    ):
        codes.add("invalid.label_order")
    return _Result(tuple(sorted(codes)), tuple(sorted(warnings)), event_id, occurred,
                   tuple(present), tuple(unavailable))


def _ratio(numerator: int, denominator: int) -> dict[str, object]:
    return {"count": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None,
            "undefined_reason": None if denominator else "no_records"}


@dataclass(frozen=True)
class DataQualityReport:
    scope: DataQualityScope
    use_cases: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize only safe schema names, aggregate counts and scope metadata."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "provisional_coverage_matrix_version": _COVERAGE_MATRIX_VERSION,
            "source": "caller_supplied_synthetic_reference_only",
            "bank_data_verified": False,
            "historical_replay_authorized": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
            "scope": {
                "tenant_id": self.scope.tenant_id,
                "dataset_digest": self.scope.dataset_digest,
                "source_schema_version": self.scope.schema_version,
                "mapping_version": self.scope.mapping_version,
                "configuration_version": self.scope.configuration_version,
                "window_start": _utc(self.scope.window_start).isoformat(),
                "window_end": _utc(self.scope.window_end).isoformat(),
                "label_cutoff": _utc(self.scope.label_cutoff).isoformat(),
            },
            "use_cases": list(self.use_cases),
            "limitations": [
                "Input schema, dataset digest, tenant and label clocks are caller assertions.",
                "No Bank-approved mappings, source attestations, mature cohort or KPI thresholds.",
                "Missing optional signals are unavailable; never synthetic zero-risk.",
                "Not wired to replay, protected API, readiness, deployment or payment paths.",
            ],
        }


def inspect_reference_quality(
    scope: DataQualityScope, observations: Sequence[QualityObservation]
) -> DataQualityReport:
    """Aggregate checks; never carry event/customer/beneficiary IDs into a report.

    This deliberately does not call the reference adapter because its optional
    intelligence normalizer can produce numeric zero defaults for absent inputs.
    """
    if type(scope) is not DataQualityScope:
        raise ValueError("expected validated DataQualityScope")
    counters: dict[UseCase, Counter[str]] = {uc: Counter() for uc in UseCase}
    failures: dict[UseCase, Counter[str]] = {uc: Counter() for uc in UseCase}
    coverage: dict[UseCase, Counter[str]] = {uc: Counter() for uc in UseCase}
    seen: set[tuple[UseCase, UUID]] = set()
    for observation in observations:
        if type(observation) is not QualityObservation:
            raise ValueError("expected validated QualityObservation")
        uc = observation.use_case
        stats = counters[uc]
        stats["total"] += 1
        check = _inspect(scope, observation)
        rejected = set(check.failed_checks)
        # Quarantined/out-of-scope rows must never reserve an in-scope ID.
        # Only structurally, temporally and tenant/schema-valid observations
        # participate in deduplication; order cannot poison accepted counts.
        if not rejected and check.event_id is not None:
            identity = (uc, check.event_id)
            if identity in seen:
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
            observation.confirmed_fraud is not None
            and observation.confirmed_at is not None
            and check.occurred_at is not None
            and check.occurred_at <= _utc(observation.confirmed_at) <= _utc(scope.label_cutoff)
        )
        if mature:
            stats["positive" if observation.confirmed_fraud else "negative"] += 1
        else:
            stats["unlabelled"] += 1
        if observation.alerted is None:
            stats["alert_unknown"] += 1
        else:
            stats["alerted" if observation.alerted else "not_alerted"] += 1
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
