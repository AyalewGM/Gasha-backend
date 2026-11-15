"""#48: synthetic, read-only point-in-time device/flow evidence projection.

This is not a detector, source attestation, ranking policy, Bank approval,
or an API/worker integration. All input observations are caller assertions.
No customer data, actor names, account numbers or payment instructions belong here.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, dataclass
from datetime import UTC, datetime, timezone
from enum import StrEnum
from uuid import UUID
from zoneinfo import ZoneInfo

_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SCENARIOS = frozenset({"ATO-02", "MM-01", "MM-02"})
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_BUNDLE_FACTORY_KEY = object()  # In-process constructor guard, not Bank attestation.
_MAX_CANONICAL_CHARS = 1_000_000


class DeviceFlowRejected(ValueError):
    """Malformed, future, mixed-tenant or conflicting synthetic evidence."""


class ObservationKind(StrEnum):
    DEVICE = "device"
    CREDIT = "credit"
    DEBIT = "debit"


class SettlementStatus(StrEnum):
    POSTED = "posted"
    SETTLED = "settled"
    REVERSED = "reversed"
    DECLINED = "declined"
    ABANDONED = "abandoned"


@dataclass(frozen=True, slots=True)
class DeviceFlowScopeV1:
    tenant_id: str
    account_ref: UUID
    journey_ref: UUID
    case_ref: UUID
    window_start: datetime
    cutoff: datetime
    correlation_seconds: int
    dataset_digest: str
    code_version: str
    mapping_version: str
    config_version: str
    policy_version: str
    rule_version: str
    model_version: str


@dataclass(frozen=True, slots=True)
class DeviceFlowObservationV1:
    tenant_id: str
    account_ref: UUID
    journey_ref: UUID
    event_ref: UUID
    scenario_id: str
    kind: ObservationKind
    occurred_at: datetime
    received_at: datetime
    source_system: str
    source_version: str
    settlement: SettlementStatus | None = None
    amount_minor: int | None = None
    currency: str | None = None
    counterparty_ref: UUID | None = None
    device_new: bool | None = None


@dataclass(frozen=True, slots=True)
class DeviceFlowEvidenceBundleV1:
    """Deterministic synthetic fingerprint, never authenticated Bank attestation."""

    _canonical_json: str
    digest: str
    _construction_key: InitVar[object | None] = None

    def __post_init__(self, _construction_key: object | None) -> None:
        # A digest proves deterministic identity, not trusted provenance.
        # Normal construction and dataclasses.replace() cannot turn caller-
        # selected JSON (even correctly hashed) into a synthetic bundle.
        if _construction_key is not _BUNDLE_FACTORY_KEY:
            raise DeviceFlowRejected("synthetic bundle requires module-controlled builder")
        if type(self._canonical_json) is not str or type(self.digest) is not str:
            raise DeviceFlowRejected("typed canonical bundle and fingerprint required")
        if _DIGEST.fullmatch(self.digest) is None:
            raise DeviceFlowRejected("invalid bundle fingerprint")
        if len(self._canonical_json) > _MAX_CANONICAL_CHARS:
            raise DeviceFlowRejected("oversized canonical bundle JSON")
        try:
            payload: dict[str, object] = json.loads(self._canonical_json)
            if type(payload) is not dict:
                raise DeviceFlowRejected("canonical bundle must be an object")
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (ValueError, TypeError, RecursionError) as exc:
            raise DeviceFlowRejected("invalid canonical bundle JSON") from exc
        if canonical != self._canonical_json or "digest" in payload:
            raise DeviceFlowRejected("noncanonical bundle JSON")
        actual_digest = hashlib.sha256(self._canonical_json.encode("utf-8")).hexdigest()
        if actual_digest != self.digest:
            raise DeviceFlowRejected("bundle fingerprint mismatch")
        # These are mandatory non-authoritative labels, not caller-settable
        # approval, fraud, ranking or execution claims.
        if (
            payload.get("schema_version") != "DeviceFlowEvidenceBundleV1"
            or payload.get("source") != "synthetic_unverified"
            or payload.get("rank_components") != []
            or payload.get("rank_change_authorized") is not False
            or payload.get("fraud_confirmed") != "unknown"
            or payload.get("deception_inferred") is not False
            or payload.get("bank_execution") != "unknown"
            or payload.get("enforcement_activated") is not False
        ):
            raise DeviceFlowRejected("invalid non-authoritative bundle claims")

    def to_dict(self) -> dict[str, object]:
        # The retained artifact is immutable even when callers mutate a copy.
        result: dict[str, object] = json.loads(self._canonical_json)
        result["digest"] = self.digest
        return result


def _time(value: object) -> datetime:
    # Type first: isinstance can trigger hostile __class__; custom tzinfo can
    # invoke callbacks before a packet has been validated.
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, ZoneInfo):
        raise DeviceFlowRejected("concrete timezone-aware timestamp required")
    if value.utcoffset() is None:
        raise DeviceFlowRejected("timezone offset required")
    return value.astimezone(UTC)


def _token(value: object) -> bool:
    return type(value) is str and _VERSION.fullmatch(value) is not None


def _uuid(value: object) -> bool:
    return type(value) is UUID


def _scope(scope: DeviceFlowScopeV1) -> tuple[datetime, datetime]:
    if type(scope) is not DeviceFlowScopeV1:
        raise DeviceFlowRejected("typed scope required")
    if not _token(scope.tenant_id) or any(
        not _uuid(value) for value in (scope.account_ref, scope.journey_ref, scope.case_ref)
    ):
        raise DeviceFlowRejected("invalid opaque scope")
    for version in (
        scope.code_version, scope.mapping_version, scope.config_version,
        scope.policy_version, scope.rule_version, scope.model_version,
    ):
        if not _token(version):
            raise DeviceFlowRejected("invalid provenance version")
    if type(scope.dataset_digest) is not str or not _DIGEST.fullmatch(scope.dataset_digest):
        raise DeviceFlowRejected("invalid dataset digest")
    if type(scope.correlation_seconds) is not int or not 1 <= scope.correlation_seconds <= 86400:
        raise DeviceFlowRejected("invalid correlation window")
    start, end = _time(scope.window_start), _time(scope.cutoff)
    if start > end:
        raise DeviceFlowRejected("invalid observation window")
    return start, end


def _row(
    obs: DeviceFlowObservationV1, scope: DeviceFlowScopeV1,
    start: datetime, cutoff: datetime,
) -> dict[str, object]:
    if type(obs) is not DeviceFlowObservationV1:
        raise DeviceFlowRejected("typed observation required")
    if (
        not _token(obs.tenant_id)
        or obs.tenant_id != scope.tenant_id
        or not _uuid(obs.account_ref) or obs.account_ref != scope.account_ref
        or not _uuid(obs.journey_ref) or obs.journey_ref != scope.journey_ref
        or not _uuid(obs.event_ref)
        or type(obs.scenario_id) is not str or obs.scenario_id not in _SCENARIOS
        or type(obs.kind) is not ObservationKind
        or not _token(obs.source_system) or not _token(obs.source_version)
    ):
        raise DeviceFlowRejected("invalid tenant, source or scenario scope")
    at, received = _time(obs.occurred_at), _time(obs.received_at)
    if not (start <= at <= received <= cutoff):
        raise DeviceFlowRejected("future, late, reversed or out-of-window observation")
    if obs.kind is ObservationKind.DEVICE:
        if (
            obs.settlement is not None or obs.amount_minor is not None
            or obs.currency is not None or obs.counterparty_ref is not None
            or (obs.device_new is not None and type(obs.device_new) is not bool)
        ):
            raise DeviceFlowRejected("invalid device assertion")
    elif (
        type(obs.settlement) is not SettlementStatus
        or type(obs.amount_minor) is not int or obs.amount_minor <= 0
        or type(obs.currency) is not str or _CURRENCY.fullmatch(obs.currency) is None
        or not _uuid(obs.counterparty_ref)
        or obs.device_new is not None
    ):
        raise DeviceFlowRejected("invalid settlement or flow observation")
    return {
        "event_ref": str(obs.event_ref), "scenario_id": obs.scenario_id,
        "kind": obs.kind.value, "occurred_at": at.isoformat(),
        "received_at": received.isoformat(), "source_system": obs.source_system,
        "source_version": obs.source_version,
        "settlement": obs.settlement.value if obs.settlement is not None else None,
        "amount_minor": obs.amount_minor, "currency": obs.currency,
        "counterparty_ref": str(obs.counterparty_ref) if obs.counterparty_ref else None,
        "device_new": obs.device_new,
    }


def build_device_flow_bundle_v1(
    scope: DeviceFlowScopeV1, observations: tuple[DeviceFlowObservationV1, ...],
) -> DeviceFlowEvidenceBundleV1:
    """Deterministic projection of *existing* scenario assertions, never scoring.

    Reject mixed/late/invalid inputs before emitting anything; deduplicate
    identical retries, reject conflicting event IDs, and keep absent telemetry
    unavailable rather than treating it as low-risk evidence.
    """
    start, cutoff = _scope(scope)
    if type(observations) is not tuple:
        raise DeviceFlowRejected("immutable observation tuple required")
    by_event: dict[str, dict[str, object]] = {}
    for observation in observations:
        row = _row(observation, scope, start, cutoff)
        ref = str(row["event_ref"])
        if ref in by_event and by_event[ref] != row:
            raise DeviceFlowRejected("conflicting event replay")
        by_event[ref] = row
    events = sorted(by_event.values(), key=lambda r: (str(r["occurred_at"]), str(r["event_ref"])))
    device_values = {r["device_new"] for r in events if r["kind"] == "device"
                     and r["device_new"] is not None}
    if len(device_values) > 1:
        raise DeviceFlowRejected("conflicting device observations")
    settled_in = [r for r in events if r["kind"] == "credit" and r["settlement"] == "settled"]
    settled_out = [r for r in events if r["kind"] == "debit" and r["settlement"] == "settled"]
    # Count co-occurring facts; do not infer a mule, fraud, deception or new risk score.
    in_window_pairs = sum(
        1 for credit in settled_in for debit in settled_out
        if credit["currency"] == debit["currency"]
        and 0 <= (
            datetime.fromisoformat(str(debit["occurred_at"]))
            - datetime.fromisoformat(str(credit["occurred_at"]))
        ).total_seconds() <= scope.correlation_seconds
    )
    # No cross-currency amount aggregation: a Bank-owned FX mapping is required.
    amounts: dict[str, dict[str, int]] = {}
    for row in (*settled_in, *settled_out):
        currency = str(row["currency"])
        bucket = amounts.setdefault(currency, {"credit_minor": 0, "debit_minor": 0})
        key = "credit_minor" if row["kind"] == "credit" else "debit_minor"
        bucket[key] += int(str(row["amount_minor"]))
    missing: list[str] = []
    if not device_values:
        missing.append("bank_device_assertion_unavailable")
    if not settled_in:
        missing.append("settled_credit_evidence_unavailable")
    if not settled_out:
        missing.append("settled_debit_evidence_unavailable")
    if len(amounts) > 1:
        missing.append("bank_fx_normalization_unavailable")
    payload: dict[str, object] = {
        "schema_version": "DeviceFlowEvidenceBundleV1", "source": "synthetic_unverified",
        "tenant_id": scope.tenant_id, "account_ref": str(scope.account_ref),
        "journey_ref": str(scope.journey_ref), "case_ref": str(scope.case_ref),
        "window_start": start.isoformat(), "decision_cutoff": cutoff.isoformat(),
        "correlation_seconds": scope.correlation_seconds,
        "dataset_digest": scope.dataset_digest,
        "code_version": scope.code_version, "mapping_version": scope.mapping_version,
        "config_version": scope.config_version, "policy_version": scope.policy_version,
        "rule_version": scope.rule_version, "model_version": scope.model_version,
        "scenario_ids": sorted({str(r["scenario_id"]) for r in events}),
        "events": events, "device_new_assertion": next(iter(device_values), None),
        "settled_inbound_count": len(settled_in), "settled_outbound_count": len(settled_out),
        "distinct_inbound_counterparties": len({r["counterparty_ref"] for r in settled_in}),
        "settled_amounts_by_currency": dict(sorted(amounts.items())),
        "credit_to_debit_window_pairs": in_window_pairs, "missing_signals": sorted(missing),
        "rank_components": [], "rank_change_authorized": False,
        "fraud_confirmed": "unknown", "deception_inferred": False,
        "bank_execution": "unknown", "enforcement_activated": False,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return DeviceFlowEvidenceBundleV1(
        _canonical_json=serialized,
        digest=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        _construction_key=_BUNDLE_FACTORY_KEY,
    )
