"""Synthetic-only Dashen scenario observation/coverage contract (#41, #48).

Maps the eight PO-selected scenarios to versioned, bank-neutral evidence keys.
This is shape/time/coverage checking, NOT signal validation, scenario detection,
bank source authentication, replay authorization, or readiness evidence.
The normal decision/worker/protected-API paths do not import this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from json import dumps
from types import MappingProxyType
from typing import Mapping
from uuid import UUID

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FIELD = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ScenarioContractError(ValueError):
    """Malformed or untrustworthy-by-shape synthetic observation."""


class ScenarioId(StrEnum):
    ATO_02 = "ATO-02"
    ATO_06 = "ATO-06"
    MM_01 = "MM-01"
    MM_02 = "MM-02"
    MM_05 = "MM-05"
    APP_01 = "APP-01"
    APP_02 = "APP-02"
    APP_05 = "APP-05"


class FieldState(StrEnum):
    OBSERVED = "observed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ScenarioFields:
    use_case: str
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()


SCENARIO_MAPPING_VERSION = "dashen-synthetic-observation-v1"

# Each field describes evidence presence, NOT a field value or a detector.
# Required means required to *consider* the eventual scenario calculation.
# Real bank field mapping, thresholds, status rules and allowed purposes
# remain Bank-controlled adapter/configuration decisions.
SCENARIO_FIELDS: Mapping[ScenarioId, ScenarioFields] = MappingProxyType({
    ScenarioId.ATO_02: ScenarioFields("UC-01", (
        "authentication_outcome", "device_pseudonym", "device_first_seen",
        "device_known_status", "device_lookback", "session_anomaly",
    ), ("approved_device_reset",)),
    ScenarioId.ATO_06: ScenarioFields("UC-01", (
        "beneficiary_pseudonym", "beneficiary_created_at", "beneficiary_status",
        "beneficiary_baseline", "transfer_attempted_at", "transfer_status",
        "transfer_amount", "transfer_currency",
    ), ("transfer_executed_at", "transfer_settled_at")),
    ScenarioId.MM_01: ScenarioFields("UC-02", (
        "account_pseudonym", "inbound_credit_reference", "inbound_credit_status",
        "outbound_debit_reference", "outbound_debit_status", "flow_direction",
        "transfer_amount", "transfer_currency", "flow_window",
    ), ("counterparty_pseudonym", "reversal_status")),
    ScenarioId.MM_02: ScenarioFields("UC-02", (
        "sender_pseudonym", "beneficiary_pseudonym", "transfer_status",
        "observation_window", "window_completeness", "deduplicated_event_set",
        "external_institution_indicator",
    ), ("sender_baseline", "payroll_merchant_exclusion")),
    ScenarioId.MM_05: ScenarioFields("UC-02", (
        "account_pseudonym", "account_lifecycle_status", "prior_activity_window",
        "prior_transaction_count", "prior_value_aggregate", "current_activity_window",
        "current_transaction_count", "current_value_aggregate", "dormancy_policy_version",
    ), ("reactivation_reason", "scheduled_bulk_activity")),
    ScenarioId.APP_01: ScenarioFields("UC-03", (
        "beneficiary_pseudonym", "beneficiary_first_seen", "beneficiary_history",
        "payment_amount", "payment_currency", "customer_amount_baseline",
        "baseline_currency", "fx_normalization_source", "payment_status",
    ), ("expected_recurring_payment",)),
    ScenarioId.APP_02: ScenarioFields("UC-03", (
        "authorized_change_event", "change_kind", "change_source",
        "change_occurred_at", "payment_event", "payment_status",
        "payment_amount", "payment_currency", "payment_baseline",
    ), ("approved_maintenance_reset",)),
    ScenarioId.APP_05: ScenarioFields("UC-03", (
        "attempt_correlation", "attempt_times", "attempt_amounts",
        "attempt_currencies", "attempt_statuses", "attempt_window",
        "deduplicated_attempts",
    ), ("technical_retry_indicator",)),
})


def _token(name: str, value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical opaque reference required")
    return value


def _digest(name: str, value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: lowercase sha256 digest required")
    return value


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: timezone-aware datetime required")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class FieldEvidence:
    """Digest-only synthetic evidence presence; never accepts raw field values."""

    name: str
    state: FieldState
    source_ref: str | None = None
    source_version: str | None = None
    evidence_digest: str | None = None
    observed_at: datetime | None = None
    available_at: datetime | None = None
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        if type(self.name) is not str or _FIELD.fullmatch(self.name) is None:
            raise ScenarioContractError("invalid canonical field name")
        if type(self.state) is not FieldState:
            raise ScenarioContractError("field state must be a FieldState enum")
        if self.state is FieldState.UNAVAILABLE:
            _token("unavailable_reason", self.unavailable_reason)
            if any(value is not None for value in (
                self.source_ref, self.source_version, self.evidence_digest,
                self.observed_at, self.available_at,
            )):
                raise ScenarioContractError("unavailable field must not claim measured evidence")
            return
        if self.unavailable_reason is not None:
            raise ScenarioContractError("observed field cannot be unavailable")
        _token("source_ref", self.source_ref)
        _token("source_version", self.source_version)
        _digest("evidence_digest", self.evidence_digest)
        observed = _instant("observed_at", self.observed_at)
        available = _instant("available_at", self.available_at)
        if observed > available:
            raise ScenarioContractError("field observed after source availability")
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "available_at", available)


@dataclass(frozen=True, slots=True)
class ScenarioObservation:
    """One caller-asserted, dataset-bound synthetic observation of field coverage."""

    scenario_id: ScenarioId
    installation_ref: str
    tenant_ref: str
    dataset_digest: str
    event_id: UUID
    source_system: str
    source_schema_version: str
    mapping_version: str
    configuration_version: str
    occurred_at: datetime
    received_at: datetime
    decision_cutoff: datetime
    fields: tuple[FieldEvidence, ...]

    def __post_init__(self) -> None:
        if type(self.scenario_id) is not ScenarioId:
            raise ScenarioContractError("scenario_id must be a selected ScenarioId")
        for name in (
            "installation_ref", "tenant_ref", "source_system", "source_schema_version",
            "mapping_version", "configuration_version",
        ):
            _token(name, getattr(self, name))
        _digest("dataset_digest", self.dataset_digest)
        if type(self.event_id) is not UUID:
            raise ScenarioContractError("event_id must be UUID")
        occurred = _instant("occurred_at", self.occurred_at)
        received = _instant("received_at", self.received_at)
        cutoff = _instant("decision_cutoff", self.decision_cutoff)
        if not occurred <= received <= cutoff:
            raise ScenarioContractError("invalid occurred/received/cutoff chronology")
        for name, value in (
            ("occurred_at", occurred), ("received_at", received), ("decision_cutoff", cutoff)
        ):
            object.__setattr__(self, name, value)
        if type(self.fields) is not tuple:
            raise ScenarioContractError("fields must be an immutable tuple")
        allowed = set(SCENARIO_FIELDS[self.scenario_id].required)
        allowed.update(SCENARIO_FIELDS[self.scenario_id].optional)
        seen: set[str] = set()
        for field in self.fields:
            if type(field) is not FieldEvidence:
                raise ScenarioContractError("untyped field evidence")
            if field.name not in allowed or field.name in seen:
                raise ScenarioContractError("unknown or duplicated scenario field")
            seen.add(field.name)
            if field.state is FieldState.OBSERVED:
                if field.observed_at is None or field.available_at is None:
                    raise ScenarioContractError("missing observed source timestamps")
                if field.observed_at > cutoff or field.available_at > cutoff:
                    raise ScenarioContractError("post-cutoff field evidence rejected")

    def fingerprint(self) -> str:
        """Stable source-value-shape identity; not Bank provenance or approval."""
        fields = [{
            "name": field.name, "state": field.state.value,
            "source_ref": field.source_ref, "source_version": field.source_version,
            "evidence_digest": field.evidence_digest,
            "observed_at": field.observed_at.isoformat() if field.observed_at else None,
            "available_at": field.available_at.isoformat() if field.available_at else None,
            "unavailable_reason": field.unavailable_reason,
        } for field in sorted(self.fields, key=lambda item: item.name)]
        payload = {
            "domain": SCENARIO_MAPPING_VERSION,
            "scenario_id": self.scenario_id.value, "installation_ref": self.installation_ref,
            "tenant_ref": self.tenant_ref, "dataset_digest": self.dataset_digest,
            "event_id": str(self.event_id), "source_system": self.source_system,
            "source_schema_version": self.source_schema_version,
            "mapping_version": self.mapping_version,
            "configuration_version": self.configuration_version,
            "occurred_at": self.occurred_at.isoformat(),
            "received_at": self.received_at.isoformat(),
            "decision_cutoff": self.decision_cutoff.isoformat(), "fields": fields,
        }
        canonical = dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return "sha256:" + sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class ScenarioCoverage:
    scenario_id: ScenarioId
    use_case: str
    contract_version: str
    status: str
    missing_required: tuple[str, ...]
    unavailable_optional: tuple[str, ...]
    observation_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id.value,
            "use_case": self.use_case,
            "contract_version": self.contract_version,
            "status": self.status,
            "missing_required": list(self.missing_required),
            "unavailable_optional": list(self.unavailable_optional),
            "observation_digest": self.observation_digest,
            "source": "synthetic_caller_asserted",
            "bank_verified": False,
            "detection_executed": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
        }


def inspect_scenario_coverage(
    observation: ScenarioObservation, *, expected_installation: str,
    expected_tenant: str, expected_dataset_digest: str,
) -> ScenarioCoverage:
    """Coverage only: required absence BLOCKS; cannot promote #54 readiness."""
    if type(observation) is not ScenarioObservation:
        raise ScenarioContractError("typed scenario observation required")
    _token("expected_installation", expected_installation)
    _token("expected_tenant", expected_tenant)
    _digest("expected_dataset_digest", expected_dataset_digest)
    if (
        observation.installation_ref != expected_installation
        or observation.tenant_ref != expected_tenant
        or observation.dataset_digest != expected_dataset_digest
    ):
        raise ScenarioContractError("installation/tenant/dataset mismatch")
    mapping = SCENARIO_FIELDS[observation.scenario_id]
    available = {field.name for field in observation.fields
                 if field.state is FieldState.OBSERVED}
    missing = tuple(sorted(set(mapping.required) - available))
    unavailable_optional = tuple(sorted(set(mapping.optional) - available))
    return ScenarioCoverage(
        scenario_id=observation.scenario_id,
        use_case=mapping.use_case,
        contract_version=SCENARIO_MAPPING_VERSION,
        status="blocked_by_data" if missing else "synthetic_coverage_only",
        missing_required=missing,
        unavailable_optional=unavailable_optional,
        observation_digest=observation.fingerprint(),
    )
