"""Offline MM-01 rapid-credit / onward-debit hypothesis (#41/#48).

All inputs, funding links, status reports, exceptions and thresholds are
synthetic caller assertions. No Bank identity, source provenance, case,
decision, replay, readiness or payment/enforcement path imports this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from enum import StrEnum
from hashlib import sha256
from json import dumps

from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
    FieldState,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
    inspect_scenario_coverage,
)

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_MAX_AMOUNT = Decimal("1e18")
_MIN_AMOUNT = Decimal("0.000001")
_MAX_AMOUNT_DIGITS = 25
_MAX_SCALE = 6  # Bank-neutral synthetic-v1 precision, not currency minor units.


class MM01Direction(StrEnum):
    INBOUND = "inbound_credit"
    OUTBOUND = "outbound_debit"


class MM01TransferStatus(StrEnum):
    ATTEMPTED = "attempted"
    POSTED = "posted"
    SETTLED = "settled"
    FAILED = "failed"
    REVERSED = "reversed"
    UNKNOWN = "unknown"


class MM01Context(StrEnum):
    UNKNOWN = "unknown_unavailable"
    REPORTED_ABSENT = "reported_absent"
    REPORTED = "reported"


class MM01RelationshipKind(StrEnum):
    SAME_OWNER = "same_authorized_owner"
    DISTINCT_OWNERS = "distinct_authorized_owners"


class MM01Status(StrEnum):
    BLOCKED_REQUIRED_FIELDS = "blocked_required_fields"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_METRICS = "blocked_metrics"
    BLOCKED_LINKAGE = "blocked_credit_debit_account_linkage"
    BLOCKED_STATUS = "blocked_unconfirmed_or_failed_flow_status"
    BLOCKED_CHRONOLOGY = "blocked_flow_chronology"
    OUTSIDE_WINDOW = "outside_proposed_flow_window"
    BELOW_CREDIT_FLOOR = "below_proposed_credit_floor"
    BELOW_RATIO = "below_proposed_outbound_credit_ratio"
    CONTEXT_REVIEW = "optional_exception_context_unknown"
    CONTEXT_EXCLUSION = "reported_own_account_or_reversal_context"
    SYNTHETIC_HYPOTHESIS = "synthetic_rapid_receipt_onward_transfer_hypothesis"


def _token(name: str, value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise ScenarioContractError(f"{name}: canonical opaque token required")
    return value


def _instant(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ScenarioContractError(f"{name}: timezone-aware instant required")
    return value.astimezone(UTC)


def _amount(name: str, value: object) -> Decimal:
    """Synthetic-money-v1: finite [1e-6, 1e18], at most six decimals."""
    if type(value) is not Decimal or not value.is_finite():
        raise ScenarioContractError(f"{name}: strict finite Decimal required")
    if not _MIN_AMOUNT <= value <= _MAX_AMOUNT:
        raise ScenarioContractError(f"{name}: bounded positive amount required")
    exponent = value.as_tuple().exponent
    if (
        type(exponent) is not int or not -_MAX_SCALE <= exponent <= 18
        or len(value.as_tuple().digits) > _MAX_AMOUNT_DIGITS
    ):
        raise ScenarioContractError(f"{name}: synthetic monetary precision exceeded")
    return value


def _ratio(value: object) -> Decimal:
    """Synthetic-ratio-v1: finite (0, 1] with no more than six decimals."""
    if type(value) is not Decimal or not value.is_finite():
        raise ScenarioContractError("strict finite proposed ratio required")
    exponent = value.as_tuple().exponent
    if (
        not Decimal(0) < value <= Decimal(1)
        or type(exponent) is not int or not -6 <= exponent <= 0
        or len(value.as_tuple().digits) > 7
    ):
        raise ScenarioContractError("proposed ratio exceeds synthetic-v1 domain")
    return value


def _present(
    obj: MM01SyntheticPolicy | MM01SyntheticMetrics
    | MM01RelationshipEvidence | MM01FieldClaim,
) -> None:
    """Convert deleted required frozen-slot members to a redacted rejection."""
    for item in fields(obj):
        try:
            getattr(obj, item.name)
        except AttributeError as exc:
            raise ScenarioContractError("missing required synthetic flow field") from exc


@dataclass(frozen=True, slots=True)
class MM01SyntheticPolicy:
    """Versioned proposed test thresholds; never bank-approved policy."""

    version: str
    configuration_version: str
    max_credit_to_debit_seconds: int
    min_credit_amount: Decimal
    min_outbound_ratio: Decimal
    currency: str

    def __post_init__(self) -> None:
        _token("policy version", self.version)
        _token("policy configuration", self.configuration_version)
        if (
            type(self.max_credit_to_debit_seconds) is not int
            or not 1 <= self.max_credit_to_debit_seconds <= 86_400
        ):
            raise ScenarioContractError("bounded proposed time window required")
        _amount("credit floor", self.min_credit_amount)
        _ratio(self.min_outbound_ratio)
        if type(self.currency) is not str or _CURRENCY.fullmatch(self.currency) is None:
            raise ScenarioContractError("canonical floor currency required")


@dataclass(frozen=True, slots=True)
class MM01RelationshipEvidence:
    """Explicit *caller-asserted* same-owner relationship; not Bank attestation."""

    kind: MM01RelationshipKind
    source_ref: str
    source_version: str
    evidence_digest: str
    snapshot_digest: str
    installation_ref: str
    tenant_ref: str
    dataset_digest: str
    observed_at: datetime
    available_at: datetime
    permitted_purpose: str

    def __post_init__(self) -> None:
        if type(self.kind) is not MM01RelationshipKind:
            raise ScenarioContractError("strict synthetic relationship kind required")
        for name in ("source_ref", "source_version", "installation_ref",
                     "tenant_ref", "permitted_purpose"):
            _token(name, getattr(self, name))
        for name in ("evidence_digest", "snapshot_digest", "dataset_digest"):
            digest = getattr(self, name)
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
                raise ScenarioContractError("invalid synthetic relationship digest")
        for name in ("observed_at", "available_at"):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        if self.observed_at > self.available_at:
            raise ScenarioContractError("relationship observed after availability")


# Synthetic semantic value groupings, NOT a ledger adapter or Bank provenance.
_MM01_SEMANTIC_FIELDS: dict[str, tuple[str, ...]] = {
    "account_pseudonym": (
        "account_ref", "inbound_account_ref", "outbound_account_ref",
    ),
    "inbound_credit_reference": (
        "inbound_event_ref", "inbound_occurred_at", "inbound_available_at",
    ),
    "inbound_credit_status": ("inbound_status",),
    "outbound_debit_reference": (
        "outbound_event_ref", "outbound_occurred_at", "outbound_available_at",
    ),
    "outbound_debit_status": ("outbound_status",),
    "flow_direction": ("inbound_direction", "outbound_direction"),
    "transfer_amount": ("inbound_amount", "outbound_amount"),
    "transfer_currency": ("currency",),
    "flow_window": ("inbound_occurred_at", "outbound_occurred_at"),
    "reversal_status": ("reversal_context",),
    "own_account_relationship": ("own_account_context",),
}


def mm01_field_value_digest(name: str, metrics: MM01SyntheticMetrics) -> str:
    """Digest a declared semantic value tuple; no source trust is implied."""
    names = _MM01_SEMANTIC_FIELDS.get(name)
    if names is None:
        raise ScenarioContractError("unknown MM-01 semantic field")
    payload: dict[str, str] = {}
    for key in names:
        value = getattr(metrics, key)
        if isinstance(value, datetime):
            payload[key] = value.astimezone(UTC).isoformat()
        elif isinstance(value, StrEnum):
            payload[key] = value.value
        else:
            payload[key] = str(value)
    if name == "own_account_relationship" and metrics.own_account_relationship is not None:
        payload["relationship_kind"] = metrics.own_account_relationship.kind.value
        payload["permitted_purpose"] = metrics.own_account_relationship.permitted_purpose
    wire = dumps(
        {"domain": "mm01-synthetic-field-values-v1", "name": name, "payload": payload},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return "sha256:" + sha256(wire.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class MM01FieldClaim:
    """Per-field semantic binding to a caller-asserted observation snapshot."""

    name: str
    source_ref: str
    source_version: str
    evidence_digest: str
    value_digest: str
    snapshot_digest: str
    installation_ref: str
    tenant_ref: str
    dataset_digest: str
    mapping_version: str
    observed_at: datetime
    available_at: datetime

    def __post_init__(self) -> None:
        for name in ("name", "source_ref", "source_version", "installation_ref",
                     "tenant_ref", "mapping_version"):
            _token(name, getattr(self, name))
        for name in ("evidence_digest", "value_digest", "snapshot_digest",
                     "dataset_digest"):
            value = getattr(self, name)
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ScenarioContractError("invalid semantic binding digest")
        for name in ("observed_at", "available_at"):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        if self.observed_at > self.available_at:
            raise ScenarioContractError("semantic evidence observed after availability")


@dataclass(frozen=True, slots=True)
class MM01SyntheticMetrics:
    """Caller-asserted flow pair; coincidence is not proof of funds tracing."""

    observation_digest: str
    policy_version: str
    account_ref: str
    inbound_account_ref: str
    outbound_account_ref: str
    inbound_event_ref: str
    outbound_event_ref: str
    inbound_direction: MM01Direction
    outbound_direction: MM01Direction
    inbound_status: MM01TransferStatus
    outbound_status: MM01TransferStatus
    inbound_occurred_at: datetime
    outbound_occurred_at: datetime
    inbound_available_at: datetime
    outbound_available_at: datetime
    inbound_amount: Decimal
    outbound_amount: Decimal
    currency: str
    own_account_context: MM01Context = MM01Context.UNKNOWN
    reversal_context: MM01Context = MM01Context.UNKNOWN
    own_account_relationship: MM01RelationshipEvidence | None = None
    field_claims: tuple[MM01FieldClaim, ...] = ()

    def __post_init__(self) -> None:
        if type(self.observation_digest) is not str or _DIGEST.fullmatch(
            self.observation_digest
        ) is None:
            raise ScenarioContractError("invalid observation digest")
        for name in (
            "policy_version", "account_ref", "inbound_account_ref",
            "outbound_account_ref", "inbound_event_ref", "outbound_event_ref",
        ):
            _token(name, getattr(self, name))
        for name, enum in (
            ("inbound_direction", MM01Direction),
            ("outbound_direction", MM01Direction),
            ("inbound_status", MM01TransferStatus),
            ("outbound_status", MM01TransferStatus),
            ("own_account_context", MM01Context),
            ("reversal_context", MM01Context),
        ):
            if type(getattr(self, name)) is not enum:
                raise ScenarioContractError(f"{name}: strict typed enum required")
        if type(self.currency) is not str or _CURRENCY.fullmatch(self.currency) is None:
            raise ScenarioContractError("canonical flow currency required")
        if (
            self.own_account_relationship is not None
            and type(self.own_account_relationship) is not MM01RelationshipEvidence
        ):
            raise ScenarioContractError("strict synthetic relationship evidence required")
        if (
            type(self.field_claims) is not tuple
            or any(type(claim) is not MM01FieldClaim for claim in self.field_claims)
        ):
            raise ScenarioContractError("strict immutable semantic field claims required")
        _amount("inbound amount", self.inbound_amount)
        _amount("outbound amount", self.outbound_amount)
        for name in (
            "inbound_occurred_at", "outbound_occurred_at",
            "inbound_available_at", "outbound_available_at",
        ):
            object.__setattr__(self, name, _instant(name, getattr(self, name)))
        if (
            self.inbound_occurred_at > self.inbound_available_at
            or self.outbound_occurred_at > self.outbound_available_at
        ):
            raise ScenarioContractError("event evidence available before event occurred")


@dataclass(frozen=True, slots=True)
class MM01SyntheticResult:
    status: MM01Status
    observation_digest: str
    effective_input_digest: str | None
    configuration_version: str
    policy_version: str | None
    reasons: tuple[str, ...]
    heuristic_evaluated: bool

    def to_dict(self) -> dict[str, object]:
        """No amount, account, counterparty, risk score or prevention claim."""
        return {
            "scenario_id": "MM-01",
            "use_case": "UC-02",
            "status": self.status.value,
            "reasons": list(self.reasons),
            "observation_digest": self.observation_digest,
            "effective_input_digest": self.effective_input_digest,
            "configuration_version": self.configuration_version,
            "policy_version": self.policy_version,
            "heuristic_evaluated": self.heuristic_evaluated,
            "source": "synthetic_caller_asserted",
            "bank_verified": False,
            "fraud_determined": False,
            "funds_traced": False,
            "funds_stopped": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
        }


def _input_digest(policy: MM01SyntheticPolicy, metrics: MM01SyntheticMetrics) -> str:
    """Hash all effective claimed fields, never attest to their origin."""
    def encode(obj: MM01SyntheticPolicy | MM01SyntheticMetrics) -> dict[str, str]:
        payload: dict[str, str] = {}
        for item in fields(obj):
            value = getattr(obj, item.name)
            if isinstance(value, datetime):
                payload[item.name] = value.isoformat()
            elif isinstance(value, StrEnum):
                payload[item.name] = value.value
            else:
                payload[item.name] = str(value)
        return payload

    wire = dumps(
        {"domain": "mm01-synthetic-v1", "policy": encode(policy),
         "metrics": encode(metrics)},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return "sha256:" + sha256(wire.encode("ascii")).hexdigest()


def _validate_field_claims(
    observation: ScenarioObservation, metrics: MM01SyntheticMetrics,
    snapshot_digest: str,
) -> None:
    """Reject unbound or source-spliced synthetic semantics before any outcome."""
    needed = set(SCENARIO_FIELDS[ScenarioId.MM_01].required)
    if metrics.own_account_context is not MM01Context.UNKNOWN:
        needed.add("own_account_relationship")
    if metrics.reversal_context is not MM01Context.UNKNOWN:
        needed.add("reversal_status")
    claims = metrics.field_claims
    if len(claims) != len(needed) or {claim.name for claim in claims} != needed:
        raise ScenarioContractError("missing, duplicate or extra semantic field claim")
    evidence = {
        field.name: field for field in observation.fields
        if field.state is FieldState.OBSERVED
    }
    by_name = {claim.name: claim for claim in claims}
    for claim in claims:
        source = evidence.get(claim.name)
        if source is None:
            raise ScenarioContractError("semantic field source unavailable")
        if (
            claim.source_ref != source.source_ref
            or claim.source_version != source.source_version
            or claim.evidence_digest != source.evidence_digest
            or claim.observed_at != source.observed_at
            or claim.available_at != source.available_at
            or claim.snapshot_digest != snapshot_digest
            or claim.installation_ref != observation.installation_ref
            or claim.tenant_ref != observation.tenant_ref
            or claim.dataset_digest != observation.dataset_digest
            or claim.mapping_version != observation.mapping_version
            or claim.value_digest != mm01_field_value_digest(claim.name, metrics)
            or claim.available_at > observation.decision_cutoff
        ):
            raise ScenarioContractError("semantic field source/value/snapshot mismatch")
    for left, right in (
        ("inbound_credit_reference", "inbound_credit_status"),
        ("outbound_debit_reference", "outbound_debit_status"),
    ):
        a, b = by_name[left], by_name[right]
        if a.source_ref != b.source_ref or a.source_version != b.source_version:
            raise ScenarioContractError("event and status semantic sources spliced")
    # MM-01 synthetic event-clock-v1: pre-issued account/event identifiers may
    # predate a debit. An event's status, or joined values describing the debit,
    # cannot be *observed* before the corresponding event exists. These clocks
    # remain caller claims and are NOT authenticated Bank posting timestamps.
    event_derived = {
        "inbound_credit_status": metrics.inbound_occurred_at,
        "outbound_debit_status": metrics.outbound_occurred_at,
        "flow_direction": metrics.outbound_occurred_at,
        "transfer_amount": metrics.outbound_occurred_at,
        "transfer_currency": metrics.outbound_occurred_at,
        "flow_window": metrics.outbound_occurred_at,
    }
    if metrics.reversal_context is not MM01Context.UNKNOWN:
        event_derived["reversal_status"] = metrics.outbound_occurred_at
    for name, occurred_at in event_derived.items():
        if by_name[name].observed_at < occurred_at:
            raise ScenarioContractError("event-derived evidence predates event")
    for name in ("inbound_credit_reference", "inbound_credit_status"):
        if by_name[name].available_at > metrics.outbound_occurred_at:
            raise ScenarioContractError("inbound evidence unavailable at debit")
    if metrics.inbound_available_at > metrics.outbound_occurred_at:
        raise ScenarioContractError("claimed inbound event unavailable at debit")


def evaluate_mm01_synthetic(
    observation: ScenarioObservation, *,
    policy: MM01SyntheticPolicy | None,
    metrics: MM01SyntheticMetrics | None,
    expected_installation: str,
    expected_tenant: str,
    expected_dataset_digest: str,
) -> MM01SyntheticResult:
    """Evaluate only a bounded synthetic flow hypothesis, with no side effects."""
    coverage = inspect_scenario_coverage(
        observation,
        expected_installation=expected_installation,
        expected_tenant=expected_tenant,
        expected_dataset_digest=expected_dataset_digest,
    )
    if observation.scenario_id is not ScenarioId.MM_01:
        raise ScenarioContractError("MM-01 observation required")
    if policy is not None:
        if type(policy) is not MM01SyntheticPolicy:
            raise ScenarioContractError("typed MM-01 policy required")
        _present(policy)
        policy = replace(policy)
    if metrics is not None:
        if type(metrics) is not MM01SyntheticMetrics:
            raise ScenarioContractError("typed MM-01 metrics required")
        _present(metrics)
        if metrics.own_account_relationship is not None:
            if type(metrics.own_account_relationship) is not MM01RelationshipEvidence:
                raise ScenarioContractError("strict synthetic relationship evidence required")
            _present(metrics.own_account_relationship)
            metrics = replace(
                metrics, own_account_relationship=replace(metrics.own_account_relationship)
            )
        if type(metrics.field_claims) is not tuple:
            raise ScenarioContractError("strict immutable semantic field claims required")
        for claim in metrics.field_claims:
            if type(claim) is not MM01FieldClaim:
                raise ScenarioContractError("strict typed semantic claim required")
            _present(claim)
        metrics = replace(metrics, field_claims=tuple(
            replace(claim) for claim in metrics.field_claims
        ))
    digest = _input_digest(policy, metrics) if policy is not None and metrics is not None else None

    def result(
        status: MM01Status, *reasons: str, evaluated: bool = False,
    ) -> MM01SyntheticResult:
        return MM01SyntheticResult(
            status=status, observation_digest=coverage.observation_digest,
            effective_input_digest=digest,
            configuration_version=observation.configuration_version,
            policy_version=policy.version if policy is not None else None,
            reasons=tuple(reasons), heuristic_evaluated=evaluated,
        )

    if coverage.missing_required:
        return result(MM01Status.BLOCKED_REQUIRED_FIELDS, *coverage.missing_required)
    if policy is None:
        return result(MM01Status.BLOCKED_POLICY, "proposed_thresholds_unavailable")
    if metrics is None:
        return result(MM01Status.BLOCKED_METRICS, "matched_flow_evidence_unavailable")
    if (
        policy.configuration_version != observation.configuration_version
        or metrics.observation_digest != coverage.observation_digest
        or metrics.policy_version != policy.version
    ):
        raise ScenarioContractError("policy/observation/metric binding mismatch")
    if (
        metrics.outbound_event_ref != str(observation.event_id)
        or metrics.inbound_event_ref == metrics.outbound_event_ref
        or metrics.outbound_occurred_at != observation.occurred_at
        or metrics.outbound_available_at > observation.decision_cutoff
        or metrics.inbound_available_at > observation.decision_cutoff
    ):
        raise ScenarioContractError("flow event identity or cutoff mismatch")
    if (
        metrics.currency != policy.currency
        or metrics.inbound_direction is not MM01Direction.INBOUND
        or metrics.outbound_direction is not MM01Direction.OUTBOUND
    ):
        raise ScenarioContractError("flow direction/currency policy mismatch")
    available_optional = {
        f.name for f in observation.fields if f.state is FieldState.OBSERVED
    }
    # Counterparty identifier presence does NOT show authorized shared ownership.
    if (
        metrics.own_account_context is not MM01Context.UNKNOWN
        and "own_account_relationship" not in available_optional
    ):
        raise ScenarioContractError("claimed optional context without observed evidence")
    if (
        metrics.reversal_context is not MM01Context.UNKNOWN
        and "reversal_status" not in available_optional
    ):
        raise ScenarioContractError("claimed optional context without observed evidence")

    relation = metrics.own_account_relationship
    if metrics.own_account_context is not MM01Context.UNKNOWN and relation is None:
        raise ScenarioContractError("own-account classification requires relationship evidence")
    if relation is not None:
        source = next(
            (field for field in observation.fields
             if field.name == "own_account_relationship"), None
        )
        if source is None or source.state is not FieldState.OBSERVED:
            raise ScenarioContractError("relationship source unavailable")
        if (
            relation.source_ref != source.source_ref
            or relation.source_version != source.source_version
            or relation.evidence_digest != source.evidence_digest
            or relation.observed_at != source.observed_at
            or relation.available_at != source.available_at
            or relation.snapshot_digest != coverage.observation_digest
            or relation.installation_ref != observation.installation_ref
            or relation.tenant_ref != observation.tenant_ref
            or relation.dataset_digest != observation.dataset_digest
            or relation.permitted_purpose != "synthetic_mm01_own_account_exclusion"
            or relation.available_at > observation.decision_cutoff
            or relation.available_at > metrics.outbound_occurred_at
        ):
            raise ScenarioContractError("relationship source, purpose or snapshot mismatch")
        if (
            (metrics.own_account_context is MM01Context.REPORTED
             and relation.kind is not MM01RelationshipKind.SAME_OWNER)
            or (metrics.own_account_context is MM01Context.REPORTED_ABSENT
                and relation.kind is not MM01RelationshipKind.DISTINCT_OWNERS)
        ):
            raise ScenarioContractError("relationship classification mismatch")
    _validate_field_claims(observation, metrics, coverage.observation_digest)
    if (
        metrics.inbound_account_ref != metrics.account_ref
        or metrics.outbound_account_ref != metrics.account_ref
    ):
        return result(MM01Status.BLOCKED_LINKAGE, "different_synthetic_account")
    if (
        metrics.inbound_occurred_at >= metrics.outbound_occurred_at
        or metrics.inbound_available_at > metrics.outbound_occurred_at
    ):
        return result(MM01Status.BLOCKED_CHRONOLOGY, "credit_not_known_before_debit")
    if (
        metrics.inbound_status in (
            MM01TransferStatus.REVERSED, MM01TransferStatus.FAILED,
        )
        or metrics.outbound_status in (
            MM01TransferStatus.REVERSED, MM01TransferStatus.FAILED,
        )
    ):
        return result(MM01Status.BLOCKED_STATUS, "reversed_or_failed_event")
    if (
        metrics.inbound_status not in (
            MM01TransferStatus.POSTED, MM01TransferStatus.SETTLED,
        )
        or metrics.outbound_status not in (
            MM01TransferStatus.POSTED, MM01TransferStatus.SETTLED,
        )
    ):
        return result(MM01Status.BLOCKED_STATUS, "unconfirmed_credit_or_debit")
    if metrics.outbound_occurred_at - metrics.inbound_occurred_at > timedelta(
        seconds=policy.max_credit_to_debit_seconds
    ):
        return result(MM01Status.OUTSIDE_WINDOW, "elapsed_time_exceeds_policy", evaluated=True)
    if metrics.inbound_amount < policy.min_credit_amount:
        return result(MM01Status.BELOW_CREDIT_FLOOR, "credit_below_policy", evaluated=True)
    # Fixed high-precision multiplication avoids unsafe Decimal division.
    with localcontext() as arithmetic:
        arithmetic.prec = 64
        below_ratio = (
            metrics.outbound_amount
            < metrics.inbound_amount * policy.min_outbound_ratio
        )
    if below_ratio:
        return result(MM01Status.BELOW_RATIO, "onward_ratio_below_policy", evaluated=True)
    if MM01Context.REPORTED in (
        metrics.own_account_context, metrics.reversal_context,
    ):
        return result(
            MM01Status.CONTEXT_EXCLUSION, "reported_own_account_or_reversal",
            evaluated=True,
        )
    if MM01Context.UNKNOWN in (
        metrics.own_account_context, metrics.reversal_context,
    ):
        return result(
            MM01Status.CONTEXT_REVIEW, "optional_context_unavailable",
            evaluated=True,
        )
    return result(
        MM01Status.SYNTHETIC_HYPOTHESIS,
        "reported_rapid_credit_and_onward_debit_not_bank_verified",
        evaluated=True,
    )
