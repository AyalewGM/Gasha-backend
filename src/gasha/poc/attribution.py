from __future__ import annotations

from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import StrEnum
from statistics import fmean
from uuid import UUID

from gasha.domain.models import DecisionPolicy
from gasha.poc.historical import (
    ALERT_ACTIONS,
    MissingTenantPolicyError,
    ReplayClassification,
    ReplayedEventResult,
)


class SignalFamily(StrEnum):
    """The independent intelligence families fused by the decision service."""

    CUSTOMER = "customer"
    TRANSACTION = "transaction"
    BENEFICIARY = "beneficiary"
    RELATIONSHIP = "relationship"
    VELOCITY = "velocity"
    DEVICE_SESSION = "device_session"
    NETWORK = "network"
    JOURNEY = "journey"

    @property
    def snapshot_field(self) -> str:
        return f"{self.value}_risk"

    @property
    def reason_code(self) -> str:
        return f"HIGH_{self.value.upper()}_RISK"


SIGNAL_FAMILIES: tuple[SignalFamily, ...] = tuple(SignalFamily)

# Named family combinations matched against the influenced-family set of each
# alert. Tenants may override or extend this mapping; names are configuration,
# not bank-specific logic.
DEFAULT_SIGNAL_COMBINATIONS: dict[str, frozenset[SignalFamily]] = {
    "new_beneficiary_unusual_amount": frozenset(
        {SignalFamily.RELATIONSHIP, SignalFamily.TRANSACTION}
    ),
    "new_beneficiary_active_call": frozenset(
        {SignalFamily.RELATIONSHIP, SignalFamily.DEVICE_SESSION}
    ),
    "beneficiary_high_velocity": frozenset(
        {SignalFamily.BENEFICIARY, SignalFamily.VELOCITY}
    ),
    "behavioral_anomaly_beneficiary_risk": frozenset(
        {SignalFamily.DEVICE_SESSION, SignalFamily.BENEFICIARY}
    ),
    "fan_in_repeat_victims": frozenset(
        {SignalFamily.BENEFICIARY, SignalFamily.NETWORK}
    ),
    "device_session_graph_risk": frozenset(
        {SignalFamily.DEVICE_SESSION, SignalFamily.NETWORK}
    ),
    "relationship_behavioral_anomaly": frozenset(
        {SignalFamily.RELATIONSHIP, SignalFamily.DEVICE_SESSION}
    ),
    "ato_journey_new_beneficiary": frozenset(
        {SignalFamily.JOURNEY, SignalFamily.RELATIONSHIP}
    ),
    "ato_journey_mule_recipient": frozenset(
        {SignalFamily.JOURNEY, SignalFamily.NETWORK}
    ),
}


@dataclass(frozen=True)
class EventAttribution:
    """Attribution of one replayed decision to signal families.

    ``influenced`` families crossed the tenant's review threshold and would
    each independently have produced at least a REVIEW alert. ``driving``
    families equal the fused max score — they set the decision risk score.
    Presence alone never counts as influence.
    """

    event_id: UUID
    tenant_id: str
    alerted: bool
    influenced: frozenset[SignalFamily]
    driving: frozenset[SignalFamily]


@dataclass(frozen=True)
class SignalFamilyAttribution:
    family: SignalFamily
    alerts_influenced: int
    driving_alerts: int
    true_positives_influenced: int
    false_positives_influenced: int
    share_of_detected_fraud: float | None
    mean_risk_contribution: float | None
    max_risk_contribution: float | None
    reason_codes: frozenset[str]


@dataclass(frozen=True)
class MultiSignalDetection:
    """An alert where more than one signal family crossed the review bar."""

    event_id: UUID
    tenant_id: str
    families: tuple[SignalFamily, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class MultiSignalAnalysis:
    detections: tuple[MultiSignalDetection, ...]
    family_combination_counts: Mapping[tuple[SignalFamily, ...], int]
    named_combination_detections: Mapping[str, int]


@dataclass(frozen=True)
class SignalAttributionReport:
    # Aggregate family counts have exactly one tenant scope, never pooled banks.
    tenant_id: str | None
    events: tuple[EventAttribution, ...]
    families: Mapping[SignalFamily, SignalFamilyAttribution]
    multi_signal: MultiSignalAnalysis


def attribute_signals(
    results: Sequence[ReplayedEventResult],
    policies: Mapping[str, DecisionPolicy],
    *,
    combinations: Mapping[str, AbstractSet[SignalFamily]] | None = None,
) -> SignalAttributionReport:
    """Deterministically attributes replayed alerts to signal families.

    Methodology: a family influenced an alert iff its fused component reached
    the tenant's ``review_threshold`` (it emitted a ``HIGH_*_RISK`` reason and
    would independently have alerted); a family drove the decision iff its
    component equals the fused max risk score. Combinations are reported when
    their family set is a subset of the influenced set, and the raw
    co-influenced family sets are counted for every multi-signal alert.
    """

    tenants = {result.decision.tenant_id for result in results}
    if len(tenants) > 1:
        raise ValueError("mixed-tenant signal attribution is not permitted")
    named_combinations = (
        combinations
        if combinations is not None
        else DEFAULT_SIGNAL_COMBINATIONS
    )
    attributed: list[EventAttribution] = []
    seen: set[tuple[str, UUID]] = set()

    for result in results:
        tenant_id = result.decision.tenant_id
        identity = (tenant_id, result.decision.event_id)
        event_identity = (
            result.event.transaction.tenant_id, result.event.transaction.event_id,
        )
        if event_identity != identity:
            raise ValueError("replayed decision and event identity mismatch")
        if identity in seen:
            raise ValueError("duplicate tenant/event attribution identity")
        seen.add(identity)
        policy = policies.get(tenant_id)
        if policy is None:
            raise MissingTenantPolicyError(
                f"no decision policy registered for tenant {tenant_id!r}"
            )
        snapshot = result.event.intelligence
        values = {
            family: getattr(snapshot, family.snapshot_field)
            for family in SignalFamily
        }
        influenced = frozenset(
            family
            for family, value in values.items()
            if value >= policy.review_threshold
        )
        alerted = result.decision.action in ALERT_ACTIONS
        driving = (
            frozenset(
                family
                for family, value in values.items()
                if value == result.decision.risk_score
            )
            if alerted and result.decision.risk_score > 0.0
            else frozenset()
        )
        attributed.append(
            EventAttribution(
                event_id=result.decision.event_id,
                tenant_id=tenant_id,
                alerted=alerted,
                influenced=influenced if alerted else frozenset(),
                driving=driving,
            )
        )

    return SignalAttributionReport(
        tenant_id=next(iter(tenants), None),
        events=tuple(attributed),
        families=_family_metrics(attributed, results),
        multi_signal=_multi_signal(attributed, results, named_combinations),
    )


def _family_metrics(
    attributed: list[EventAttribution],
    results: Sequence[ReplayedEventResult],
) -> dict[SignalFamily, SignalFamilyAttribution]:
    total_tp = sum(
        1
        for result in results
        if result.classification == ReplayClassification.TRUE_POSITIVE
    )
    by_event = {
        (result.decision.tenant_id, result.decision.event_id): result
        for result in results
    }
    metrics: dict[SignalFamily, SignalFamilyAttribution] = {}

    for family in SignalFamily:
        influenced_results = [
            by_event[(event.tenant_id, event.event_id)]
            for event in attributed
            if event.alerted and family in event.influenced
        ]
        contributions = [
            getattr(
                result.event.intelligence, family.snapshot_field
            )
            for result in influenced_results
        ]
        tp_influenced = sum(
            1
            for result in influenced_results
            if result.classification == ReplayClassification.TRUE_POSITIVE
        )
        fp_influenced = sum(
            1
            for result in influenced_results
            if result.classification == ReplayClassification.FALSE_POSITIVE
        )
        reason_codes = {
            code
            for result in influenced_results
            for code in result.decision.reason_codes
        }
        metrics[family] = SignalFamilyAttribution(
            family=family,
            alerts_influenced=len(influenced_results),
            driving_alerts=sum(
                1
                for event in attributed
                if event.alerted and family in event.driving
            ),
            true_positives_influenced=tp_influenced,
            false_positives_influenced=fp_influenced,
            share_of_detected_fraud=tp_influenced / total_tp if total_tp else None,
            mean_risk_contribution=(
                fmean(contributions) if contributions else None
            ),
            max_risk_contribution=(
                max(contributions) if contributions else None
            ),
            reason_codes=frozenset(reason_codes),
        )

    return metrics


def _multi_signal(
    attributed: list[EventAttribution],
    results: Sequence[ReplayedEventResult],
    combinations: Mapping[str, AbstractSet[SignalFamily]],
) -> MultiSignalAnalysis:
    by_event = {
        (result.decision.tenant_id, result.decision.event_id): result
        for result in results
    }
    detections: list[MultiSignalDetection] = []
    family_combination_counts: dict[tuple[SignalFamily, ...], int] = {}
    named_counts = {name: 0 for name in combinations}

    for event in attributed:
        if not event.alerted or len(event.influenced) < 2:
            continue
        families = tuple(
            family
            for family in SIGNAL_FAMILIES
            if family in event.influenced
        )
        family_combination_counts[families] = (
            family_combination_counts.get(families, 0) + 1
        )
        for name, required in combinations.items():
            if set(required) <= event.influenced:
                named_counts[name] += 1
        detections.append(
            MultiSignalDetection(
                event_id=event.event_id,
                tenant_id=event.tenant_id,
                families=families,
                reason_codes=tuple(
                    by_event[(event.tenant_id, event.event_id)].decision.reason_codes
                ),
            )
        )

    return MultiSignalAnalysis(
        detections=tuple(detections),
        family_combination_counts=family_combination_counts,
        named_combination_detections=named_counts,
    )
