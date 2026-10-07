from __future__ import annotations

from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from gasha.domain.models import DecisionPolicy, IntelligenceSnapshot
from gasha.poc.attribution import SIGNAL_FAMILIES, SignalFamily
from gasha.poc.historical import (
    ALERT_ACTIONS,
    HistoricalReplayReport,
    HistoricalTransactionEvent,
    replay_historical,
)

FULL_CONFIGURATION = "full"


class AblationConfiguration(BaseModel):
    """A named replay configuration with signal families removed."""

    name: str = Field(min_length=1)
    removed_families: frozenset[SignalFamily] = frozenset()


class IncrementalDetectionReason(StrEnum):
    """A confirmed-fraud alert that disappeared when a family was removed.

    Marks cases where a signal family was *necessary* for detection — distinct
    from merely participating in a detection.
    """

    CUSTOMER_INCREMENTAL_DETECTION = "customer_incremental_detection"
    TRANSACTION_INCREMENTAL_DETECTION = "transaction_incremental_detection"
    BENEFICIARY_INCREMENTAL_DETECTION = "beneficiary_incremental_detection"
    RELATIONSHIP_INCREMENTAL_DETECTION = "relationship_incremental_detection"
    VELOCITY_INCREMENTAL_DETECTION = "velocity_incremental_detection"
    DEVICE_SESSION_INCREMENTAL_DETECTION = (
        "device_session_incremental_detection"
    )
    NETWORK_INCREMENTAL_DETECTION = "network_incremental_detection"


_FAMILY_INCREMENTAL_REASON = {
    family: IncrementalDetectionReason(
        f"{family.value}_incremental_detection"
    )
    for family in SIGNAL_FAMILIES
}


@dataclass(frozen=True)
class UniqueDetection:
    """A fraud alert present in the full run but absent without one family."""

    event_id: UUID
    tenant_id: str
    family: SignalFamily
    reason: IncrementalDetectionReason
    full_action: str
    ablated_action: str


@dataclass(frozen=True)
class AblationComparison:
    """Measured delta of one ablated configuration versus the full run.

    These deltas are analytical measurements of association on the replayed
    dataset, not proof of causal detection value.
    """

    configuration_name: str
    removed_families: tuple[SignalFamily, ...]
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    recall: float
    precision: float
    false_positive_rate: float
    recall_delta: float
    incremental_recall_contribution: float
    false_positive_delta: int
    detections_lost: int


@dataclass(frozen=True)
class AblationReport:
    """Full replay plus per-configuration comparisons and unique detections."""

    full: HistoricalReplayReport
    comparisons: tuple[AblationComparison, ...]
    unique_detections: tuple[UniqueDetection, ...]


def default_ablation_plan() -> tuple[AblationConfiguration, ...]:
    """Full run, each single family, and strategically important pairs.

    Deliberately bounded: combinatorial ablation across seven families would
    be uncontrolled; pairs are limited to documented high-interest sets.
    """

    plan = [
        AblationConfiguration(name=FULL_CONFIGURATION),
        *(
            AblationConfiguration(
                name=f"without_{family.value}",
                removed_families=frozenset({family}),
            )
            for family in SIGNAL_FAMILIES
        ),
        AblationConfiguration(
            name="without_beneficiary_and_relationship",
            removed_families=frozenset(
                {SignalFamily.BENEFICIARY, SignalFamily.RELATIONSHIP}
            ),
        ),
        AblationConfiguration(
            name="without_beneficiary_and_network",
            removed_families=frozenset(
                {SignalFamily.BENEFICIARY, SignalFamily.NETWORK}
            ),
        ),
        AblationConfiguration(
            name="without_device_session_and_velocity",
            removed_families=frozenset(
                {SignalFamily.DEVICE_SESSION, SignalFamily.VELOCITY}
            ),
        ),
    ]
    return tuple(plan)


def ablate_intelligence(
    snapshot: IntelligenceSnapshot, removed: AbstractSet[SignalFamily]
) -> IntelligenceSnapshot:
    """Returns a snapshot with the removed families zeroed out."""

    return IntelligenceSnapshot(
        **{
            family.snapshot_field: (
                0.0
                if family in removed
                else getattr(snapshot, family.snapshot_field)
            )
            for family in SIGNAL_FAMILIES
        }
    )


def run_ablation(
    events: Sequence[HistoricalTransactionEvent],
    policies: Mapping[str, DecisionPolicy],
    *,
    configurations: Sequence[AblationConfiguration] | None = None,
) -> AblationReport:
    """Replays the dataset under each configuration and measures deltas.

    Every configuration runs the same chronological ``replay_historical``
    decision path; ablated runs only zero the removed families' snapshot
    components before decision. Tenant-policy resolution and isolation are
    inherited unchanged from the replay runner.
    """

    plan = list(configurations or default_ablation_plan())
    if not any(not config.removed_families for config in plan):
        plan.insert(0, AblationConfiguration(name=FULL_CONFIGURATION))

    runs: dict[str, HistoricalReplayReport] = {}
    for config in plan:
        if not config.removed_families:
            configured = events
        else:
            configured = [
                event.model_copy(
                    update={
                        "intelligence": ablate_intelligence(
                            event.intelligence, config.removed_families
                        )
                    }
                )
                for event in events
            ]
        runs[config.name] = replay_historical(configured, policies)

    full_name = next(
        config.name for config in plan if not config.removed_families
    )
    full = runs[full_name]
    full_decisions = {
        (result.decision.tenant_id, result.decision.event_id): result
        for result in full.results
    }

    comparisons: list[AblationComparison] = []
    unique: list[UniqueDetection] = []
    for config in plan:
        if not config.removed_families:
            continue
        ablated = runs[config.name]
        metrics = ablated.metrics
        detections_lost = 0
        single_family = (
            next(iter(config.removed_families))
            if len(config.removed_families) == 1
            else None
        )
        for result in ablated.results:
            key = (result.decision.tenant_id, result.decision.event_id)
            baseline = full_decisions[key]
            lost = (
                baseline.decision.action in ALERT_ACTIONS
                and result.decision.action not in ALERT_ACTIONS
            )
            detections_lost += int(lost)
            if (
                lost
                and single_family is not None
                and result.event.label is not None
                and result.event.label.is_fraud
            ):
                unique.append(
                    UniqueDetection(
                        event_id=result.decision.event_id,
                        tenant_id=result.decision.tenant_id,
                        family=single_family,
                        reason=_FAMILY_INCREMENTAL_REASON[single_family],
                        full_action=str(baseline.decision.action),
                        ablated_action=str(result.decision.action),
                    )
                )

        comparisons.append(
            AblationComparison(
                configuration_name=config.name,
                removed_families=tuple(
                    family
                    for family in SIGNAL_FAMILIES
                    if family in config.removed_families
                ),
                true_positives=metrics.true_positives,
                false_positives=metrics.false_positives,
                true_negatives=metrics.true_negatives,
                false_negatives=metrics.false_negatives,
                recall=metrics.recall,
                precision=metrics.precision,
                false_positive_rate=metrics.false_positive_rate,
                recall_delta=metrics.recall - full.metrics.recall,
                incremental_recall_contribution=(
                    full.metrics.recall - metrics.recall
                ),
                false_positive_delta=(
                    metrics.false_positives - full.metrics.false_positives
                ),
                detections_lost=detections_lost,
            )
        )

    return AblationReport(
        full=full,
        comparisons=tuple(comparisons),
        unique_detections=tuple(unique),
    )
