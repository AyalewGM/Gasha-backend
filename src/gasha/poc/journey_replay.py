from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from gasha.domain.models import DecisionPolicy
from gasha.journey.detector import JourneyDetector
from gasha.journey.events import JourneyEvent
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.repository import InMemoryJourneyEventRepository
from gasha.poc.historical import (
    HistoricalReplayReport,
    HistoricalTransactionEvent,
    replay_historical,
)

JourneyReplayItem = JourneyEvent | HistoricalTransactionEvent


def replay_journey_scenario(
    items: Sequence[JourneyReplayItem],
    policies: Mapping[str, DecisionPolicy],
    journey_policies: Mapping[str, JourneyRiskPolicy],
) -> HistoricalReplayReport:
    """Replays a mixed journey/transaction stream chronologically.

    Events are ordered by ``occurred_at`` (business time, not arrival
    order) and appended to a tenant-scoped journey repository. Each
    transaction is then evaluated with the journey context legitimately
    available at its ``occurred_at`` — earlier events only, so replay can
    never leak future information into a past decision. Journey reason
    codes and the journey policy version are merged into the event's
    evidence before it enters the unmodified ``replay_historical`` path.
    """

    repository = InMemoryJourneyEventRepository()
    detectors = {
        tenant: JourneyDetector(repository, policy)
        for tenant, policy in journey_policies.items()
    }

    ordered = sorted(items, key=_occurred_at)
    transactions: list[HistoricalTransactionEvent] = []
    for item in ordered:
        if isinstance(item, JourneyEvent):
            repository.append(item)
            continue

        detector = detectors.get(item.transaction.tenant_id)
        assessment = (
            detector.assess(
                item.transaction.tenant_id,
                item.transaction.sender_customer_id,
                as_of=item.transaction.occurred_at,
            )
            if detector is not None
            else None
        )
        if assessment is None:
            transactions.append(item)
            continue
        transactions.append(
            item.model_copy(
                update={
                    "intelligence": item.intelligence.model_copy(
                        update={"journey_risk": assessment.journey_risk}
                    ),
                    "evidence_reason_codes": tuple(
                        dict.fromkeys(
                            [
                                *item.evidence_reason_codes,
                                *assessment.reason_codes,
                            ]
                        )
                    ),
                    "signal_policy_versions": tuple(
                        dict.fromkeys(
                            [
                                *item.signal_policy_versions,
                                assessment.policy_version,
                            ]
                        )
                    ),
                }
            )
        )
    return replay_historical(tuple(transactions), policies)


def _occurred_at(item: JourneyReplayItem) -> datetime:
    if isinstance(item, JourneyEvent):
        return item.occurred_at
    return item.transaction.occurred_at
