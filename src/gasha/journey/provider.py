from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from gasha.domain.models import CanonicalTransaction
from gasha.journey.detector import JourneyAssessment, JourneyDetector
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.repository import JourneyEventRepository


class JourneyIntelligence(Protocol):
    """Optional enrichment port: journey context for a transaction.

    Returning ``None`` means journey intelligence is unavailable or not
    configured for the tenant — degraded, never suspicious.
    """

    def assess(
        self, transaction: CanonicalTransaction
    ) -> JourneyAssessment | None: ...


class PolicyBoundJourneyIntelligence:
    """Journey assessments bound to each tenant's own journey policy.

    Point-in-time correct: the assessment time is the transaction's
    ``occurred_at``, so only events at or before the payment can
    contribute.
    """

    def __init__(
        self,
        repository: JourneyEventRepository,
        policies: Mapping[str, JourneyRiskPolicy],
    ) -> None:
        self._repository = repository
        self._detectors = {
            tenant: JourneyDetector(repository, policy)
            for tenant, policy in policies.items()
        }

    def assess(
        self, transaction: CanonicalTransaction
    ) -> JourneyAssessment | None:
        detector = self._detectors.get(transaction.tenant_id)
        if detector is None:
            # Journey intelligence is not enabled for this tenant —
            # unavailable optional signal, not elevated risk.
            return None
        return detector.assess(
            transaction.tenant_id,
            transaction.sender_customer_id,
            as_of=transaction.occurred_at,
        )
