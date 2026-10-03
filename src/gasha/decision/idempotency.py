from __future__ import annotations

from collections.abc import Sequence

from gasha.decision.audit import DecisionAuditRepository, audit_record
from gasha.decision.service import DecisionService
from gasha.domain.models import CanonicalTransaction, FraudDecision, IntelligenceSnapshot
from gasha.intelligence.provenance import IntelligenceEvidence


class IdempotentDecisionService:
    """Returns the first durable decision for a tenant/event idempotency key."""

    def __init__(
        self,
        decision_service: DecisionService,
        audit_repository: DecisionAuditRepository,
    ) -> None:
        self.decision_service = decision_service
        self.audit_repository = audit_repository

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        *,
        evidence_reason_codes: Sequence[str] = (),
        signal_policy_versions: Sequence[str] = (),
        evidence: Sequence[IntelligenceEvidence] = (),
    ) -> FraudDecision:
        existing = self.audit_repository.get(
            transaction.tenant_id, transaction.event_id
        )
        if existing is not None:
            return existing.decision

        decision = self.decision_service.decide(
            transaction,
            intelligence,
            evidence_reason_codes,
        )
        persisted = self.audit_repository.save(
            audit_record(
                decision,
                signal_policy_versions=signal_policy_versions,
                evidence=evidence,
            )
        )
        return persisted.decision
