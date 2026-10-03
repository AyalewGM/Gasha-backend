from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from gasha.domain.models import FraudDecision
from gasha.intelligence.provenance import IntelligenceEvidence


@dataclass(frozen=True)
class DecisionAuditRecord:
    decision: FraudDecision
    signal_policy_versions: tuple[str, ...] = ()
    evidence: tuple[IntelligenceEvidence, ...] = ()


class DecisionAuditRepository(Protocol):
    def get(self, tenant_id: str, event_id: UUID) -> DecisionAuditRecord | None: ...

    def save(self, record: DecisionAuditRecord) -> DecisionAuditRecord: ...


class InMemoryDecisionAuditRepository:
    """Test/reference repository; production storage implements the same contract."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, UUID], DecisionAuditRecord] = {}

    def get(self, tenant_id: str, event_id: UUID) -> DecisionAuditRecord | None:
        return self._records.get((tenant_id, event_id))

    def save(self, record: DecisionAuditRecord) -> DecisionAuditRecord:
        key = (record.decision.tenant_id, record.decision.event_id)
        existing = self._records.get(key)
        if existing is not None:
            return existing
        self._records[key] = record
        return record


def audit_record(
    decision: FraudDecision,
    *,
    signal_policy_versions: Sequence[str] = (),
    evidence: Sequence[IntelligenceEvidence] = (),
) -> DecisionAuditRecord:
    return DecisionAuditRecord(
        decision=decision,
        signal_policy_versions=tuple(dict.fromkeys(signal_policy_versions)),
        evidence=tuple(evidence),
    )
