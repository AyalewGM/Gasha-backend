from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel

from gasha.decision.audit import (
    DecisionAuditRepository,
    InMemoryDecisionAuditRepository,
    audit_record,
)
from gasha.decision.mode import DecisionEnvelope, ModeAwareDecisionService
from gasha.domain.models import DecisionPolicy
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.poc.historical import MissingTenantPolicyError


class ShadowEvaluationRecord(BaseModel):
    """Persisted shadow evaluation — everything needed to reconstruct it.

    ``event`` carries the canonical transaction plus adapter/schema
    versions; ``evaluation`` carries the hypothetical Gasha decision, the
    non-enforcing effective action, versions, timestamp and latency.
    """

    event: FraudEventEnvelope
    evaluation: DecisionEnvelope
    persisted_at: datetime


class ShadowEvaluationRepository(Protocol):
    """Tenant-scoped persistence for shadow/enforcing evaluations."""

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> ShadowEvaluationRecord | None: ...

    def save(self, record: ShadowEvaluationRecord) -> ShadowEvaluationRecord: ...


class InMemoryShadowEvaluationRepository:
    """Reference store; production storage implements the same contract."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, UUID], ShadowEvaluationRecord] = {}

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> ShadowEvaluationRecord | None:
        return self._records.get((tenant_id, event_id))

    def save(
        self, record: ShadowEvaluationRecord
    ) -> ShadowEvaluationRecord:
        key = (
            record.event.tenant_id,
            record.event.event_id,
        )
        existing = self._records.get(key)
        if existing is not None:
            return existing
        self._records[key] = record
        return record


class ShadowOrchestrator:
    """Connects normalized envelopes to the existing decision engine.

    There is no second fraud engine here: every envelope goes through
    ``ModeAwareDecisionService`` with the tenant's own policy and the
    envelope's operating mode. In SHADOW mode the hypothetical decision
    (including BLOCK/HOLD) is persisted while the effective action stays
    non-enforcing. Persistence failures propagate — the orchestrator never
    reports an unaudited evaluation as audited.
    """

    def __init__(
        self,
        policies: Mapping[str, DecisionPolicy],
        *,
        evaluations: ShadowEvaluationRepository | None = None,
        audit: DecisionAuditRepository | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policies = dict(policies)
        self._evaluations = evaluations or InMemoryShadowEvaluationRepository()
        self._audit = audit or InMemoryDecisionAuditRepository()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def evaluations(self) -> ShadowEvaluationRepository:
        return self._evaluations

    def evaluate(self, event: FraudEventEnvelope) -> DecisionEnvelope:
        policy = self._policies.get(event.tenant_id)
        if policy is None:
            raise MissingTenantPolicyError(
                f"no decision policy registered for tenant "
                f"{event.tenant_id!r}"
            )

        evaluation = ModeAwareDecisionService(
            policy,
            operating_mode=event.operating_mode,
            clock=self._clock,
        ).decide(
            event.canonical_transaction,
            event.intelligence,
            event.evidence_reason_codes,
        )

        self._audit.save(
            audit_record(
                evaluation.decision,
                signal_policy_versions=event.signal_policy_versions,
            )
        )
        self._evaluations.save(
            ShadowEvaluationRecord(
                event=event,
                evaluation=evaluation,
                persisted_at=self._clock(),
            )
        )
        return evaluation
