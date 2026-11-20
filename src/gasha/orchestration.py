from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol, Self
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from gasha.decision.audit import (
    DecisionAuditRecord,
    DecisionAuditRepository,
    InMemoryDecisionAuditRepository,
    audit_record,
)
from gasha.decision.mode import DecisionEnvelope, ModeAwareDecisionService
from gasha.domain.models import DecisionAction, DecisionPolicy, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.intelligence.feature_assessment_v1 import FeatureAssessmentV1
from gasha.intelligence.feature_evidence_v1 import SyntheticFeatureEvidenceV1
from gasha.journey.detector import JourneyAssessment
from gasha.journey.provider import JourneyIntelligence
from gasha.observability.metrics import MetricsRegistry
from gasha.poc.historical import MissingTenantPolicyError


class ShadowEvaluationRecord(BaseModel):
    """Persisted shadow evaluation — everything needed to reconstruct it.

    ``event`` carries the canonical transaction plus adapter/schema
    versions; ``evaluation`` carries the hypothetical Gasha decision, the
    non-enforcing effective action, versions, timestamp and latency;
    ``journey`` preserves the journey assessment evidence when UC-03
    enrichment ran.
    """

    event: FraudEventEnvelope
    evaluation: DecisionEnvelope
    persisted_at: datetime
    journey: JourneyAssessment | None = None
    # Keep pre-existing serialized evaluation/content digests byte-stable.
    feature_evidence: SyntheticFeatureEvidenceV1 | None = Field(
        default=None, exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_feature_evidence(self) -> Self:
        if self.feature_evidence is not None:
            self.feature_evidence.assert_matches_event(self.event)
            if (
                self.evaluation.operating_mode is not OperatingMode.SHADOW
                or self.evaluation.effective_action is not DecisionAction.NO_ACTION_SHADOW
            ):
                raise ValueError("feature evidence requires a non-enforcing shadow evaluation")
        return self


class ShadowEvaluationRepository(Protocol):
    """Tenant-scoped persistence for shadow/enforcing evaluations."""

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> ShadowEvaluationRecord | None: ...

    def save(self, record: ShadowEvaluationRecord) -> ShadowEvaluationRecord: ...


class EvaluationPersistence(Protocol):
    """Atomic persistence boundary for audit + shadow evaluation.

    One evaluation produces two durable artifacts — the decision audit
    and the shadow evaluation record. They must land together: an
    implementation writes both in a single transaction (or returns the
    already-persisted pair on first-write-wins), so a retry can never
    find the audit committed while the evaluation is missing, and
    evidence never disagrees across the two stores.
    """

    def save(
        self,
        record: ShadowEvaluationRecord,
        audit: DecisionAuditRecord,
    ) -> ShadowEvaluationRecord: ...


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
        metrics: MetricsRegistry | None = None,
        journey: JourneyIntelligence | None = None,
        persistence: EvaluationPersistence | None = None,
    ) -> None:
        self._policies = dict(policies)
        self._evaluations = evaluations or InMemoryShadowEvaluationRepository()
        self._audit = audit or InMemoryDecisionAuditRepository()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._metrics = metrics
        self._journey = journey
        self._persistence = persistence

    @property
    def evaluations(self) -> ShadowEvaluationRepository:
        return self._evaluations

    def evaluate(
        self,
        event: FraudEventEnvelope,
        policy: DecisionPolicy | None = None,
        *,
        feature_assessment: FeatureAssessmentV1 | None = None,
    ) -> DecisionEnvelope:
        """Evaluate under ``policy`` when given (pinned replay snapshot)
        else the tenant's currently registered policy."""
        # Explicit trusted in-process synthetic assessment only. Neither JSON
        # nor protected API can supply lineage or select an enforcing mode.
        feature_evidence = None
        if feature_assessment is not None:
            if (
                type(feature_assessment) is not FeatureAssessmentV1
                or event != feature_assessment.assessed_envelope
            ):
                raise ValueError("synthetic feature assessment mismatch")
            feature_evidence = SyntheticFeatureEvidenceV1.from_assessment(
                feature_assessment
            )
        resolved = policy or self._policies.get(event.tenant_id)
        if resolved is None:
            raise MissingTenantPolicyError(
                f"no decision policy registered for tenant "
                f"{event.tenant_id!r}"
            )

        intelligence = event.intelligence
        evidence = list(event.evidence_reason_codes)
        assessment = self._journey_assessment(event)
        if assessment is not None:
            intelligence = intelligence.model_copy(
                update={"journey_risk": assessment.journey_risk}
            )
            evidence.extend(assessment.reason_codes)

        try:
            evaluation = ModeAwareDecisionService(
                resolved,
                operating_mode=event.operating_mode,
                clock=self._clock,
            ).decide(
                event.canonical_transaction,
                intelligence,
                evidence,
            )
        except Exception:
            self._count("gasha_evaluation_failures", event.tenant_id)
            raise
        self._count("gasha_evaluations_completed", event.tenant_id)
        self._count(
            "gasha_shadow_hypothetical_decisions",
            event.tenant_id,
            action=evaluation.decision.action.value,
        )
        if self._metrics is not None:
            self._metrics.observe(
                "gasha_evaluation_latency_ms",
                evaluation.evaluation_latency_ms,
                labels={"tenant_id": event.tenant_id},
            )

        record = ShadowEvaluationRecord(
            event=event,
            evaluation=evaluation,
            persisted_at=self._clock(),
            journey=assessment,
            feature_evidence=feature_evidence,
        )
        audit = audit_record(
            evaluation.decision,
            signal_policy_versions=event.signal_policy_versions,
        )
        try:
            if self._persistence is not None:
                return self._persistence.save(record, audit).evaluation
            else:
                self._audit.save(audit)
                self._evaluations.save(record)
        except Exception:
            self._count("gasha_persistence_failures", event.tenant_id)
            raise
        return evaluation

    def _journey_assessment(
        self, event: FraudEventEnvelope
    ) -> JourneyAssessment | None:
        if self._journey is None:
            return None
        try:
            assessment = self._journey.assess(event.canonical_transaction)
        except Exception:  # noqa: BLE001 - optional intelligence degrades
            self._count(
                "gasha_journey_evaluation_failures", event.tenant_id
            )
            return None
        if assessment is not None:
            self._count("gasha_journey_evaluations", event.tenant_id)
        return assessment

    def _count(
        self, name: str, tenant_id: str, **labels: str
    ) -> None:
        if self._metrics is None:
            return
        self._metrics.increment(
            name, labels={"tenant_id": tenant_id} | labels
        )
