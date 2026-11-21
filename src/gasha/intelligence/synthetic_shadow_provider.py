"""#145/#48: opt-in worker evaluator from bounded synthetic observations only.

The installed worker calls this evaluator with a normalized pending envelope.
Only a process-configured synthetic snapshot source can supply observation
history; neither transport JSON nor HTTP callers can submit an assessment,
a policy override, or a payment action. These records are NOT bank attestations.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from gasha.domain.models import DecisionPolicy
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.intelligence.feature_assessment_v1 import assess_synthetic_shadow_features
from gasha.intelligence.feature_set_v1 import ObservedTransfer
from gasha.intelligence.internal_graph import InternalGraphPolicy
from gasha.orchestration import ShadowOrchestrator


@dataclass(frozen=True, slots=True)
class SyntheticHistorySnapshotV1:
    """Trusted-in-process fixture only; raw observations are never persisted."""

    tenant_id: str
    event_id: UUID
    source_system: str
    receipt_cutoff: datetime
    observations: tuple[ObservedTransfer, ...]
    graph_policy: InternalGraphPolicy
    relationship_history_complete: bool


class SyntheticHistorySource(Protocol):
    """Opt-in configured worker port; NEVER populated from untrusted JSON."""

    def snapshot_for(
        self, tenant_id: str, event_id: UUID
    ) -> SyntheticHistorySnapshotV1 | None: ...


class SyntheticShadowWorkerEvaluator:
    """Callable composed into IngestionWorker's normal pending-evaluate seam.

    Missing or altered snapshots throw before any evaluation, alert, case or
    audit write. The existing worker retains its retry/terminal-DLQ policy.
    This port is deliberately not a general or Bank-signed feature provider.
    """

    def __init__(
        self,
        orchestrator: ShadowOrchestrator,
        *,
        history_source: SyntheticHistorySource | None,
    ) -> None:
        self._orchestrator = orchestrator
        self._history_source = history_source

    def __call__(
        self,
        normalized: FraudEventEnvelope,
        policy: DecisionPolicy | None = None,
    ) -> object:
        if (
            type(normalized) is not FraudEventEnvelope
            or self._history_source is None
        ):
            raise ValueError("trusted synthetic history provider unavailable")
        snapshot = self._history_source.snapshot_for(
            normalized.tenant_id, normalized.event_id
        )
        if type(snapshot) is not SyntheticHistorySnapshotV1:
            raise ValueError("trusted synthetic history snapshot unavailable")
        received = normalized.received_at
        if (
            snapshot.tenant_id != normalized.tenant_id
            or snapshot.event_id != normalized.event_id
            or snapshot.source_system != normalized.adapter.source_system
            or type(received) is not datetime
            or type(received.tzinfo) is not timezone
            or type(snapshot.receipt_cutoff) is not datetime
            or type(snapshot.receipt_cutoff.tzinfo) is not timezone
            or snapshot.receipt_cutoff != received
            or type(snapshot.observations) is not tuple
            or type(snapshot.graph_policy) is not InternalGraphPolicy
            or type(snapshot.relationship_history_complete) is not bool
        ):
            raise ValueError("synthetic history source/clock mismatch")
        assessment = assess_synthetic_shadow_features(
            normalized,
            snapshot.observations,
            policy=snapshot.graph_policy,
            relationship_history_complete=snapshot.relationship_history_complete,
        )
        return self._orchestrator.evaluate(
            assessment.assessed_envelope,
            policy=policy,
            feature_assessment=assessment,
        )
