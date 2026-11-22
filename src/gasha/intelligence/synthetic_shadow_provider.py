"""#145/#48: opt-in worker evaluator from bounded synthetic observations only.

The installed worker calls this evaluator with a normalized pending envelope.
Only a process-configured synthetic snapshot source can supply observation
history; neither transport JSON nor HTTP callers can submit an assessment,
a policy override, or a payment action. These records are NOT bank attestations.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from re import fullmatch
from typing import Protocol
from uuid import UUID

from gasha.domain.models import DecisionPolicy, IntelligenceSnapshot, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.shadow_copy import SHADOW_COPY_SCHEMA
from gasha.intelligence.feature_assessment_v1 import assess_synthetic_shadow_features
from gasha.intelligence.feature_set_v1 import ObservedTransfer
from gasha.intelligence.internal_graph import InternalGraphPolicy
from gasha.intelligence.redis_feature_history import RedisFeatureHistory
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
    beneficiary_window_complete: bool | None = None
    history_epoch_ref: str | None = None


class SyntheticHistorySource(Protocol):
    """Opt-in configured worker port; NEVER populated from untrusted JSON."""

    def snapshot_for(
        self, tenant_id: str, event_id: UUID
    ) -> SyntheticHistorySnapshotV1 | None: ...


class RedisSyntheticHistorySource:
    """Server-configured Redis-to-worker composition for synthetic SHADOW copies.

    Epoch, Redis client and graph policy come from the installer, not the
    inbound copy or an analyst endpoint. The worker recovers the normalized
    envelope from its existing pending ledger after a crash; no per-event
    in-memory fixture map or second alert writer is needed.
    """

    def __init__(
        self,
        history: RedisFeatureHistory,
        *,
        tenant_id: str,
        source_system: str,
        graph_policy: InternalGraphPolicy,
    ) -> None:
        if (
            type(history) is not RedisFeatureHistory
            or type(tenant_id) is not str
            or fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tenant_id) is None
            or type(source_system) is not str
            or fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", source_system) is None
            or type(graph_policy) is not InternalGraphPolicy
        ):
            raise ValueError("invalid server-configured synthetic Redis source")
        self._history = history
        self._tenant_id = tenant_id
        self._source_system = source_system
        self._graph_policy = graph_policy

    def snapshot_for_envelope(
        self, normalized: FraudEventEnvelope
    ) -> SyntheticHistorySnapshotV1:
        if (
            type(normalized) is not FraudEventEnvelope
            or normalized.tenant_id != self._tenant_id
            or normalized.operating_mode is not OperatingMode.SHADOW
            or normalized.adapter.adapter_type != "synthetic-shadow-copy"
            or normalized.adapter.schema_version != SHADOW_COPY_SCHEMA
            or normalized.adapter.source_system != self._source_system
            or normalized.intelligence != IntelligenceSnapshot()
            or normalized.signal_policy_versions
            or normalized.evidence_reason_codes
            or type(normalized.received_at) is not datetime
            or type(normalized.received_at.tzinfo) is not timezone
        ):
            raise ValueError("untrusted synthetic Redis evaluation envelope")
        tx = normalized.canonical_transaction
        if tx.tenant_id != normalized.tenant_id or tx.event_id != normalized.event_id:
            raise ValueError("synthetic Redis target identity mismatch")
        target = ObservedTransfer(
            tenant_id=normalized.tenant_id,
            event_id=str(normalized.event_id),
            account_ref=tx.sender_account_id,
            beneficiary_ref=tx.beneficiary_id or None,
            device_ref=tx.device_id,
            occurred_at=tx.occurred_at,
            available_at=normalized.received_at,
        )
        # A verified Redis epoch/seal gates evaluation before any PG writer.
        # If unavailable, IngestionWorker retries its existing durable pending
        # record; it must NOT substitute an empty or client-asserted snapshot.
        observations = self._history.observations_for(
            target, decision_as_of=normalized.received_at,
        )
        return SyntheticHistorySnapshotV1(
            tenant_id=normalized.tenant_id,
            event_id=normalized.event_id,
            source_system=self._source_system,
            receipt_cutoff=normalized.received_at,
            observations=observations,
            graph_policy=self._graph_policy,
            relationship_history_complete=False,
            beneficiary_window_complete=True,
            history_epoch_ref=self._history.epoch_fingerprint,
        )


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
        history_source: SyntheticHistorySource | RedisSyntheticHistorySource | None,
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
        if isinstance(self._history_source, RedisSyntheticHistorySource):
            snapshot = self._history_source.snapshot_for_envelope(normalized)
        else:
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
            or (snapshot.beneficiary_window_complete is not None
                and type(snapshot.beneficiary_window_complete) is not bool)
            or (snapshot.history_epoch_ref is not None
                and (type(snapshot.history_epoch_ref) is not str
                     or fullmatch(r"[0-9a-f]{64}", snapshot.history_epoch_ref) is None))
        ):
            raise ValueError("synthetic history source/clock mismatch")
        assessment = assess_synthetic_shadow_features(
            normalized,
            snapshot.observations,
            policy=snapshot.graph_policy,
            relationship_history_complete=snapshot.relationship_history_complete,
            beneficiary_window_complete=snapshot.beneficiary_window_complete,
            source_epoch_ref=snapshot.history_epoch_ref,
        )
        return self._orchestrator.evaluate(
            assessment.assessed_envelope,
            policy=policy,
            feature_assessment=assessment,
        )
