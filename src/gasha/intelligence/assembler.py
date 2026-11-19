"""Default-off offline intelligence assembly; only verified original-decision inputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from json import dumps
from typing import Protocol

from pydantic import BaseModel, Field

from gasha.domain.models import CanonicalTransaction, IntelligenceSnapshot, RiskScore
from gasha.intelligence.assembly_lineage import (
    AssemblyAuthority,
    OriginalDecisionContext,
    ProviderEvidence,
    context_identity,
    context_matches,
    verified,
)
from gasha.intelligence.behavioral_session import (
    BehavioralSessionAssessment,
    BehavioralSessionDetector,
    BehavioralSessionSignals,
)
from gasha.intelligence.internal_graph import (
    InternalGraphAssessment,
    InternalGraphDetector,
    InternalGraphSignals,
)
from gasha.intelligence.provenance import (
    IntelligenceEvidence,
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)
from gasha.intelligence.social_engineering import (
    SocialEngineeringAssessment,
    SocialEngineeringDetector,
    SocialEngineeringSignals,
)
from gasha.journey.detector import JourneyAssessment


class AssemblyRejected(ValueError):
    """No authenticated original-decision authority or invalid event context."""


@dataclass(frozen=True, slots=True)
class HistoryFeatures:
    account_transfers_1h: int | None = None
    beneficiary_unique_senders_1h: int | None = None
    beneficiary_incoming_count_1h: int | None = None
    sender_beneficiary_prior_transfer_count: int | None = None
    amount_to_sender_baseline_ratio: float | None = None
    device_seen_for_sender_before: bool | None = None
    beneficiary_confirmed_fraud_sender_count: int | None = None
    missing: tuple[str, ...] = ()


class HistoryFeatureProvider(Protocol):
    def compute(
        self, transaction: CanonicalTransaction, *,
        decision_as_of: datetime, decision_context: OriginalDecisionContext
    ) -> ProviderEvidence | None: ...


class GraphSignalProvider(Protocol):
    def signals_for(
        self, transaction: CanonicalTransaction, *,
        decision_as_of: datetime, decision_context: OriginalDecisionContext
    ) -> ProviderEvidence | None: ...


class JourneySignalProvider(Protocol):
    def assess(
        self, transaction: CanonicalTransaction, *,
        decision_as_of: datetime, decision_context: OriginalDecisionContext
    ) -> ProviderEvidence | None: ...


class AssemblyPolicy(BaseModel):
    policy_version: str = Field(min_length=1)
    velocity_1h_threshold: int = Field(default=3, ge=1)
    velocity_risk: RiskScore = 0.75


@dataclass(frozen=True, slots=True)
class AssembledIntelligence:
    snapshot: IntelligenceSnapshot
    reason_codes: tuple[str, ...]
    evidence: tuple[IntelligenceEvidence, ...]
    missing: tuple[str, ...]
    signal_policy_versions: tuple[str, ...]
    decision_id: str
    original_context_digest: str
    provider_digests: tuple[tuple[str, str], ...]
    snapshot_digest: str


class IntelligenceAssembler:
    """Requires independently authenticated decision and provider issuance.

    A later replay of the same original context remains tied to its original
    received_at. Outages or unattested inputs are explicitly unavailable and
    contribute no risk. No raw, unverified session/provider API is supported.
    """

    def __init__(
        self, *, history: HistoryFeatureProvider, graph: GraphSignalProvider,
        authority: AssemblyAuthority, social_engineering: SocialEngineeringDetector,
        behavioral_session: BehavioralSessionDetector,
        internal_graph: InternalGraphDetector, assembly_policy: AssemblyPolicy,
        source_version: str, journey: JourneySignalProvider | None = None,
    ) -> None:
        if type(assembly_policy) is not AssemblyPolicy or not source_version:
            raise AssemblyRejected("typed versioned assembly policy required")
        self._history = history
        self._graph = graph
        self._authority = authority
        self._social = social_engineering
        self._behavioral = behavioral_session
        self._graph_detector = internal_graph
        self._policy = assembly_policy
        self._source_version = source_version
        self._journey = journey

    def _fetch(
        self, provider: object, method: str, transaction: CanonicalTransaction,
        context: OriginalDecisionContext, source: str, payload_type: type,
    ) -> ProviderEvidence | None:
        try:
            response = getattr(provider, method)(
                transaction, decision_as_of=context.cutoff, decision_context=context
            )
            if verified(response, source, payload_type, context, self._authority):
                assert isinstance(response, ProviderEvidence)
                return response
        except Exception:  # noqa: BLE001
            # A failed optional provider is explicitly unavailable, never zero-risk evidence.
            return None
        return None

    @staticmethod
    def _provenance(
        envelope: ProviderEvidence, source: IntelligenceSource
    ) -> SignalProvenance:
        return SignalProvenance(
            source=source, scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=envelope.observed_at, source_version=envelope.source_version
        )

    @staticmethod
    def _provenance_matches(
        actual: SignalProvenance, envelope: ProviderEvidence, source: IntelligenceSource
    ) -> bool:
        return (
            actual.source == source
            and actual.scope == IntelligenceScope.TENANT_OBSERVED
            and actual.source_version == envelope.source_version
            and actual.observed_at == envelope.observed_at
        )

    def assemble(
        self, transaction: CanonicalTransaction, *,
        decision_context: OriginalDecisionContext,
        session: ProviderEvidence | None = None,
    ) -> AssembledIntelligence:
        if type(transaction) is not CanonicalTransaction:
            raise AssemblyRejected("typed canonical transaction required")
        if not context_matches(
            decision_context, transaction.tenant_id, transaction.event_id,
            transaction.occurred_at
        ):
            raise AssemblyRejected("original-decision identity/clock mismatch")
        try:
            if self._authority.verify_context(decision_context) is not True:
                raise AssemblyRejected("untrusted original-decision issuance")
        except AssemblyRejected:
            raise
        except Exception as exc:
            raise AssemblyRejected("unavailable original-decision authority") from exc

        context = decision_context
        history = self._fetch(self._history, "compute", transaction, context,
                              "history", HistoryFeatures)
        graph = self._fetch(self._graph, "signals_for", transaction, context,
                            "graph", InternalGraphSignals)
        journey = (
            self._fetch(self._journey, "assess", transaction, context,
                        "journey", JourneyAssessment)
            if self._journey is not None else None
        )
        if journey is not None:
            assessment = journey.payload
            assert isinstance(assessment, JourneyAssessment)
            if (
                assessment.tenant_id != transaction.tenant_id
                or assessment.customer_id != transaction.sender_customer_id
                or assessment.as_of != context.cutoff
                or any(
                    event.occurred_at.tzinfo is None
                    or event.occurred_at.utcoffset() is None
                    or event.occurred_at > context.cutoff
                    for event in assessment.contributing_events
                )
            ):
                journey = None
        if graph is not None:
            signals = graph.payload
            assert isinstance(signals, InternalGraphSignals)
            if not self._provenance_matches(
                signals.provenance, graph, IntelligenceSource.TENANT_NETWORK
            ):
                graph = None

        if session is not None and not verified(
            session, "session", BehavioralSessionSignals, context, self._authority
        ):
            session = None
        if session is not None:
            telemetry = session.payload
            assert isinstance(telemetry, BehavioralSessionSignals)
            if not self._provenance_matches(
                telemetry.provenance, session, IntelligenceSource.TENANT_BEHAVIORAL
            ):
                session = None

        components: dict[str, float] = {
            key: 0.0 for key in IntelligenceSnapshot.model_fields
        }
        reasons: list[str] = []
        evidence: list[IntelligenceEvidence] = []
        versions = [self._policy.policy_version]
        missing: list[str] = []
        accepted: list[tuple[str, str]] = []

        def consume(
            name: str,
            result: SocialEngineeringAssessment | InternalGraphAssessment | BehavioralSessionAssessment,
            envelope: ProviderEvidence,
        ) -> None:
            for key in IntelligenceSnapshot.model_fields:
                components[key] = max(
                    components[key], getattr(result.intelligence, key)
                )
            reasons.extend(result.reason_codes)
            evidence.extend(result.evidence)
            versions.append(result.signal_policy_version)
            accepted.append((name, envelope.payload_digest))

        if history is None:
            missing.append("history_features")
        else:
            features = history.payload
            assert isinstance(features, HistoryFeatures)
            accepted.append(("history", history.payload_digest))
            missing.extend(features.missing)
            for name in (
                "account_transfers_1h", "beneficiary_unique_senders_1h",
                "beneficiary_incoming_count_1h",
                "sender_beneficiary_prior_transfer_count",
                "amount_to_sender_baseline_ratio",
                "device_seen_for_sender_before",
                "beneficiary_confirmed_fraud_sender_count",
            ):
                if getattr(features, name) is None:
                    missing.append(name)
            social = self._social.assess(
                transaction,
                SocialEngineeringSignals(
                    beneficiary_is_new_to_sender=(
                        features.sender_beneficiary_prior_transfer_count == 0
                    ),
                    amount_to_sender_baseline_ratio=(
                        features.amount_to_sender_baseline_ratio
                        if features.amount_to_sender_baseline_ratio is not None else 0.0
                    ),
                    sender_beneficiary_prior_transfer_count=(
                        features.sender_beneficiary_prior_transfer_count or 0
                    ),
                    beneficiary_unique_senders_1h=(
                        features.beneficiary_unique_senders_1h or 0
                    ),
                    beneficiary_incoming_count_1h=(
                        features.beneficiary_incoming_count_1h or 0
                    ),
                    beneficiary_confirmed_fraud_sender_count=(
                        features.beneficiary_confirmed_fraud_sender_count or 0
                    ),
                    device_is_new_to_sender=(
                        not features.device_seen_for_sender_before
                        if features.device_seen_for_sender_before is not None else None
                    ),
                    provenance=self._provenance(
                        history, IntelligenceSource.TENANT_BENEFICIARY
                    ),
                ),
            )
            consume("social", social, history)
            if (
                features.account_transfers_1h is not None
                and features.account_transfers_1h >= self._policy.velocity_1h_threshold
            ):
                components["velocity_risk"] = max(
                    components["velocity_risk"], self._policy.velocity_risk
                )
                reasons.append("HIGH_ACCOUNT_VELOCITY_1H")
                evidence.append(IntelligenceEvidence(
                    reason_code="HIGH_ACCOUNT_VELOCITY_1H",
                    provenance=self._provenance(
                        history, IntelligenceSource.TENANT_TRANSACTION
                    ),
                ))

        if graph is None:
            missing.append("graph_intelligence")
        else:
            signals = graph.payload
            assert isinstance(signals, InternalGraphSignals)
            consume("graph", self._graph_detector.assess(signals), graph)

        if session is None:
            missing.append("session_telemetry")
        else:
            telemetry = session.payload
            assert isinstance(telemetry, BehavioralSessionSignals)
            consume("session", self._behavioral.assess(telemetry), session)

        if journey is None:
            missing.append("journey_intelligence")
        else:
            assessment = journey.payload
            assert isinstance(assessment, JourneyAssessment)
            components["journey_risk"] = max(
                components["journey_risk"], assessment.journey_risk
            )
            reasons.extend(assessment.reason_codes)
            versions.append(assessment.policy_version)
            accepted.append(("journey", journey.payload_digest))

        snapshot = IntelligenceSnapshot(**components)
        unique_reasons = tuple(dict.fromkeys(reasons))
        unique_missing = tuple(dict.fromkeys(missing))
        unique_versions = tuple(dict.fromkeys(versions))
        context_hash = sha256(context_identity(context)).hexdigest()
        fingerprint = sha256(dumps(
            {
                "context": context_hash,
                "snapshot": snapshot.model_dump(mode="json"),
                "reasons": unique_reasons,
                "evidence": [item.model_dump(mode="json") for item in evidence],
                "missing": unique_missing,
                "policy_versions": unique_versions,
                "providers": accepted,
                "assembly_version": self._source_version,
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        return AssembledIntelligence(
            snapshot=snapshot, reason_codes=unique_reasons,
            evidence=tuple(evidence), missing=unique_missing,
            signal_policy_versions=unique_versions, decision_id=context.decision_id,
            original_context_digest=context_hash,
            provider_digests=tuple(accepted), snapshot_digest=fingerprint,
        )
