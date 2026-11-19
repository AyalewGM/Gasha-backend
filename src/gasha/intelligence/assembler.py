"""Server-side intelligence assembly: history + detectors → signal snapshot.

``IntelligenceAssembler`` is the reference implementation of the serving-time
feature path the synthetic API defers (``DecisionRequest``'s "temporary M1
request shape until intelligence assembly is server-side"). It consumes the
same contracts the protected API expects: point-in-time history features,
tenant graph signals, optional channel session telemetry and the journey
enrichment port, then fuses the versioned detectors' partial snapshots into
one ``IntelligenceSnapshot``.

Unavailable data is recorded in ``missing`` and contributes nothing — absent
history, absent session telemetry or absent journey configuration never raise
risk and never fabricate evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel, Field

from gasha.domain.models import (
    CanonicalTransaction,
    IntelligenceSnapshot,
    RiskScore,
)
from gasha.intelligence.behavioral_session import (
    BehavioralSessionDetector,
    BehavioralSessionSignals,
)
from gasha.intelligence.internal_graph import (
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
    SocialEngineeringDetector,
    SocialEngineeringSignals,
)
from gasha.journey.provider import JourneyIntelligence

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class AssemblyRejected(ValueError):
    """The assembler's providers, policy or inputs are untrustworthy."""


@dataclass(frozen=True, slots=True)
class HistoryFeatures:
    """Point-in-time history features the snapshot derives from.

    ``None`` means the feature could not be computed for this event —
    unavailable, not zero. ``missing`` names the fields the provider could
    not establish so callers can audit degraded assembly.
    """

    account_transfers_1h: int | None = None
    beneficiary_unique_senders_1h: int | None = None
    beneficiary_incoming_count_1h: int | None = None
    sender_beneficiary_prior_transfer_count: int | None = None
    amount_to_sender_baseline_ratio: float | None = None
    device_seen_for_sender_before: bool | None = None
    beneficiary_confirmed_fraud_sender_count: int | None = None
    missing: tuple[str, ...] = ()


class HistoryFeatureProvider(Protocol):
    """Point-in-time history features; point-in-time discipline is the
    provider's contract (``RedisFeatureHistory`` enforces it upstream)."""

    def compute(
        self,
        transaction: CanonicalTransaction,
        *,
        decision_as_of: datetime,
    ) -> HistoryFeatures: ...


class GraphSignalProvider(Protocol):
    """Tenant graph aggregates for the scored event (strictly prior history)."""

    def signals_for(
        self, transaction: CanonicalTransaction
    ) -> InternalGraphSignals: ...


class AssemblyPolicy(BaseModel):
    """Versioned policy for the assembly-owned velocity contribution."""

    policy_version: str = Field(min_length=1)
    velocity_1h_threshold: int = Field(default=3, ge=1)
    velocity_risk: RiskScore = 0.75


@dataclass(frozen=True, slots=True)
class AssembledIntelligence:
    """The fused snapshot plus its provenance and degradation record."""

    snapshot: IntelligenceSnapshot
    reason_codes: tuple[str, ...]
    evidence: tuple[IntelligenceEvidence, ...]
    missing: tuple[str, ...]
    signal_policy_versions: tuple[str, ...]


class IntelligenceAssembler:
    """Fuses history features, graph signals, telemetry and journey context."""

    def __init__(
        self,
        *,
        history: HistoryFeatureProvider,
        graph: GraphSignalProvider,
        social_engineering: SocialEngineeringDetector,
        behavioral_session: BehavioralSessionDetector,
        internal_graph: InternalGraphDetector,
        assembly_policy: AssemblyPolicy,
        source_version: str,
        journey: JourneyIntelligence | None = None,
    ) -> None:
        if type(assembly_policy) is not AssemblyPolicy:
            raise AssemblyRejected("typed assembly policy required")
        if _TAG.fullmatch(source_version) is None:
            raise AssemblyRejected("source_version must be a tag-safe identifier")
        self._history = history
        self._graph = graph
        self._social = social_engineering
        self._behavioral = behavioral_session
        self._graph_detector = internal_graph
        self._policy = assembly_policy
        self._source_version = source_version
        self._journey = journey

    def _provenance(self, source: IntelligenceSource, as_of: datetime) -> SignalProvenance:
        return SignalProvenance(
            source=source,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=as_of,
            source_version=self._source_version,
        )

    def assemble(
        self,
        transaction: CanonicalTransaction,
        *,
        session: BehavioralSessionSignals | None = None,
        decision_as_of: datetime | None = None,
    ) -> AssembledIntelligence:
        """Fuses all providers into one snapshot for ``transaction``.

        ``decision_as_of`` defaults to the transaction's ``occurred_at`` —
        the only correct real-time semantics: nothing after the event may
        contribute to its own assessment.
        """
        if type(transaction) is not CanonicalTransaction:
            raise AssemblyRejected("typed canonical transaction required")
        as_of = (
            decision_as_of
            if decision_as_of is not None
            else transaction.occurred_at
        )
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise AssemblyRejected("decision_as_of must be timezone-aware")
        as_of = as_of.astimezone(UTC)

        history = self._history.compute(transaction, decision_as_of=as_of)
        if type(history) is not HistoryFeatures:
            raise AssemblyRejected("typed history features required")

        missing = list(history.missing)
        for name in (
            "account_transfers_1h",
            "beneficiary_unique_senders_1h",
            "beneficiary_incoming_count_1h",
            "sender_beneficiary_prior_transfer_count",
            "amount_to_sender_baseline_ratio",
            "device_seen_for_sender_before",
            "beneficiary_confirmed_fraud_sender_count",
        ):
            if getattr(history, name) is None and name not in missing:
                missing.append(name)

        social = self._social.assess(
            transaction,
            SocialEngineeringSignals(
                beneficiary_is_new_to_sender=(
                    history.sender_beneficiary_prior_transfer_count == 0
                ),
                amount_to_sender_baseline_ratio=(
                    history.amount_to_sender_baseline_ratio
                    if history.amount_to_sender_baseline_ratio is not None
                    else 1.0
                ),
                sender_beneficiary_prior_transfer_count=(
                    history.sender_beneficiary_prior_transfer_count or 0
                ),
                beneficiary_unique_senders_1h=(
                    history.beneficiary_unique_senders_1h or 0
                ),
                beneficiary_incoming_count_1h=(
                    history.beneficiary_incoming_count_1h or 0
                ),
                beneficiary_confirmed_fraud_sender_count=(
                    history.beneficiary_confirmed_fraud_sender_count or 0
                ),
                device_is_new_to_sender=(
                    not history.device_seen_for_sender_before
                    if history.device_seen_for_sender_before is not None
                    else None
                ),
                provenance=self._provenance(
                    IntelligenceSource.TENANT_BENEFICIARY, as_of
                ),
            )
        )
        graph_assessment = self._graph_detector.assess(
            self._graph.signals_for(transaction)
        )
        behavioral = (
            self._behavioral.assess(session)
            if session is not None
            else None
        )

        components: dict[str, float] = {
            name: 0.0 for name in IntelligenceSnapshot.model_fields
        }
        reasons: list[str] = []
        evidence: list[IntelligenceEvidence] = []
        policy_versions = [self._policy.policy_version]

        for assessment in (social, graph_assessment, behavioral):
            if assessment is None:
                continue
            for name in IntelligenceSnapshot.model_fields:
                components[name] = max(
                    components[name], getattr(assessment.intelligence, name)
                )
            reasons.extend(assessment.reason_codes)
            evidence.extend(assessment.evidence)
            policy_versions.append(assessment.signal_policy_version)

        if (
            history.account_transfers_1h is not None
            and history.account_transfers_1h
            >= self._policy.velocity_1h_threshold
        ):
            components["velocity_risk"] = max(
                components["velocity_risk"], self._policy.velocity_risk
            )
            reasons.append("HIGH_ACCOUNT_VELOCITY_1H")

        if self._journey is not None:
            journey = self._journey.assess(transaction)
            if journey is not None:
                components["journey_risk"] = max(
                    components["journey_risk"], journey.journey_risk
                )
                reasons.extend(journey.reason_codes)
                policy_versions.append(journey.policy_version)

        if session is None:
            missing.append("session_telemetry")
        if self._journey is None:
            missing.append("journey_intelligence")

        return AssembledIntelligence(
            snapshot=IntelligenceSnapshot(**components),
            reason_codes=tuple(dict.fromkeys(reasons)),
            evidence=tuple(evidence),
            missing=tuple(missing),
            signal_policy_versions=tuple(dict.fromkeys(policy_versions)),
        )
