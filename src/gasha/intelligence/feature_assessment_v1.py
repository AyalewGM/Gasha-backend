"""Synthetic-only point-in-time graph assessment contract for #145/#48.

This is a pure, opt-in assessment after trusted *synthetic* normalization.
It carries verifiable opaque lineage in memory; it does not attest a Bank
clock, install a model, persist lineage, or authorize payment enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from re import fullmatch
from uuid import UUID

from gasha.domain.models import IntelligenceSnapshot, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.shadow_copy import SHADOW_COPY_SCHEMA
from gasha.intelligence.feature_set_v1 import (
    FeatureSetV1,
    ObservedTransfer,
    compute_feature_set,
)
from gasha.intelligence.internal_graph import (
    InternalGraphDetector,
    InternalGraphPolicy,
    InternalGraphSignals,
)
from gasha.intelligence.provenance import (
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)

ASSESSMENT_VERSION = "gasha-synthetic-feature-assessment-v1"


def _digest(value: object) -> str:
    return sha256(dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _observation_identity(item: ObservedTransfer) -> tuple[str, ...]:
    # Only the digest leaves this function; never expose the raw pseudonyms.
    return (
        item.tenant_id, item.event_id, item.account_ref,
        item.beneficiary_ref or "", item.device_ref or "",
        item.occurred_at.isoformat(), item.available_at.isoformat(),
    )


@dataclass(frozen=True, slots=True)
class FeatureAssessmentV1:
    """An in-memory bounded assessment, not a trusted persisted evidence record."""

    version: str
    tenant_id: str
    event_id: UUID
    decision_as_of: datetime
    feature_set: FeatureSetV1
    source_fingerprint: str
    computation_fingerprint: str
    eligible_observations: int
    late_observations: int
    nonprior_observations: int
    unavailable_signals: tuple[str, ...]
    assessed_envelope: FraudEventEnvelope


def assess_synthetic_shadow_features(
    normalized: FraudEventEnvelope,
    observations: tuple[ObservedTransfer, ...],
    *,
    policy: InternalGraphPolicy,
    relationship_history_complete: bool = True,
    beneficiary_window_complete: bool | None = None,
) -> FeatureAssessmentV1:
    """Assess a normalized synthetic copy using only receipt-available history.

    The trusted synthetic adapter, not a transport payload, supplies mode and
    zeroed intelligence. This bounded provider rejects pre-assessed envelopes,
    foreign observations, clock/identity mismatches, and malformed inputs.
    """
    if (
        type(normalized) is not FraudEventEnvelope
        or type(observations) is not tuple
        or type(policy) is not InternalGraphPolicy
    ):
        raise ValueError("invalid synthetic assessment inputs")
    # Bounded one-hour coverage can prove a beneficiary fan-in count while
    # still being insufficient to prove a first-ever sender relationship.
    # Only a configured synthetic producer may assert this coverage. The
    # Redis adapter's seal is NOT independently attested Bank provenance.
    if beneficiary_window_complete is None:
        beneficiary_window_complete = relationship_history_complete
    if (
        type(relationship_history_complete) is not bool
        or type(beneficiary_window_complete) is not bool
        or (relationship_history_complete and not beneficiary_window_complete)
    ):
        raise ValueError("invalid synthetic feature coverage claims")
    tx = normalized.canonical_transaction
    cutoff = normalized.received_at
    if (
        normalized.operating_mode is not OperatingMode.SHADOW
        or normalized.adapter.adapter_type != "synthetic-shadow-copy"
        or normalized.adapter.schema_version != SHADOW_COPY_SCHEMA
        or type(normalized.adapter.source_system) is not str
        or fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", normalized.adapter.source_system) is None
        or tx.tenant_id != normalized.tenant_id
        or tx.event_id != normalized.event_id
        or normalized.intelligence != IntelligenceSnapshot()
        or normalized.signal_policy_versions
        or normalized.evidence_reason_codes
        or type(cutoff) is not datetime
        or type(cutoff.tzinfo) is not timezone
    ):
        raise ValueError("untrusted synthetic assessment envelope")
    decision_as_of = cutoff.astimezone(UTC)
    target = ObservedTransfer(
        normalized.tenant_id,
        str(normalized.event_id),
        tx.sender_account_id,
        tx.beneficiary_id or None,
        tx.device_id,
        tx.occurred_at,
        cutoff,
    )
    # Check every row even if it is excluded from the decision. Cross-tenant
    # late rows must not silently disappear during feature selection.
    for item in observations:
        if type(item) is not ObservedTransfer or item.tenant_id != normalized.tenant_id:
            raise ValueError("untrusted synthetic history scope")
    features = compute_feature_set(
        target, observations, decision_as_of=decision_as_of,
        relationship_history_complete=relationship_history_complete,
    )
    # Incomplete source coverage cannot establish a measured graph zero (or
    # an authoritative fan-in count). Keep the core feature engine reusable;
    # this synthetic assessment conservatively marks its graph signal absent.
    if not beneficiary_window_complete and target.beneficiary_ref is not None:
        features = replace(
            features,
            beneficiary_unique_senders_1h=None,
            missing=tuple(sorted({*features.missing, "beneficiary_unique_senders_1h"})),
            computation_fingerprint=_digest([
                ASSESSMENT_VERSION, features.computation_fingerprint,
                "beneficiary_history_incomplete",
            ]),
        )
    late = sum(
        item.occurred_at < target.occurred_at and item.available_at > decision_as_of
        for item in observations
    )
    nonprior = sum(item.occurred_at >= target.occurred_at for item in observations)
    eligible = sum(
        item.occurred_at < target.occurred_at and item.available_at <= decision_as_of
        for item in observations
    )
    unavailable = list(features.missing)
    reasons: tuple[str, ...]
    if features.beneficiary_unique_senders_1h is None:
        # Never turn missing beneficiary telemetry into a measured zero-risk signal.
        if "beneficiary_unique_senders_1h" not in unavailable:
            unavailable.append("beneficiary_unique_senders_1h")
        assessment_intelligence = IntelligenceSnapshot()
        reasons = ("UNAVAILABLE_BENEFICIARY_FAN_IN",)
    else:
        graph = InternalGraphDetector(policy).assess(
            InternalGraphSignals(
                unique_senders_to_beneficiary_1h=features.beneficiary_unique_senders_1h,
                provenance=SignalProvenance(
                    source=IntelligenceSource.TENANT_NETWORK,
                    scope=IntelligenceScope.TENANT_OBSERVED,
                    observed_at=tx.occurred_at,
                    source_version=features.version,
                ),
            )
        )
        assessment_intelligence = graph.intelligence
        reasons = tuple(graph.reason_codes)
    missing = tuple(sorted(unavailable))
    # Bind not just the eligible cohort, but the bounded input/availability
    # snapshot, including late and nonprior observations. Identical numeric
    # features from different snapshots must not share an assessment identity.
    source = _digest([
        ASSESSMENT_VERSION, normalized.tenant_id, str(normalized.event_id),
        decision_as_of.isoformat(), normalized.adapter.adapter_type,
        normalized.adapter.adapter_version, normalized.adapter.schema_version,
        normalized.adapter.source_system,
        features.source_fingerprint,
        sorted(_observation_identity(item) for item in observations),
    ])
    computation = _digest([
        ASSESSMENT_VERSION, source, features.computation_fingerprint,
        policy.model_dump(mode="json"), assessment_intelligence.model_dump(mode="json"),
        reasons, missing, eligible, late, nonprior,
        relationship_history_complete,
        *((("bounded_beneficiary_window_complete",) if (
            beneficiary_window_complete and not relationship_history_complete
        ) else ())),
    ])
    # Risk is computed by Gasha; the synthetic JSON adapter cannot supply it.
    assessed = normalized.model_copy(update={
        "intelligence": assessment_intelligence,
        "evidence_reason_codes": reasons,
        "signal_policy_versions": (policy.policy_version,),
    })
    return FeatureAssessmentV1(
        version=ASSESSMENT_VERSION,
        tenant_id=normalized.tenant_id,
        event_id=normalized.event_id,
        decision_as_of=decision_as_of,
        feature_set=features,
        source_fingerprint=source,
        computation_fingerprint=computation,
        eligible_observations=eligible,
        late_observations=late,
        nonprior_observations=nonprior,
        unavailable_signals=missing,
        assessed_envelope=assessed,
    )
