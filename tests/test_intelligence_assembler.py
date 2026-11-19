"""Server-side intelligence assembly tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.intelligence.assembler import (
    AssemblyPolicy,
    AssemblyRejected,
    HistoryFeatures,
    IntelligenceAssembler,
)
from gasha.intelligence.behavioral_session import (
    BehavioralSessionDetector,
    BehavioralSessionPolicy,
    BehavioralSessionSignals,
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
from gasha.intelligence.social_engineering import (
    SocialEngineeringDetector,
    SocialEngineeringPolicy,
)
from gasha.journey.detector import JourneyAssessment

AT = datetime(2026, 1, 5, 9, tzinfo=UTC)


def tx() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a",
        event_id=UUID(int=1),
        occurred_at=AT,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(5000),
        currency="ETB",
        sender_customer_id="customer-1",
        sender_account_id="account-1",
        beneficiary_id="beneficiary-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id="corr-1",
    )


PROVENANCE = SignalProvenance(
    source=IntelligenceSource.TENANT_NETWORK,
    scope=IntelligenceScope.TENANT_OBSERVED,
    observed_at=AT,
    source_version="fixture-v1",
)


class FixtureHistory:
    def __init__(self, features: HistoryFeatures | Exception) -> None:
        self._features = features

    def compute(self, transaction, *, decision_as_of):
        if isinstance(self._features, Exception):
            raise self._features
        return self._features


class FixtureGraph:
    def __init__(self, signals: InternalGraphSignals | None = None) -> None:
        self._signals = signals or InternalGraphSignals(provenance=PROVENANCE)

    def signals_for(self, transaction):
        return self._signals


class FixtureJourney:
    def __init__(self, assessment: JourneyAssessment | None) -> None:
        self._assessment = assessment

    def assess(self, transaction):
        return self._assessment


def assembler(
    *,
    history: HistoryFeatures | Exception | None = None,
    graph: InternalGraphSignals | None = None,
    journey: JourneyAssessment | None = None,
    include_journey: bool = False,
) -> IntelligenceAssembler:
    return IntelligenceAssembler(
        history=FixtureHistory(HistoryFeatures() if history is None else history),
        graph=FixtureGraph(graph),
        social_engineering=SocialEngineeringDetector(
            SocialEngineeringPolicy(policy_version="soc-v1")
        ),
        behavioral_session=BehavioralSessionDetector(
            BehavioralSessionPolicy(policy_version="beh-v1")
        ),
        internal_graph=InternalGraphDetector(
            InternalGraphPolicy(policy_version="graph-v1")
        ),
        assembly_policy=AssemblyPolicy(policy_version="assembly-v1"),
        source_version="assembly-src-v1",
        journey=FixtureJourney(journey) if include_journey else None,
    )


def test_clean_event_produces_zero_snapshot() -> None:
    result = assembler().assemble(tx())
    assert result.snapshot == IntelligenceSnapshot()
    assert "session_telemetry" in result.missing
    assert "journey_intelligence" in result.missing


def test_history_features_drive_social_and_velocity() -> None:
    result = assembler(
        history=HistoryFeatures(
            account_transfers_1h=5,
            beneficiary_unique_senders_1h=8,
            sender_beneficiary_prior_transfer_count=0,
            amount_to_sender_baseline_ratio=6.0,
        )
    ).assemble(tx())
    snap = result.snapshot
    assert snap.velocity_risk == pytest.approx(0.75)  # assembly policy
    assert snap.relationship_risk == pytest.approx(0.80)  # no prior relationship
    assert snap.beneficiary_risk == pytest.approx(0.86)  # unique senders
    assert snap.transaction_risk == pytest.approx(0.78)  # amount vs baseline
    assert "HIGH_ACCOUNT_VELOCITY_1H" in result.reason_codes
    assert "soc-v1" in result.signal_policy_versions


def test_graph_signals_drive_network_risk() -> None:
    result = assembler(
        graph=InternalGraphSignals(
            unique_senders_to_beneficiary_1h=7,
            confirmed_fraud_neighbors_30d=2,
            provenance=PROVENANCE,
        )
    ).assemble(tx())
    assert result.snapshot.network_risk == pytest.approx(0.94)
    assert "graph-v1" in result.signal_policy_versions


def test_session_telemetry_drives_device_session_risk() -> None:
    result = assembler().assemble(
        tx(),
        session=BehavioralSessionSignals(
            remote_access_indicator=True, provenance=PROVENANCE
        ),
    )
    assert result.snapshot.device_session_risk == pytest.approx(0.90)
    assert "session_telemetry" not in result.missing


def test_journey_port_contributes_when_present() -> None:
    journey = JourneyAssessment(
        tenant_id="tenant-a",
        customer_id="customer-1",
        as_of=AT,
        journey_risk=0.81,
        reason_codes=("JOURNEY_ANOMALY",),
        contributing_events=(),
        configuration_version="jcfg-v1",
        policy_version="jp-v1",
    )
    result = assembler(journey=journey, include_journey=True).assemble(tx())
    assert result.snapshot.journey_risk == pytest.approx(0.81)
    assert "JOURNEY_ANOMALY" in result.reason_codes
    assert "journey_intelligence" not in result.missing


def test_journey_none_is_degraded_not_suspicious() -> None:
    result = assembler(include_journey=True, journey=None).assemble(tx())
    assert result.snapshot.journey_risk == 0.0


def test_missing_history_recorded_not_fabricated() -> None:
    result = assembler(
        history=HistoryFeatures(missing=("amount_to_sender_baseline_ratio",))
    ).assemble(tx())
    # Every optional field absent → all names appear in the missing record.
    assert "account_transfers_1h" in result.missing
    assert "amount_to_sender_baseline_ratio" in result.missing
    assert result.snapshot.beneficiary_risk == 0.0


def test_bad_inputs_rejected() -> None:
    with pytest.raises(AssemblyRejected):
        assembler().assemble(object())  # type: ignore[arg-type]
    naive_tx = tx().model_copy(
        update={"occurred_at": datetime(2026, 1, 5, 9, tzinfo=UTC).replace(tzinfo=None)}
    )
    with pytest.raises(AssemblyRejected):
        assembler().assemble(tx(), decision_as_of=naive_tx.occurred_at)


def test_untyped_history_result_rejected() -> None:
    class WrongType:
        def compute(self, transaction, *, decision_as_of):
            return {"not": "typed"}

    service = IntelligenceAssembler(
        history=WrongType(),  # type: ignore[arg-type]
        graph=FixtureGraph(),
        social_engineering=SocialEngineeringDetector(
            SocialEngineeringPolicy(policy_version="soc-v1")
        ),
        behavioral_session=BehavioralSessionDetector(
            BehavioralSessionPolicy(policy_version="beh-v1")
        ),
        internal_graph=InternalGraphDetector(
            InternalGraphPolicy(policy_version="graph-v1")
        ),
        assembly_policy=AssemblyPolicy(policy_version="assembly-v1"),
        source_version="src-v1",
    )
    with pytest.raises(AssemblyRejected, match="typed history"):
        service.assemble(tx())
