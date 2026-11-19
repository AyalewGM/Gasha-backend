"""Offline point-in-time attested assembly negative controls (synthetic only)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hmac import new
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
from gasha.intelligence.assembly_lineage import (
    OriginalDecisionContext,
    ProviderEvidence,
    context_identity,
    evidence_identity,
    payload_digest,
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
RECEIVED = AT + timedelta(seconds=20)
KEY = b"synthetic-only-unit-test-issuer-key"


def tx() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="tenant-a", event_id=UUID(int=1), occurred_at=AT,
        channel="mobile", transaction_type="transfer", amount=Decimal(5000),
        currency="ETB", sender_customer_id="customer-1",
        sender_account_id="account-1", beneficiary_id="beneficiary-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank", correlation_id="corr-1",
    )


def mac(value: bytes) -> str:
    return new(KEY, value, "sha256").hexdigest()


def context() -> OriginalDecisionContext:
    unsigned = OriginalDecisionContext(
        tenant_id="tenant-a", event_id=UUID(int=1),
        decision_id="original-1", occurred_at=AT, received_at=RECEIVED,
        dataset_epoch="epoch-1", dataset_seal="seal-1", attestation="x" * 64,
    )
    return replace(unsigned, attestation=mac(context_identity(unsigned)))


class Authority:
    def verify_context(self, ctx: OriginalDecisionContext) -> bool:
        from hmac import compare_digest
        return compare_digest(mac(context_identity(ctx)), ctx.attestation)

    def verify_evidence(
        self, item: ProviderEvidence, ctx: OriginalDecisionContext
    ) -> bool:
        from hmac import compare_digest
        return compare_digest(mac(evidence_identity(item)), item.attestation)


AUTH = Authority()


def issued(
    source: str, payload: object, *, ctx: OriginalDecisionContext | None = None,
    available: datetime | None = None, observed: datetime | None = None,
) -> ProviderEvidence:
    ctx = context() if ctx is None else ctx
    raw = ProviderEvidence(
        source=source, source_version="fixture-v1", tenant_id=ctx.tenant_id,
        event_id=ctx.event_id, decision_id=ctx.decision_id,
        dataset_epoch=ctx.dataset_epoch, dataset_seal=ctx.dataset_seal,
        as_of=ctx.cutoff, observed_at=observed or AT,
        available_at=available or ctx.cutoff, payload_digest=payload_digest(payload),
        attestation="x" * 64, payload=payload,
    )
    return replace(raw, attestation=mac(evidence_identity(raw)))


def graph_signals(*, risk: bool = False) -> InternalGraphSignals:
    return InternalGraphSignals(
        confirmed_fraud_neighbors_30d=2 if risk else 0,
        provenance=SignalProvenance(
            source=IntelligenceSource.TENANT_NETWORK,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=AT, source_version="fixture-v1",
        ),
    )


def session_signals() -> BehavioralSessionSignals:
    return BehavioralSessionSignals(
        remote_access_indicator=True,
        provenance=SignalProvenance(
            source=IntelligenceSource.TENANT_BEHAVIORAL,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=AT, source_version="fixture-v1",
        ),
    )


class Provider:
    def __init__(self, response: ProviderEvidence | None) -> None:
        self.response = response
        self.received: list[datetime] = []

    def compute(self, transaction, *, decision_as_of, decision_context):
        self.received.append(decision_as_of)
        return self.response

    def signals_for(self, transaction, *, decision_as_of, decision_context):
        self.received.append(decision_as_of)
        return self.response

    def assess(self, transaction, *, decision_as_of, decision_context):
        self.received.append(decision_as_of)
        return self.response


def assembler(
    history: ProviderEvidence | None = None,
    graph: ProviderEvidence | None = None,
    journey: ProviderEvidence | None = None,
    include_journey: bool = False,
    baseline_ratio_threshold: float = 4.0,
    authority: Authority | None = None,
) -> tuple[IntelligenceAssembler, Provider, Provider, Provider]:
    h = Provider(history)
    g = Provider(graph)
    j = Provider(journey)
    service = IntelligenceAssembler(
        history=h, graph=g, authority=authority or AUTH,
        social_engineering=SocialEngineeringDetector(
            SocialEngineeringPolicy(
                policy_version="soc-v1",
                amount_baseline_ratio_threshold=baseline_ratio_threshold,
            )
        ),
        behavioral_session=BehavioralSessionDetector(
            BehavioralSessionPolicy(policy_version="beh-v1")
        ),
        internal_graph=InternalGraphDetector(
            InternalGraphPolicy(policy_version="graph-v1")
        ),
        assembly_policy=AssemblyPolicy(policy_version="assembly-v1"),
        source_version="assembly-src-v1",
        journey=j if include_journey else None,
    )
    return service, h, g, j


def test_unavailable_providers_zero_risk_and_auditable_missing() -> None:
    service, h, g, j = assembler(include_journey=True)
    result = service.assemble(tx(), decision_context=context())
    assert result.snapshot == IntelligenceSnapshot()
    assert {"history_features", "graph_intelligence", "session_telemetry",
            "journey_intelligence"} <= set(result.missing)
    assert result.provider_digests == ()
    assert h.received == g.received == j.received == [RECEIVED]


def test_verified_signals_same_cutoff_replay_and_provenance() -> None:
    history = issued("history", HistoryFeatures(
        account_transfers_1h=5, beneficiary_unique_senders_1h=8,
        sender_beneficiary_prior_transfer_count=0,
        amount_to_sender_baseline_ratio=6.0,
    ))
    graph = issued("graph", graph_signals(risk=True))
    session = issued("session", session_signals())
    service, h, g, _ = assembler(history, graph)
    original = service.assemble(
        tx(), decision_context=context(), session=session
    )
    replay = service.assemble(
        tx(), decision_context=context(), session=session
    )
    assert original == replay
    assert original.snapshot_digest == replay.snapshot_digest
    assert original.snapshot.transaction_risk == pytest.approx(0.78)
    assert original.snapshot.velocity_risk == pytest.approx(0.75)
    assert original.snapshot.network_risk == pytest.approx(0.94)
    assert original.snapshot.device_session_risk == pytest.approx(0.90)
    assert original.decision_id == "original-1"
    assert all(
        item.provenance.observed_at == AT and
        item.provenance.source_version == "fixture-v1"
        for item in original.evidence
    )
    assert h.received == g.received == [RECEIVED, RECEIVED]


def test_context_mismatch_untrusted_replay_and_forgery_rejected() -> None:
    service, _, _, _ = assembler()
    with pytest.raises(AssemblyRejected):
        service.assemble(tx(), decision_context=replace(context(), tenant_id="other"))
    with pytest.raises(AssemblyRejected):
        service.assemble(tx(), decision_context=replace(context(), received_at=RECEIVED + timedelta(days=1)))
    with pytest.raises(AssemblyRejected):
        service.assemble(tx(), decision_context=replace(context(), attestation="0" * 64))
    with pytest.raises(AssemblyRejected):
        service.assemble(tx(), decision_context=replace(context(), occurred_at=AT - timedelta(seconds=1)))
    with pytest.raises(AssemblyRejected):
        service.assemble(tx(), decision_context=replace(context(), received_at=RECEIVED.replace(tzinfo=None)))
    with pytest.raises(AssemblyRejected):
        service.assemble(object(), decision_context=context())  # type: ignore[arg-type]


@pytest.mark.parametrize("mutation", [
    lambda e: replace(e, tenant_id="tenant-b"),
    lambda e: replace(e, event_id=UUID(int=2)),
    lambda e: replace(e, decision_id="retrospective-2"),
    lambda e: replace(e, dataset_epoch="stale-epoch"),
    lambda e: replace(e, dataset_seal="altered-seal"),
    lambda e: replace(e, as_of=RECEIVED + timedelta(seconds=1)),
    lambda e: replace(e, observed_at=RECEIVED + timedelta(seconds=1)),
    lambda e: replace(e, available_at=RECEIVED + timedelta(seconds=1)),
    lambda e: replace(e, payload_digest="0" * 64),
    lambda e: replace(e, payload=HistoryFeatures(account_transfers_1h=99)),
    lambda e: replace(e, attestation="0" * 64),
])
def test_untrusted_history_degrades_no_fabricated_risk(mutation) -> None:
    trusted = issued("history", HistoryFeatures(account_transfers_1h=5))
    service, _, _, _ = assembler(history=mutation(trusted))
    result = service.assemble(tx(), decision_context=context())
    assert result.snapshot == IntelligenceSnapshot()
    assert "history_features" in result.missing
    assert "HIGH_ACCOUNT_VELOCITY_1H" not in result.reason_codes


def test_before_at_after_receipt_and_late_replay() -> None:
    row = HistoryFeatures(account_transfers_1h=5)
    before = issued("history", row, available=RECEIVED - timedelta(microseconds=1))
    at = issued("history", row, available=RECEIVED)
    after = issued("history", row, available=RECEIVED + timedelta(microseconds=1))
    for item, allowed in ((before, True), (at, True), (after, False)):
        service, _, _, _ = assembler(history=item)
        result = service.assemble(tx(), decision_context=context())
        assert (result.snapshot.velocity_risk > 0) is allowed
    service, _, _, _ = assembler(history=after)
    late = service.assemble(tx(), decision_context=context())
    assert late.snapshot.velocity_risk == 0
    assert "history_features" in late.missing


def test_unverified_graph_and_session_cannot_make_risk() -> None:
    graph = issued("graph", graph_signals(risk=True))
    session = issued("session", session_signals())
    wrong_graph = replace(graph, dataset_epoch="other")
    service, _, _, _ = assembler(graph=wrong_graph)
    result = service.assemble(
        tx(), decision_context=context(),
        session=replace(session, available_at=RECEIVED + timedelta(seconds=1))
    )
    assert result.snapshot == IntelligenceSnapshot()
    assert "graph_intelligence" in result.missing
    assert "session_telemetry" in result.missing


def test_missing_baseline_never_triggers_low_ratio_threshold() -> None:
    service, _, _, _ = assembler(
        history=issued("history", HistoryFeatures(amount_to_sender_baseline_ratio=None)),
        baseline_ratio_threshold=0.5,
    )
    result = service.assemble(tx(), decision_context=context())
    assert result.snapshot.transaction_risk == 0
    assert "amount_to_sender_baseline_ratio" in result.missing
    measured, _, _, _ = assembler(
        history=issued("history", HistoryFeatures(amount_to_sender_baseline_ratio=1.0)),
        baseline_ratio_threshold=0.5,
    )
    assert measured.assemble(tx(), decision_context=context()).snapshot.transaction_risk > 0


def test_journey_future_and_wrong_tenant_are_missing() -> None:
    assessment = JourneyAssessment(
        tenant_id="tenant-a", customer_id="customer-1", as_of=RECEIVED,
        journey_risk=0.81, reason_codes=("JOURNEY_ANOMALY",),
        contributing_events=(), configuration_version="jcfg-v1",
        policy_version="jp-v1",
    )
    service, _, _, _ = assembler(
        journey=issued("journey", assessment), include_journey=True
    )
    assert service.assemble(tx(), decision_context=context()).snapshot.journey_risk == pytest.approx(0.81)
    for bad in (
        replace(issued("journey", assessment), dataset_seal="stale"),
        issued("journey", assessment.model_copy(update={"tenant_id": "tenant-b"})),
        issued("journey", assessment.model_copy(update={"as_of": RECEIVED + timedelta(seconds=1)})),
    ):
        service, _, _, _ = assembler(journey=bad, include_journey=True)
        result = service.assemble(tx(), decision_context=context())
        assert result.snapshot.journey_risk == 0.0
        assert "journey_intelligence" in result.missing


def test_provider_outage_is_explicitly_unavailable() -> None:
    class Outage:
        def compute(self, transaction, *, decision_as_of, decision_context):
            raise RuntimeError("provider unavailable")
    service, _, _, _ = assembler()
    service._history = Outage()  # type: ignore[assignment]
    result = service.assemble(tx(), decision_context=context())
    assert "history_features" in result.missing
    assert result.snapshot == IntelligenceSnapshot()
