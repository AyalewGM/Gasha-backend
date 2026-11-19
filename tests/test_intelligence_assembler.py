"""Offline point-in-time attested assembly negative controls (synthetic only)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hmac import new
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.intelligence.assembler import (
    HISTORY_FEATURE_SCHEMA_VERSION,
    HISTORY_MAX_COUNT,
    HISTORY_MAX_RATIO,
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
    policy_snapshot,
    transaction_digest,
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
from gasha.journey.detector import ContributingEvent, JourneyAssessment
from gasha.journey.policy import JourneyRiskPolicy

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


def context(
    *, baseline_ratio_threshold: float = 4.0, velocity_threshold: int = 3,
) -> OriginalDecisionContext:
    snapshots = (
        policy_snapshot("assembly", AssemblyPolicy(
            policy_version="assembly-v1", velocity_1h_threshold=velocity_threshold
        )),
        policy_snapshot("social", SocialEngineeringPolicy(
            policy_version="soc-v1",
            amount_baseline_ratio_threshold=baseline_ratio_threshold,
        )),
        policy_snapshot("graph", InternalGraphPolicy(policy_version="graph-v1")),
        policy_snapshot("session", BehavioralSessionPolicy(policy_version="beh-v1")),
        policy_snapshot("journey", JourneyRiskPolicy(
            policy_version="jp-v1", configuration_version="jcfg-v1"
        )),
    )
    unsigned = OriginalDecisionContext(
        tenant_id="tenant-a", event_id=UUID(int=1),
        decision_id="original-1", occurred_at=AT, received_at=RECEIVED,
        dataset_epoch="epoch-1", dataset_seal="seal-1",
        transaction_digest=transaction_digest(tx()), policy_snapshots=snapshots,
        attestation="x" * 64,
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
        policy_digest=(next(p.digest for p in ctx.policy_snapshots if p.role == "journey")
                       if source == "journey" else None),
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
    velocity_threshold: int = 3,
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
        assembly_policy=AssemblyPolicy(
            policy_version="assembly-v1", velocity_1h_threshold=velocity_threshold
        ),
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
    result = service.assemble(
        tx(), decision_context=context(baseline_ratio_threshold=0.5)
    )
    assert result.snapshot.transaction_risk == 0
    assert "amount_to_sender_baseline_ratio" in result.missing
    measured, _, _, _ = assembler(
        history=issued("history", HistoryFeatures(amount_to_sender_baseline_ratio=1.0)),
        baseline_ratio_threshold=0.5,
    )
    assert measured.assemble(
        tx(), decision_context=context(baseline_ratio_threshold=0.5)
    ).snapshot.transaction_risk > 0


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


@pytest.mark.parametrize("change", [
    {"amount": Decimal("5000.01")},
    {"currency": "USD"},
    {"sender_customer_id": "customer-2"},
    {"sender_account_id": "account-2"},
    {"beneficiary_id": "beneficiary-2"},
    {"beneficiary_type": BeneficiaryType.INTERNAL},
    {"destination_institution_id": "other-bank"},
    {"channel": "internet"},
    {"transaction_type": "withdrawal"},
    {"correlation_id": "other-correlation"},
    {"device_id": "device-2"},
])
def test_original_issuer_transaction_binding_rejects_same_identity_substitution(change) -> None:
    service, h, g, j = assembler()
    changed = tx().model_copy(update=change)
    with pytest.raises(AssemblyRejected, match="identity/clock"):
        service.assemble(changed, decision_context=context())
    assert h.received == g.received == j.received == []


def test_exact_decimal_canonicalization() -> None:
    assert transaction_digest(tx()) == transaction_digest(
        tx().model_copy(update={"amount": Decimal("5000.0000")})
    )
    assert transaction_digest(tx()) != transaction_digest(
        tx().model_copy(update={"amount": Decimal("5000.0001")})
    )
    for bad in (Decimal("1E+999"), Decimal("1E-999")):
        with pytest.raises(ValueError):
            transaction_digest(tx().model_copy(update={"amount": bad}))


def test_same_policy_version_changed_velocity_rejected_before_provider() -> None:
    fact = issued("history", HistoryFeatures(account_transfers_1h=5))
    first, _, _, _ = assembler(history=fact)
    original = first.assemble(tx(), decision_context=context())
    assert "HIGH_ACCOUNT_VELOCITY_1H" in original.reason_codes
    second, h, g, _ = assembler(history=fact, velocity_threshold=6)
    with pytest.raises(AssemblyRejected, match="effective policy"):
        second.assemble(tx(), decision_context=context())
    assert h.received == g.received == []
    new_context = context(velocity_threshold=6)
    revised = second.assemble(tx(), decision_context=new_context)
    assert "HIGH_ACCOUNT_VELOCITY_1H" not in revised.reason_codes
    assert original.snapshot_digest != revised.snapshot_digest
    assert original.policy_snapshots[0].digest != revised.policy_snapshots[0].digest


def test_unverified_policy_snapshot_rejected_before_provider_call() -> None:
    signed = context()
    service, h, g, _ = assembler()
    for broken in (
        replace(signed, policy_snapshots=signed.policy_snapshots[:-1]),
        replace(signed, policy_snapshots=signed.policy_snapshots[:1] + (
            replace(signed.policy_snapshots[1], content="{}"),
        ) + signed.policy_snapshots[2:]),
        replace(signed, policy_snapshots=signed.policy_snapshots[:2] + (
            replace(signed.policy_snapshots[2], digest="0" * 64),
        ) + signed.policy_snapshots[3:]),
    ):
        with pytest.raises(AssemblyRejected):
            service.assemble(tx(), decision_context=broken)
        assert h.received == g.received == []


def test_issuer_signed_invalid_effective_policy_fails_closed() -> None:
    signed = context()
    corrupted = replace(
        signed, policy_snapshots=signed.policy_snapshots[:1] + (
            replace(signed.policy_snapshots[1], digest="0" * 64),
        ) + signed.policy_snapshots[2:],
        attestation="x" * 64,
    )
    reissued = replace(corrupted, attestation=mac(context_identity(corrupted)))
    service, h, g, _ = assembler()
    with pytest.raises(AssemblyRejected, match="unverified effective policy"):
        service.assemble(tx(), decision_context=reissued)
    assert h.received == g.received == []


def test_equally_scored_attested_provider_metadata_has_distinct_identity() -> None:
    features = HistoryFeatures(account_transfers_1h=0)
    first, _, _, _ = assembler(
        history=issued("history", features, available=RECEIVED - timedelta(seconds=2))
    )
    second, _, _, _ = assembler(
        history=issued("history", features, available=RECEIVED - timedelta(seconds=1))
    )
    a = first.assemble(tx(), decision_context=context())
    b = second.assemble(tx(), decision_context=context())
    assert a.snapshot == b.snapshot
    assert a.provider_digests != b.provider_digests
    assert a.snapshot_digest != b.snapshot_digest
    assert a == first.assemble(tx(), decision_context=context())


def test_journey_policy_artifact_and_envelope_are_bound() -> None:
    assessment = JourneyAssessment(
        tenant_id="tenant-a", customer_id="customer-1", as_of=RECEIVED,
        journey_risk=0.5, reason_codes=("JOURNEY_ANOMALY",),
        contributing_events=(), configuration_version="jcfg-v1",
        policy_version="jp-v1",
    )
    signed = issued("journey", assessment)
    service, _, _, _ = assembler(journey=signed, include_journey=True)
    result = service.assemble(tx(), decision_context=context())
    assert result.snapshot.journey_risk == pytest.approx(0.5)
    assert {p.role for p in result.policy_snapshots} == {
        "assembly", "social", "graph", "session", "journey"
    }
    unbound = replace(signed, policy_digest="0" * 64)
    service, _, _, _ = assembler(journey=unbound, include_journey=True)
    unavailable = service.assemble(tx(), decision_context=context())
    assert unavailable.snapshot.journey_risk == 0
    assert "journey_intelligence" in unavailable.missing


# Authenticated sources can be wrong: authenticity must precede a separate
# versioned semantic-validation boundary. Each payload below is re-digested
# and signed by the fixture issuer, not merely tampered after signing.
_HISTORY_COUNTS = (
    "account_transfers_1h",
    "beneficiary_unique_senders_1h",
    "beneficiary_incoming_count_1h",
    "sender_beneficiary_prior_transfer_count",
    "beneficiary_confirmed_fraud_sender_count",
)


def assert_invalid_signed_history(features: HistoryFeatures) -> None:
    signed = issued("history", features)
    service, _, _, _ = assembler(history=signed)
    original = service.assemble(tx(), decision_context=context())
    replay = service.assemble(tx(), decision_context=context())
    assert original == replay
    assert original.snapshot == IntelligenceSnapshot()
    assert original.reason_codes == ()
    assert original.evidence == ()
    assert original.missing[:2] == ("history_features", "history_features_invalid")
    assert original.provider_digests == ()
    assert original.snapshot_digest == replay.snapshot_digest
    assert "tenant-b" not in str(original)


@pytest.mark.parametrize("field", _HISTORY_COUNTS)
@pytest.mark.parametrize("invalid", [
    -1, HISTORY_MAX_COUNT + 1, True, False, "5", 5.0, 1.5, [], {"count": 5},
])
def test_attested_invalid_history_count_fails_optional_source(
    field: str, invalid: object,
) -> None:
    assert_invalid_signed_history(replace(HistoryFeatures(), **{field: invalid}))


@pytest.mark.parametrize("invalid", [
    float("nan"), float("inf"), float("-inf"), -1.0, -0.0,
    HISTORY_MAX_RATIO + 1, 10**400, -(10**400), True, False,
    "4.0", [], {"ratio": 4.0},
])
def test_attested_invalid_baseline_ratio_not_fraud_evidence(invalid: object) -> None:
    assert_invalid_signed_history(HistoryFeatures(
        amount_to_sender_baseline_ratio=invalid  # type: ignore[arg-type]
    ))


@pytest.mark.parametrize("field,measured", [
    ("account_transfers_1h", 5),
    ("beneficiary_unique_senders_1h", 2),
    ("beneficiary_incoming_count_1h", 2),
    ("sender_beneficiary_prior_transfer_count", 1),
    ("beneficiary_confirmed_fraud_sender_count", 1),
    ("amount_to_sender_baseline_ratio", 7.0),
    ("device_seen_for_sender_before", False),
])
def test_attested_history_cannot_be_missing_and_measured(
    field: str, measured: object,
) -> None:
    # The fixture genuinely signs the contradictory content, rather than
    # mutating a previously attested envelope after issuance.
    contradictory = replace(
        HistoryFeatures(missing=(field,)), **{field: measured}
    )
    assert_invalid_signed_history(contradictory)


@pytest.mark.parametrize("listed", [True, False])
def test_attested_none_is_unavailable_with_or_without_explicit_missing(
    listed: bool,
) -> None:
    features = HistoryFeatures(
        account_transfers_1h=None,
        missing=("account_transfers_1h",) if listed else (),
    )
    service, _, _, _ = assembler(history=issued("history", features))
    result = service.assemble(tx(), decision_context=context())
    assert result == service.assemble(tx(), decision_context=context())
    assert result.missing.count("account_transfers_1h") == 1
    assert "history_features_invalid" not in result.missing
    assert "history" in dict(result.provider_digests)
    assert "HIGH_ACCOUNT_VELOCITY_1H" not in result.reason_codes


@pytest.mark.parametrize("features", [
    HistoryFeatures(account_transfers_1h=5, missing=("account_transfers_1h",)),
    HistoryFeatures(
        amount_to_sender_baseline_ratio=7.0,
        missing=("amount_to_sender_baseline_ratio",),
    ),
    HistoryFeatures(amount_to_sender_baseline_ratio=10**400),
    HistoryFeatures(amount_to_sender_baseline_ratio=-(10**400)),
])
def test_invalid_attested_history_keeps_valid_graph_and_session(
    features: HistoryFeatures,
) -> None:
    service, _, _, _ = assembler(
        history=issued("history", features),
        graph=issued("graph", graph_signals(risk=True)),
    )
    session = issued("session", session_signals())
    original = service.assemble(tx(), decision_context=context(), session=session)
    replay = service.assemble(tx(), decision_context=context(), session=session)
    assert original == replay
    assert original.missing[:2] == ("history_features", "history_features_invalid")
    assert "history" not in dict(original.provider_digests)
    assert {"graph", "session"} <= set(dict(original.provider_digests))
    assert original.snapshot.velocity_risk == 0
    assert original.snapshot.transaction_risk == 0
    assert original.snapshot.network_risk > 0
    assert original.snapshot.device_session_risk > 0
    assert "HIGH_ACCOUNT_VELOCITY_1H" not in original.reason_codes
    assert "AMOUNT_ABOVE_SENDER_BASELINE" not in original.reason_codes
    assert "tenant-b" not in str(original)


def test_unexpected_history_validation_exception_is_fail_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gasha.intelligence import assembler as module

    def broken(_payload: object) -> bool:
        raise OverflowError("fixture boundary exception (must not be logged)")

    monkeypatch.setattr(module, "valid_history_features", broken)
    service, _, _, _ = assembler(
        history=issued("history", HistoryFeatures(account_transfers_1h=5))
    )
    original = service.assemble(tx(), decision_context=context())
    assert original == service.assemble(tx(), decision_context=context())
    assert original.snapshot == IntelligenceSnapshot()
    assert original.missing[:2] == ("history_features", "history_features_invalid")
    assert original.provider_digests == ()
    assert "fixture boundary exception" not in str(original)


@pytest.mark.parametrize("invalid", ["false", 0, 1, [], {}])
def test_attested_invalid_device_boolean_is_unavailable(invalid: object) -> None:
    assert_invalid_signed_history(HistoryFeatures(
        device_seen_for_sender_before=invalid  # type: ignore[arg-type]
    ))


@pytest.mark.parametrize("invalid", [
    ["account_transfers_1h"], "account_transfers_1h",
    ("account_transfers_1h", "account_transfers_1h"),
    ("unapproved_field",), (1,), (["account_transfers_1h"],),
    ("account_transfers_1h", None),
])
def test_attested_invalid_missing_field_names_are_unavailable(invalid: object) -> None:
    assert_invalid_signed_history(HistoryFeatures(
        missing=invalid  # type: ignore[arg-type]
    ))


@pytest.mark.parametrize("features", [
    HistoryFeatures(
        beneficiary_unique_senders_1h=3, beneficiary_incoming_count_1h=2
    ),
    HistoryFeatures(
        beneficiary_confirmed_fraud_sender_count=3, beneficiary_unique_senders_1h=2
    ),
    HistoryFeatures(schema_version="unknown-schema-v2"),
])
def test_attested_impossible_count_relations_or_schema_fail_closed(
    features: HistoryFeatures,
) -> None:
    assert_invalid_signed_history(features)


@pytest.mark.parametrize("field", _HISTORY_COUNTS)
@pytest.mark.parametrize("boundary", [0, HISTORY_MAX_COUNT])
def test_signed_history_counts_accept_named_integrity_boundaries(
    field: str, boundary: int,
) -> None:
    features = replace(HistoryFeatures(), **{field: boundary})
    service, _, _, _ = assembler(history=issued("history", features))
    result = service.assemble(tx(), decision_context=context())
    assert "history_features_invalid" not in result.missing
    assert "history" in dict(result.provider_digests)


@pytest.mark.parametrize("ratio,expected", [
    (0.0, False), (0, False), (3.999, False), (4.0, True),
    (4.001, True), (int(HISTORY_MAX_RATIO), True),
    (HISTORY_MAX_RATIO, True),
])
def test_signed_finite_ratio_boundary_is_reproducible(
    ratio: float, expected: bool,
) -> None:
    features = HistoryFeatures(amount_to_sender_baseline_ratio=ratio)
    service, _, _, _ = assembler(history=issued("history", features))
    result = service.assemble(tx(), decision_context=context())
    assert ("AMOUNT_ABOVE_SENDER_BASELINE" in result.reason_codes) is expected
    assert "history_features_invalid" not in result.missing
    assert result == service.assemble(tx(), decision_context=context())


def test_signed_boolean_and_missing_metadata_positive_controls() -> None:
    features = HistoryFeatures(
        device_seen_for_sender_before=False,
        beneficiary_unique_senders_1h=1,
        beneficiary_incoming_count_1h=1,
        beneficiary_confirmed_fraud_sender_count=1,
        missing=("account_transfers_1h",),
        schema_version=HISTORY_FEATURE_SCHEMA_VERSION,
    )
    service, _, _, _ = assembler(history=issued("history", features))
    result = service.assemble(tx(), decision_context=context())
    assert "history_features_invalid" not in result.missing
    assert "history" in dict(result.provider_digests)
    assert result.snapshot.transaction_risk > 0
    assert result == service.assemble(tx(), decision_context=context())


def test_invalid_history_does_not_suppress_independent_verified_graph() -> None:
    invalid = issued("history", HistoryFeatures(account_transfers_1h=float("inf")))
    graph = issued("graph", graph_signals(risk=True))
    service, _, _, _ = assembler(history=invalid, graph=graph)
    result = service.assemble(tx(), decision_context=context())
    assert "history_features_invalid" in result.missing
    assert "history" not in dict(result.provider_digests)
    assert "graph" in dict(result.provider_digests)
    assert result.snapshot.velocity_risk == 0
    assert result.snapshot.network_risk > 0
    assert result == service.assemble(tx(), decision_context=context())


# A matching wall clock is not necessarily the same instant at a DST fold.
# Every fixture here is reissued using the synthetic test authority; these
# are provenance/chronology negatives, not forged or modified signatures.
_NY = ZoneInfo("America/New_York")


def dst_original(
    occurred_at: datetime, received_at: datetime,
) -> tuple[CanonicalTransaction, OriginalDecisionContext]:
    transaction = tx().model_copy(update={"occurred_at": occurred_at})
    unsigned = replace(
        context(), occurred_at=occurred_at, received_at=received_at,
        transaction_digest=transaction_digest(transaction), attestation="x" * 64,
    )
    return transaction, replace(
        unsigned, attestation=mac(context_identity(unsigned))
    )


def dst_payload(source: str, observed_at: datetime) -> object:
    if source == "history":
        return HistoryFeatures(account_transfers_1h=5)
    if source == "graph":
        original = graph_signals(risk=True)
    else:
        original = session_signals()
    return original.model_copy(update={
        "provenance": original.provenance.model_copy(
            update={"observed_at": observed_at}
        ),
    })


@pytest.mark.parametrize("occurred,received,allowed", [
    (
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=0),
        False,
    ),
    (
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=0),
        datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=1),
        True,
    ),
    (
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        True,
    ),
    (
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 6, 30, tzinfo=UTC),
        True,
    ),
])
def test_issuer_signed_original_receipt_uses_utc_instant_order(
    occurred: datetime, received: datetime, allowed: bool,
) -> None:
    transaction, original = dst_original(occurred, received)
    history = issued(
        "history", HistoryFeatures(account_transfers_1h=5), ctx=original
    )
    service, h, g, j = assembler(history=history)
    if not allowed:
        with pytest.raises(AssemblyRejected, match="identity/clock"):
            service.assemble(transaction, decision_context=original)
        assert h.received == g.received == j.received == []
    else:
        first = service.assemble(transaction, decision_context=original)
        assert first == service.assemble(transaction, decision_context=original)
        assert "history" in dict(first.provider_digests)
        assert h.received == g.received == [received.astimezone(UTC)] * 2


@pytest.mark.parametrize("source", ["history", "graph", "session"])
def test_issuer_signed_dst_fold_rejects_provider_observation_after_availability(
    source: str,
) -> None:
    # Later physical instant (EST) has an earlier wall time than the
    # provider's earlier availability instant (EDT).
    observed = datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1)
    available = datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=0)
    transaction, original = dst_original(
        datetime(2026, 11, 1, 5, 0, tzinfo=UTC),
        datetime(2026, 11, 1, 7, 0, tzinfo=UTC),
    )
    bad = issued(
        source, dst_payload(source, observed), ctx=original,
        observed=observed, available=available,
    )
    good_graph = issued("graph", graph_signals(risk=True), ctx=original)
    good_session = issued("session", session_signals(), ctx=original)
    service, _, _, _ = assembler(
        history=bad if source == "history" else None,
        graph=bad if source == "graph" else good_graph,
    )
    result = service.assemble(
        transaction, decision_context=original,
        session=bad if source == "session" else good_session,
    )
    marker = {
        "history": "history_features",
        "graph": "graph_intelligence",
        "session": "session_telemetry",
    }[source]
    assert marker in result.missing
    assert source not in dict(result.provider_digests)
    if source == "history":
        assert result.snapshot.velocity_risk == 0
        assert result.snapshot.network_risk > 0
    elif source == "graph":
        assert result.snapshot.network_risk == 0
        assert result.snapshot.device_session_risk > 0
    else:
        assert result.snapshot.device_session_risk == 0
        assert result.snapshot.network_risk > 0
    assert result == service.assemble(
        transaction, decision_context=original,
        session=bad if source == "session" else good_session,
    )


@pytest.mark.parametrize("source", ["graph", "session"])
def test_signed_embedded_provenance_dst_fold_not_equal_to_envelope(
    source: str,
) -> None:
    early = datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=0)
    late = datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1)
    transaction, original = dst_original(
        datetime(2026, 11, 1, 5, 0, tzinfo=UTC),
        datetime(2026, 11, 1, 7, 0, tzinfo=UTC),
    )
    bad = issued(
        source, dst_payload(source, early), ctx=original,
        observed=late,
    )
    def assess(envelope: ProviderEvidence) -> object:
        service, _, _, _ = assembler(
            graph=envelope if source == "graph" else None,
        )
        return service.assemble(
            transaction, decision_context=original,
            session=envelope if source == "session" else None,
        )

    rejected = assess(bad)
    assert source not in dict(rejected.provider_digests)
    assert ("graph_intelligence" if source == "graph" else "session_telemetry") in rejected.missing
    assert rejected.snapshot.network_risk == 0
    assert rejected.snapshot.device_session_risk == 0
    assert rejected == assess(bad)

    # Differently represented clocks that denote the SAME UTC instant pass.
    good = issued(
        source, dst_payload(source, late), ctx=original,
        observed=late.astimezone(UTC),
    )
    accepted = assess(good)
    assert source in dict(accepted.provider_digests)
    assert accepted.snapshot.network_risk > 0 if source == "graph" else accepted.snapshot.device_session_risk > 0
    assert accepted == assess(good)

# SEC-171-05: signed UC-03 journey payload clocks must use physical UTC
# instants, including during the repeated New York DST hour. All payloads
# below are freshly digested and attested by the synthetic fixture issuer.
@pytest.mark.parametrize("cutoff,as_of,event_at,accepted", [
    # Identical instant in New York EST and UTC; previously falsely rejected.
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        True,
    ),
    # Same local wall time, but earlier EDT fold: not the cutoff instant.
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=0),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=0),
        False,
    ),
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        True,
    ),
    # Earlier wall clock may actually be AFTER the original UTC cutoff.
    (
        datetime(2026, 11, 1, 5, 45, tzinfo=UTC),
        datetime(2026, 11, 1, 5, 45, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        False,
    ),
    # Later local wall clock in EDT can be earlier than cutoff in EST.
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=0),
        True,
    ),
    (
        datetime(2026, 11, 1, 5, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=0),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=0),
        True,
    ),
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 6, 15),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        False,
    ),
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 5, 30),
        False,
    ),
    (
        datetime(2026, 11, 1, 6, 15, tzinfo=UTC),
        datetime(2026, 11, 1, 1, 15, tzinfo=_NY, fold=1),
        datetime(2026, 11, 1, 1, 30, tzinfo=_NY, fold=1),
        False,
    ),
])
def test_signed_journey_dst_payload_uses_aware_utc_instant(
    cutoff: datetime, as_of: datetime, event_at: datetime, accepted: bool,
) -> None:
    transaction, original = dst_original(
        datetime(2026, 11, 1, 5, tzinfo=UTC), cutoff
    )
    assessment = JourneyAssessment(
        tenant_id="tenant-a", customer_id="customer-1", as_of=as_of,
        journey_risk=0.81, reason_codes=("JOURNEY_ANOMALY",),
        contributing_events=(ContributingEvent(
            event_id=UUID(int=9), kind="authentication", subtype="login_failed",
            occurred_at=event_at,
        ),),
        configuration_version="jcfg-v1", policy_version="jp-v1",
    )
    journey = issued("journey", assessment, ctx=original)
    history = issued(
        "history", HistoryFeatures(account_transfers_1h=5), ctx=original
    )
    graph = issued("graph", graph_signals(risk=True), ctx=original)
    session = issued("session", session_signals(), ctx=original)
    service, _, _, _ = assembler(
        history=history, graph=graph, journey=journey, include_journey=True
    )
    result = service.assemble(
        transaction, decision_context=original, session=session
    )
    assert result == service.assemble(
        transaction, decision_context=original, session=session
    )
    digests = dict(result.provider_digests)
    assert {"history", "graph", "session"} <= digests.keys()
    assert result.snapshot.velocity_risk > 0
    assert result.snapshot.network_risk > 0
    assert result.snapshot.device_session_risk > 0
    assert ("journey" in digests) is accepted
    assert ("journey_intelligence" not in result.missing) is accepted
    assert ("JOURNEY_ANOMALY" in result.reason_codes) is accepted
    if accepted:
        assert result.snapshot.journey_risk == pytest.approx(0.81)
    else:
        assert result.snapshot.journey_risk == 0.0
        assert "journey" not in digests
        assert "customer-1" not in str(result.reason_codes)
