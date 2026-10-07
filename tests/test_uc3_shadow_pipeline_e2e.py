from __future__ import annotations

from datetime import timedelta

from gasha.domain.models import (
    DecisionAction,
    DecisionPolicy,
    OperatingMode,
)
from gasha.ingestion.bus import InMemoryEventBus
from gasha.ingestion.outcome_ingestion import OutcomeIngestionService
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionOutcome, IngestionService
from gasha.journey.features import JourneyWindows
from gasha.journey.ingestion import (
    JourneyIngestionOutcome,
    JourneyIngestionService,
)
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.provider import PolicyBoundJourneyIntelligence
from gasha.journey.repository import InMemoryJourneyEventRepository
from gasha.orchestration import (
    InMemoryShadowEvaluationRepository,
    ShadowOrchestrator,
)
from gasha.poc.bank_simulator import (
    SyntheticBankSimulator,
    is_journey_inbound,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.outcomes import OutcomeRecord, OutcomeType
from gasha.poc.report import build_poc_report

POLICIES = {
    "tenant-a": DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version="policy-1",
        rule_version="rules-1",
        model_version="model-1",
    )
}

# Engineering fixture: the simulator spaces events 15 minutes apart, so
# the tenant's authentication window is widened accordingly.
JOURNEY_POLICIES = {
    "tenant-a": JourneyRiskPolicy(
        configuration_version="journey-config-1",
        policy_version="journey-v1",
        windows=JourneyWindows(
            authentication_window=timedelta(hours=3),
        ),
    )
}

CONFIRMED_FRAUD = {
    "coached-scam",
    "remote-access-scam",
    "mule-aggregation",
    "ato-takeover-payment",
}


def _name(event) -> str:
    return event.payload["correlation_id"].removeprefix("sim-corr-")


def _pipeline(policies=None, journey_policies=None):
    bus = InMemoryEventBus()
    adapter = ReferenceJsonAdapter()
    source = SyntheticBankSimulator().source_system
    payments = IngestionService({source: adapter})
    journey_repo = InMemoryJourneyEventRepository()
    journeys = JourneyIngestionService({source: adapter}, journey_repo)
    intelligence = PolicyBoundJourneyIntelligence(
        journey_repo, journey_policies or JOURNEY_POLICIES
    )
    evaluations = InMemoryShadowEvaluationRepository()
    orchestrator = ShadowOrchestrator(
        policies or POLICIES,
        evaluations=evaluations,
        journey=intelligence,
    )
    outcomes = OutcomeIngestionService()
    return (
        bus,
        payments,
        journeys,
        evaluations,
        orchestrator,
        outcomes,
    )


def _run(stream, policies=None, journey_policies=None):
    (
        bus,
        payments,
        journeys,
        evaluations,
        orchestrator,
        outcomes,
    ) = _pipeline(policies, journey_policies)
    for inbound in stream:
        bus.publish(inbound)

    evaluated = []
    for inbound in bus.poll(max_events=200):
        if is_journey_inbound(inbound):
            result = journeys.ingest(inbound)
            assert (
                result.outcome == JourneyIngestionOutcome.ACCEPTED
            ), _name(inbound)
            continue
        result = payments.ingest(inbound)
        assert result.outcome == IngestionOutcome.ACCEPTED, _name(
            inbound
        )
        evaluation = orchestrator.evaluate(result.envelope)
        evaluated.append((inbound, result.envelope, evaluation))
    return evaluated, evaluations, outcomes


def test_uc3_ato_payment_gains_journey_context_through_pipeline():
    """Async journey events -> repository; payment -> decision."""

    simulator = SyntheticBankSimulator()
    evaluated, evaluations, _ = _run(simulator.ato_scenario())

    assert len(evaluated) == 1
    inbound, envelope, evaluation = evaluated[0]
    assert _name(inbound) == "ato-takeover-payment"

    # The sequence is worth more than the payment alone: journey risk
    # drives a hypothetical BLOCK the payment's own features could not.
    assert evaluation.decision.action == DecisionAction.BLOCK
    assert "HIGH_JOURNEY_RISK" in evaluation.decision.reason_codes
    assert (
        "PAYMENT_SOON_AFTER_BENEFICIARY_CREATION"
        in evaluation.decision.reason_codes
    )

    # In SHADOW the bank-facing action never enforces.
    assert (
        evaluation.effective_action == DecisionAction.NO_ACTION_SHADOW
    )
    assert envelope.operating_mode == OperatingMode.SHADOW

    # The full assessment is persisted for audit reconstruction.
    stored = evaluations.get(envelope.tenant_id, envelope.event_id)
    assert stored is not None
    assessment = stored.journey
    assert assessment is not None
    assert assessment.policy_version == "journey-v1"
    assert assessment.journey_risk > 0.0
    contributing = {
        event.subtype for event in assessment.contributing_events
    }
    assert {
        "login_failed",
        "login_success",
        "new_device_observed",
        "credential_changed",
        "beneficiary_created",
    } <= contributing


def test_uc1_uc2_uc3_share_one_shadow_decision_path():
    """One stream, one engine: every scenario family fuses together."""

    simulator = SyntheticBankSimulator()
    stream = [
        *simulator.ato_scenario(),
        *simulator.scenario_events(),
    ]
    evaluated, evaluations, outcomes = _run(stream)
    assert len(evaluated) == 8 + 1

    hypothetical = {
        _name(inbound): evaluation.decision.action
        for inbound, _, evaluation in evaluated
    }
    # UC-03
    assert (
        hypothetical["ato-takeover-payment"] == DecisionAction.BLOCK
    )
    # UC-01
    assert hypothetical["coached-scam"] == DecisionAction.HOLD
    assert hypothetical["remote-access-scam"] == DecisionAction.BLOCK
    # UC-02
    assert hypothetical["mule-aggregation"] == DecisionAction.BLOCK

    assert all(
        evaluation.effective_action == DecisionAction.NO_ACTION_SHADOW
        for _, _, evaluation in evaluated
    )

    # Every payment evaluation persisted with provenance.
    for _, envelope, _ in evaluated:
        assert (
            evaluations.get(envelope.tenant_id, envelope.event_id)
            is not None
        )

    # Confirmed outcomes attach; T0 decisions never mutate.
    for inbound, envelope, _ in evaluated:
        outcomes.submit(
            OutcomeRecord(
                tenant_id=envelope.tenant_id,
                event_id=envelope.event_id,
                outcome=(
                    OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD
                    if _name(inbound) in CONFIRMED_FRAUD
                    else OutcomeType.CONFIRMED_LEGITIMATE
                ),
                outcome_source="case-review",
                outcome_version="outcomes-1",
            )
        )

    # The same envelopes feed replay + POC evidence. Journey risk is
    # reconstructed from the persisted assessment — exactly the fused
    # snapshot the decision saw at evaluation time.
    labeled = [
        HistoricalTransactionEvent(
            transaction=envelope.canonical_transaction,
            intelligence=envelope.intelligence.model_copy(
                update={
                    "journey_risk": (
                        stored.journey.journey_risk
                        if (
                            stored := evaluations.get(
                                envelope.tenant_id, envelope.event_id
                            )
                        )
                        and stored.journey is not None
                        else 0.0
                    )
                }
            ),
            evidence_reason_codes=envelope.evidence_reason_codes,
            signal_policy_versions=envelope.signal_policy_versions,
            label=ConfirmedOutcomeLabel(
                is_fraud=_name(inbound) in CONFIRMED_FRAUD,
                label_source="case-review",
            ),
        )
        for inbound, envelope, _ in evaluated
    ]
    replay = replay_historical(tuple(labeled), POLICIES)
    assert replay.metrics.labeled_cases == 9
    assert replay.metrics.true_positives == 4

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="uc1-uc2-uc3-shadow-e2e",
        report=replay,
        policies=POLICIES,
    )
    assert poc.confusion.true_positives == 4
    assert poc.confusion.false_positives == 3
    assert poc.confusion.true_negatives == 2
    assert poc.limitations


def test_journey_context_cannot_cross_tenants_e2e():
    """Tenant-b journey events must not score tenant-a payments."""

    simulator_b = SyntheticBankSimulator(tenant_id="tenant-b")
    simulator_a = SyntheticBankSimulator(tenant_id="tenant-a")

    policies = dict(POLICIES)
    policies["tenant-b"] = DecisionPolicy(
        configuration_version="tenant-b-config",
        policy_version="policy-b",
        rule_version="rules-b",
    )
    journey_policies = dict(JOURNEY_POLICIES)
    journey_policies["tenant-b"] = JourneyRiskPolicy(
        configuration_version="journey-b-config",
        policy_version="journey-b",
        windows=JourneyWindows(
            authentication_window=timedelta(hours=3),
        ),
    )

    (
        bus,
        payments,
        journeys,
        _evaluations,
        orchestrator,
        _outcomes,
    ) = _pipeline(policies, journey_policies)

    for inbound in simulator_b.ato_scenario(name="b-ato"):
        if is_journey_inbound(inbound):
            bus.publish(inbound)
    # Only tenant-b's journey events exist; tenant-a's identical
    # payment must score with an empty journey.
    payment = simulator_a.event(
        "a-clean-payment",
        amount="5600.00",
        customer_id="sim-customer-b-ato",
    )
    bus.publish(payment)

    for inbound in bus.poll(max_events=50):
        if is_journey_inbound(inbound):
            journeys.ingest(inbound)
            continue
        result = payments.ingest(inbound)
        evaluation = orchestrator.evaluate(result.envelope)
        assert evaluation.decision.action == DecisionAction.ALLOW
        assert (
            "HIGH_JOURNEY_RISK"
            not in evaluation.decision.reason_codes
        )
