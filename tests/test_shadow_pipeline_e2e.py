from __future__ import annotations

from gasha.domain.models import (
    DecisionAction,
    DecisionPolicy,
    OperatingMode,
)
from gasha.ingestion.bus import InMemoryEventBus
from gasha.ingestion.outcome_ingestion import OutcomeIngestionService
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionOutcome, IngestionService
from gasha.orchestration import (
    InMemoryShadowEvaluationRepository,
    ShadowOrchestrator,
)
from gasha.poc.bank_simulator import SyntheticBankSimulator
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

# Which simulator scenarios the bank later confirms as fraud.
CONFIRMED_FRAUD = {"coached-scam", "remote-access-scam", "mule-aggregation"}


def _scenario_name(event) -> str:
    return event.payload["correlation_id"].removeprefix("sim-corr-")


def test_shadow_pipeline_end_to_end() -> None:
    bus = InMemoryEventBus()
    ingestion = IngestionService(
        {SyntheticBankSimulator().source_system: ReferenceJsonAdapter()}
    )
    evaluations = InMemoryShadowEvaluationRepository()
    orchestrator = ShadowOrchestrator(POLICIES, evaluations=evaluations)
    outcomes = OutcomeIngestionService()

    simulator = SyntheticBankSimulator()
    for event in simulator.scenario_events():
        bus.publish(event)

    # Transport -> ingestion -> normalization -> shadow decision -> audit.
    envelopes = []
    for inbound in bus.poll(max_events=100):
        result = ingestion.ingest(inbound)
        assert result.outcome == IngestionOutcome.ACCEPTED
        assert result.envelope is not None
        evaluation = orchestrator.evaluate(result.envelope)
        envelopes.append((inbound, result.envelope, evaluation))

    assert len(envelopes) == 8

    # No hypothetical action ever becomes an enforcing bank action.
    hypothetical = {
        _scenario_name(inbound): evaluation.decision.action
        for inbound, _, evaluation in envelopes
    }
    assert hypothetical["coached-scam"] == DecisionAction.HOLD
    assert hypothetical["remote-access-scam"] == DecisionAction.BLOCK
    assert hypothetical["mule-aggregation"] == DecisionAction.BLOCK
    assert hypothetical["ambiguous-legit"] == DecisionAction.REVIEW
    assert hypothetical["normal-payment-1"] == DecisionAction.ALLOW
    assert all(
        evaluation.effective_action == DecisionAction.NO_ACTION_SHADOW
        for _, envelope_, evaluation in envelopes
    )
    assert all(
        envelope_.operating_mode == OperatingMode.SHADOW
        for _, envelope_, _ in envelopes
    )

    # Every evaluation persisted with full reconstruction context.
    for _, envelope_, _ in envelopes:
        stored = evaluations.get(
            envelope_.tenant_id, envelope_.event_id
        )
        assert stored is not None
        assert stored.event.adapter.adapter_version == "1.0.0"
        assert stored.evaluation.decision.policy_version == "policy-1"

    # Later confirmed outcomes attach without mutating decisions.
    for inbound, envelope_, _ in envelopes:
        name = _scenario_name(inbound)
        outcomes.submit(
            OutcomeRecord(
                tenant_id="tenant-a",
                event_id=envelope_.event_id,
                outcome=(
                    OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD
                    if name in CONFIRMED_FRAUD
                    else OutcomeType.CONFIRMED_LEGITIMATE
                ),
                outcome_source="case-review",
                outcome_version="outcomes-1",
            )
        )

    # Shadow evidence feeds the POC metrics path unchanged.
    labeled = [
        HistoricalTransactionEvent(
            transaction=envelope_.canonical_transaction,
            intelligence=envelope_.intelligence,
            evidence_reason_codes=envelope_.evidence_reason_codes,
            signal_policy_versions=envelope_.signal_policy_versions,
            label=ConfirmedOutcomeLabel(
                is_fraud=_scenario_name(inbound) in CONFIRMED_FRAUD,
                label_source="case-review",
            ),
        )
        for inbound, envelope_, _ in envelopes
    ]
    replay = replay_historical(tuple(labeled), POLICIES)
    assert replay.metrics.labeled_cases == 8
    assert replay.metrics.true_positives == 3

    poc = build_poc_report(
        tenant_id="tenant-a",
        dataset_id="shadow-pipeline-e2e",
        report=replay,
        policies=POLICIES,
    )
    assert poc.confusion.true_positives == 3
    # new-beneficiary-large, velocity-burst and ambiguous-legit are
    # legitimate scenarios that alert — the realistic FP cost a shadow
    # pilot exists to measure.
    assert poc.confusion.false_positives == 3
    assert poc.confusion.true_negatives == 2
    assert poc.limitations


def test_simulator_resubmission_is_idempotent_through_pipeline() -> None:
    bus = InMemoryEventBus()
    ingestion = IngestionService(
        {SyntheticBankSimulator().source_system: ReferenceJsonAdapter()}
    )
    simulator = SyntheticBankSimulator()
    event = simulator.event("dup-check")

    bus.publish(event)
    bus.publish(event)  # bank-side retry
    results = [
        ingestion.ingest(inbound).outcome
        for inbound in bus.poll(max_events=10)
    ]
    assert results == [
        IngestionOutcome.ACCEPTED,
        IngestionOutcome.DUPLICATE,
    ]
