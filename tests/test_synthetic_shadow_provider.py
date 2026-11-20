"""#145/#48 in-process worker port boundaries; no Bank or payment effects."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from test_feature_assessment_v1 import POLICY, T, history, normalized

from gasha.domain.models import (
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.intelligence.synthetic_shadow_provider import (
    SyntheticHistorySnapshotV1,
    SyntheticShadowWorkerEvaluator,
)
from gasha.orchestration import ShadowOrchestrator

DECISION_POLICY = DecisionPolicy(
    configuration_version="synthetic-config-1",
    policy_version="synthetic-decision-1",
    rule_version="synthetic-rules-1",
)


class History:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def snapshot_for(self, tenant_id, event_id):
        return self.snapshot


def snapshot_for(event, *, complete=True):
    return SyntheticHistorySnapshotV1(
        tenant_id=event.tenant_id,
        event_id=event.event_id,
        source_system=event.adapter.source_system,
        receipt_cutoff=event.received_at,
        observations=history(tenant=event.tenant_id),
        graph_policy=POLICY,
        relationship_history_complete=complete,
    )


def test_recovered_worker_callable_derives_evidence_from_source_snapshot_only():
    event = normalized()
    source = History(snapshot_for(event))
    orchestrator = ShadowOrchestrator({event.tenant_id: DECISION_POLICY})
    evaluate = SyntheticShadowWorkerEvaluator(orchestrator, history_source=source)
    result = evaluate(event, DECISION_POLICY)
    assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
    record = orchestrator.evaluations.get(event.tenant_id, event.event_id)
    assert record is not None
    assert record.feature_evidence is not None
    assert len(record.feature_evidence.lineage_ref) == 64
    assert record.feature_evidence.eligible_observations == 5
    assert "beneficiary_unique_senders_1h" not in record.feature_evidence.unavailable_signals
    assert "sender-1" not in record.feature_evidence.model_dump_json()


@pytest.mark.parametrize(
    "change",
    [
        "absent_source", "missing_snapshot", "wrong_tenant", "wrong_event",
        "wrong_source", "wrong_cutoff", "foreign_history", "enforcing_mode",
        "precomputed_risk", "invalid_coverage_flag",
    ],
)
def test_provider_absence_substitution_and_untrusted_inputs_fail_without_records(change):
    event = normalized()
    snapshot = snapshot_for(event)
    if change == "absent_source":
        provider = None
    else:
        if change == "missing_snapshot":
            snapshot = None
        elif change == "wrong_tenant":
            snapshot = replace(snapshot, tenant_id="another-tenant")
        elif change == "wrong_event":
            snapshot = replace(snapshot, event_id=uuid4())
        elif change == "wrong_source":
            snapshot = replace(snapshot, source_system="other-synthetic-source")
        elif change == "wrong_cutoff":
            snapshot = replace(
                snapshot, receipt_cutoff=T + timedelta(seconds=2),
            )
        elif change == "foreign_history":
            snapshot = replace(snapshot, observations=history(tenant="foreign"))
        elif change == "invalid_coverage_flag":
            snapshot = replace(snapshot, relationship_history_complete=1)
        elif change == "enforcing_mode":
            event = event.model_copy(update={"operating_mode": OperatingMode.ENFORCING})
        elif change == "precomputed_risk":
            event = event.model_copy(update={
                "intelligence": IntelligenceSnapshot(network_risk=0.9),
            })
        provider = History(snapshot)
    orchestrator = ShadowOrchestrator({event.tenant_id: DECISION_POLICY})
    evaluate = SyntheticShadowWorkerEvaluator(orchestrator, history_source=provider)
    with pytest.raises(ValueError, match="synthetic|untrusted|provider"):
        evaluate(event, DECISION_POLICY)
    assert orchestrator.evaluations.get(event.tenant_id, event.event_id) is None


def test_incomplete_history_is_unavailable_never_measured_as_zero():
    event = normalized()
    orchestrator = ShadowOrchestrator({event.tenant_id: DECISION_POLICY})
    evaluate = SyntheticShadowWorkerEvaluator(
        orchestrator, history_source=History(snapshot_for(event, complete=False)),
    )
    result = evaluate(event, DECISION_POLICY)
    assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
    persisted = orchestrator.evaluations.get(event.tenant_id, event.event_id)
    assert persisted is not None
    assert persisted.event.intelligence == IntelligenceSnapshot()
    assert persisted.feature_evidence is not None
    assert "beneficiary_unique_senders_1h" in persisted.feature_evidence.unavailable_signals
    assert persisted.feature_evidence.eligible_observations == 5
