"""#145/#48: synthetic-only immutable feature evidence and replay negatives."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from test_feature_assessment_v1 import T, assess, history, normalized

from gasha.domain.models import DecisionAction, DecisionPolicy
from gasha.intelligence.feature_evidence_v1 import SyntheticFeatureEvidenceV1
from gasha.orchestration import ShadowEvaluationRecord, ShadowOrchestrator

POLICY = DecisionPolicy(
    configuration_version="synthetic-config-1",
    policy_version="synthetic-policy-1",
    rule_version="synthetic-rules-1",
)


def _assessed():
    event = normalized()
    return assess(event, history())


def test_evidence_is_atomic_record_content_not_a_free_form_analyst_claim():
    assessment = _assessed()
    workflow = ShadowOrchestrator(
        {assessment.tenant_id: POLICY}, clock=lambda: T + timedelta(minutes=30),
    )
    result = workflow.evaluate(
        assessment.assessed_envelope, feature_assessment=assessment,
    )
    assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
    original = workflow.evaluations.get(assessment.tenant_id, assessment.event_id)
    assert original is not None and original.feature_evidence is not None
    lineage = original.feature_evidence
    assert lineage.tenant_id == assessment.tenant_id
    assert lineage.event_id == assessment.event_id
    assert lineage.decision_as_of == assessment.decision_as_of
    assert lineage.source_fingerprint == assessment.source_fingerprint
    assert lineage.computation_fingerprint == assessment.computation_fingerprint
    assert len(lineage.lineage_ref) == 64
    assert "customer-x" not in original.feature_evidence.model_dump_json()
    restored = ShadowEvaluationRecord.model_validate_json(original.model_dump_json())
    assert restored.feature_evidence == lineage
    assert restored.feature_evidence is not None
    assert restored.feature_evidence.lineage_ref == lineage.lineage_ref


@pytest.mark.parametrize("change", [
    "wrong_tenant", "wrong_event", "wrong_cutoff", "altered_envelope",
    "altered_lineage_ref", "enforcing_mode",
])
def test_untrusted_lineage_substitution_rejected_before_evaluation(change):
    assessment = _assessed()
    candidate = assessment
    event = candidate.assessed_envelope
    if change == "wrong_tenant":
        candidate = replace(assessment, tenant_id="other-tenant")
    elif change == "wrong_event":
        candidate = replace(assessment, event_id=uuid4())
    elif change == "wrong_cutoff":
        candidate = replace(
            assessment, decision_as_of=assessment.decision_as_of + timedelta(seconds=1),
        )
    elif change == "altered_envelope":
        event = event.model_copy(update={"evidence_reason_codes": ("FORGED",)})
    elif change == "altered_lineage_ref":
        original = SyntheticFeatureEvidenceV1.from_assessment(assessment)
        edited = original.model_copy(update={"lineage_ref": "0" * 64})
        with pytest.raises(ValueError, match="digest mismatch"):
            edited.assert_matches_event(event)
        return
    else:
        from gasha.domain.models import OperatingMode
        event = event.model_copy(update={"operating_mode": OperatingMode.ENFORCING})
    workflow = ShadowOrchestrator({assessment.tenant_id: POLICY})
    with pytest.raises(ValueError, match="mismatch|untrusted|invalid"):
        workflow.evaluate(event, feature_assessment=candidate)
    assert workflow.evaluations.get(assessment.tenant_id, assessment.event_id) is None


def test_forged_in_process_source_digest_is_not_bank_attestation():
    """Content consistency cannot authenticate a forged in-process assessment.

    The configured synthetic provider snapshot must supply source authority;
    caller-controlled hashes, however internally consistent, are not proof.
    """
    assessment = _assessed()
    fabricated = replace(assessment, source_fingerprint="0" * 64)
    forged = SyntheticFeatureEvidenceV1.from_assessment(fabricated)
    honest = SyntheticFeatureEvidenceV1.from_assessment(assessment)
    assert forged.source_fingerprint != honest.source_fingerprint
    assert forged.lineage_ref != honest.lineage_ref
    # A self-consistent fabricated hash alone cannot be rejected here.
    # Do not use this component in isolation as a Bank-trusted source check.


def test_changed_receipt_or_available_source_changes_lineage_identity():
    event = normalized()
    original = assess(event, history())
    later = assess(
        event.model_copy(update={"received_at": event.received_at + timedelta(seconds=2)}),
        history(),
    )
    assert (
        SyntheticFeatureEvidenceV1.from_assessment(original).lineage_ref
        != SyntheticFeatureEvidenceV1.from_assessment(later).lineage_ref
    )
    changed = replace(
        history()[0], available_at=history()[0].available_at + timedelta(seconds=3),
    )
    newer = assess(event, (changed,) + history()[1:])
    assert newer.feature_set.beneficiary_unique_senders_1h == original.feature_set.beneficiary_unique_senders_1h
    assert (
        SyntheticFeatureEvidenceV1.from_assessment(original).lineage_ref
        != SyntheticFeatureEvidenceV1.from_assessment(newer).lineage_ref
    )
