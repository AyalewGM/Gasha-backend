"""#43 P1: historical case context digests survive optional-evidence serializers.

Pure synthetic fixtures only. A stable content hash is not Bank attestation.
"""
from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from json import dumps

import pytest
from test_feature_assessment_v1 import T, assess, history, normalized

from gasha.cases.evaluation_alerts import evaluation_context_ref
from gasha.domain.models import DecisionPolicy
from gasha.orchestration import (
    ShadowEvaluationRecord,
    ShadowOrchestrator,
    canonical_evaluation_context_payload,
)
from gasha.postgres_evaluations import _immutable_replay_identity

POLICY = DecisionPolicy(
    configuration_version="synthetic-context-config-v1",
    policy_version="synthetic-context-policy-v1",
    rule_version="synthetic-context-rules-v1",
)


def _record(*, with_evidence: bool = False) -> ShadowEvaluationRecord:
    raw = normalized()
    assessment = assess(raw, history()) if with_evidence else None
    event = assessment.assessed_envelope if assessment is not None else raw
    flow = ShadowOrchestrator(
        {event.tenant_id: POLICY}, clock=lambda: T + timedelta(seconds=30),
    )
    flow.evaluate(event, feature_assessment=assessment)
    record = flow.evaluations.get(event.tenant_id, event.event_id)
    assert record is not None
    return record


def _pre_181_digest(record: ShadowEvaluationRecord) -> str:
    # Deliberately implement the *original* v1 digest independently of the
    # production canonical helper: the old model had no feature_evidence key.
    original = record.model_dump(mode="json")
    original.pop("feature_evidence", None)
    return sha256(dumps(
        ["gasha-shadow-evaluation-v1", original],
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def test_absent_and_explicit_null_have_identical_pre_181_context() -> None:
    legacy = _record()
    assert legacy.feature_evidence is None
    baseline = _pre_181_digest(legacy)
    document = legacy.model_dump(mode="json")
    document.pop("feature_evidence", None)
    explicit_null = ShadowEvaluationRecord.model_validate(
        {**document, "feature_evidence": None},
    )
    assert canonical_evaluation_context_payload(legacy)["journey"] is None
    assert "feature_evidence" not in canonical_evaluation_context_payload(legacy)
    assert "feature_evidence" not in canonical_evaluation_context_payload(explicit_null)
    assert evaluation_context_ref(legacy) == evaluation_context_ref(explicit_null) == baseline
    assert _immutable_replay_identity(legacy) == _immutable_replay_identity(explicit_null)


def test_legacy_digest_stable_when_serializer_emits_optional_null(monkeypatch) -> None:
    original_dump = ShadowEvaluationRecord.model_dump
    legacy = _record()
    expected = evaluation_context_ref(legacy)

    def serializer_with_optional_null(self, *args, **kwargs):
        payload = original_dump(self, *args, **kwargs)
        if self.feature_evidence is None and (
            "feature_evidence" not in (kwargs.get("exclude") or set())
        ):
            payload["feature_evidence"] = None
        return payload

    monkeypatch.setattr(ShadowEvaluationRecord, "model_dump", serializer_with_optional_null)
    assert "feature_evidence" in legacy.model_dump(mode="json")
    assert evaluation_context_ref(legacy) == expected
    assert _immutable_replay_identity(legacy)["journey"] is None
    assert "feature_evidence" not in _immutable_replay_identity(legacy)


def test_new_feature_evidence_changes_digest_and_rejects_tampering() -> None:
    current = _record(with_evidence=True)
    evidence = current.feature_evidence
    assert evidence is not None
    assert canonical_evaluation_context_payload(current)["feature_evidence"] == (
        evidence.model_dump(mode="json")
    )
    without_evidence = current.model_copy(update={"feature_evidence": None})
    assert evaluation_context_ref(without_evidence) != evaluation_context_ref(current)
    assert evaluation_context_ref(ShadowEvaluationRecord.model_validate_json(
        current.model_dump_json()
    )) == evaluation_context_ref(current)

    for field in ("lineage_ref", "eligible_observations", "late_observations"):
        original = getattr(evidence, field)
        changed = "0" * 64 if field == "lineage_ref" else original + 1
        modified = evidence.model_copy(update={field: changed})
        tampered = current.model_copy(update={"feature_evidence": modified})
        with pytest.raises(ValueError, match="digest|invalid|mismatch"):
            evaluation_context_ref(tampered)


def test_non_record_rejected_instead_of_untrusted_hash() -> None:
    with pytest.raises(ValueError, match="typed"):
        canonical_evaluation_context_payload(object())  # type: ignore[arg-type]
