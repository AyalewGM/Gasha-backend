"""Fail-closed POC progression tests; no real bank data or inline activation."""
from dataclasses import replace

import pytest

from gasha.poc.readiness import (
    EvidenceArea,
    FindingSeverity,
    POCGateRequest,
    SecurityFinding,
    Stage,
    evaluate_poc_gate,
)


ALL = frozenset(EvidenceArea)


def request(stage: Stage) -> POCGateRequest:
    return POCGateRequest(tenant_id="synthetic-tenant", stage=stage, evidence=ALL)


def test_missing_evidence_blocks_historical_replay() -> None:
    result = evaluate_poc_gate(replace(request(Stage.HISTORICAL), evidence=frozenset()))
    assert not result.ready
    assert "data_quality" in result.missing_evidence
    assert result.to_dict()["enforcement_activated"] is False


def test_historical_gate_independent_of_shadow() -> None:
    assert evaluate_poc_gate(request(Stage.HISTORICAL)).ready
    result = evaluate_poc_gate(request(Stage.SHADOW))
    assert not result.ready
    assert result.blockers == ("historical_acceptance_missing",)


def test_shadow_requires_all_areas_and_historical_acceptance() -> None:
    ready = replace(request(Stage.SHADOW), historical_accepted=True)
    assert evaluate_poc_gate(ready).ready
    missing = replace(ready, evidence=ALL - {EvidenceArea.PERFORMANCE})
    assert not evaluate_poc_gate(missing).ready


def test_inline_never_promotes_without_all_explicit_approvals() -> None:
    request_value = request(Stage.INLINE_PREPARATION)
    assert not evaluate_poc_gate(request_value).ready
    enabled = replace(
        request_value,
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
    )
    report = evaluate_poc_gate(enabled)
    assert report.ready
    assert report.to_dict()["enforcement_activated"] is False


def test_critical_unresolved_gasha_security_finding_blocks_inline() -> None:
    enabled = replace(
        request(Stage.INLINE_PREPARATION),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
    )
    finding = SecurityFinding(
        finding_id="synthetic-sec-1",
        severity=FindingSeverity.CRITICAL,
        owner="security-team",
        resolved=False,
    )
    report = evaluate_poc_gate(replace(enabled, findings=(finding,)))
    assert not report.ready
    assert "unresolved_critical_security_finding" in report.blockers
    assert evaluate_poc_gate(replace(enabled, findings=(replace(finding, resolved=True),))).ready


def test_tenant_identity_required() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        evaluate_poc_gate(replace(request(Stage.HISTORICAL), tenant_id="   "))
