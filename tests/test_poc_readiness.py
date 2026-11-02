"""Fail-closed POC progression tests; no real bank data or inline activation."""

from dataclasses import replace
from typing import Any

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


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize(
    "tenant_id",
    [
        "", " ", "\t", "\n", " leading", "trailing ", "embedded\nnewline",
        "nul\x00injection", "zero\u200bwidth", "bidi\u202ereversal",
    ],
)
def test_tenant_identity_must_be_canonical_printable_text(
    stage: Stage, tenant_id: str
) -> None:
    # Reject ambiguous report attribution at every stage, even if approvals
    # would otherwise be satisfied; this is shape validation, not tenant auth.
    packet = replace(
        request(stage),
        tenant_id=tenant_id,
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
    )
    with pytest.raises(ValueError, match="tenant_id"):
        evaluate_poc_gate(packet)


@pytest.mark.parametrize("tenant_id", [None, 1, b"tenant", True])
def test_tenant_identity_requires_actual_string(tenant_id: Any) -> None:
    with pytest.raises(TypeError, match="tenant_id"):
        evaluate_poc_gate(replace(request(Stage.HISTORICAL), tenant_id=tenant_id))


def test_valid_canonical_tenant_identifier_preserved_in_report() -> None:
    report = evaluate_poc_gate(request(Stage.HISTORICAL))
    assert report.ready
    assert report.tenant_id == "synthetic-tenant"
    assert report.to_dict()["enforcement_activated"] is False


@pytest.mark.parametrize(
    ("stage", "area"),
    [
        (Stage.HISTORICAL, EvidenceArea.FUNCTIONAL),
        (Stage.HISTORICAL, EvidenceArea.DATA_QUALITY),
        (Stage.HISTORICAL, EvidenceArea.SECURITY),
        *[(Stage.SHADOW, area) for area in EvidenceArea],
        *[(Stage.INLINE_PREPARATION, area) for area in EvidenceArea],
    ],
)
def test_each_required_area_independently_blocks(stage: Stage, area: EvidenceArea) -> None:
    packet = replace(
        request(stage),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
    )
    assert evaluate_poc_gate(packet).ready
    report = evaluate_poc_gate(replace(packet, evidence=ALL - {area}))
    assert not report.ready
    assert report.missing_evidence == (area.value,)
    assert report.to_dict()["enforcement_activated"] is False


@pytest.mark.parametrize(
    ("stage", "approval", "blocker"),
    [
        (Stage.SHADOW, "historical", "historical_acceptance_missing"),
        (Stage.INLINE_PREPARATION, "historical", "historical_acceptance_missing"),
        (Stage.INLINE_PREPARATION, "shadow", "shadow_acceptance_missing"),
        (Stage.INLINE_PREPARATION, "bank", "bank_inline_approval_missing"),
        (Stage.INLINE_PREPARATION, "tenant", "tenant_inline_configuration_disabled"),
    ],
)
def test_each_required_approval_independently_blocks(
    stage: Stage, approval: str, blocker: str
) -> None:
    packet = replace(
        request(stage),
        historical_accepted=approval != "historical",
        shadow_accepted=approval != "shadow",
        bank_inline_approved=approval != "bank",
        tenant_inline_enabled=approval != "tenant",
    )
    report = evaluate_poc_gate(packet)
    assert not report.ready
    assert report.blockers == (blocker,)
    assert not report.missing_evidence
    assert report.to_dict()["enforcement_activated"] is False


@pytest.mark.parametrize("stage", list(Stage))
def test_complete_packet_never_activates_or_mutates_request(stage: Stage) -> None:
    packet = replace(
        request(stage),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
    )
    before = replace(packet)
    first = evaluate_poc_gate(packet)
    assert first.ready
    assert first.to_dict()["enforcement_activated"] is False
    assert packet == before
    assert evaluate_poc_gate(packet) == first




@pytest.mark.parametrize("stage", ["historical", "shadow", "inline_preparation", "unknown", None])
def test_runtime_stage_strings_cannot_skip_approval_checks(stage: Any) -> None:
    packet = replace(request(Stage.INLINE_PREPARATION), stage=stage, historical_accepted=True)
    with pytest.raises(TypeError, match="stage"):
        evaluate_poc_gate(packet)


@pytest.mark.parametrize("field", [
    "historical_accepted", "shadow_accepted", "bank_inline_approved", "tenant_inline_enabled",
])
@pytest.mark.parametrize("value", ["false", "true", 1, 0, None])
def test_runtime_approvals_require_actual_booleans(field: str, value: Any) -> None:
    with pytest.raises(TypeError, match=field):
        evaluate_poc_gate(replace(request(Stage.INLINE_PREPARATION), **{field: value}))


@pytest.mark.parametrize("evidence", [frozenset(area.value for area in EvidenceArea),
                                      set(EvidenceArea), frozenset({"unknown"}), None])
def test_runtime_evidence_requires_typed_immutable_areas(evidence: Any) -> None:
    with pytest.raises(TypeError, match="evidence"):
        evaluate_poc_gate(replace(request(Stage.HISTORICAL), evidence=evidence))


@pytest.mark.parametrize(("field", "value"), [
    ("severity", "critical"), ("severity", "unknown"),
    ("resolved", "false"), ("resolved", 1),
    ("gasha_attributable", "false"), ("gasha_attributable", 0),
])
def test_malformed_findings_cannot_skip_critical_veto(field: str, value: Any) -> None:
    finding = SecurityFinding("synthetic-critical", FindingSeverity.CRITICAL, "security", False)
    packet = replace(request(Stage.INLINE_PREPARATION), historical_accepted=True,
                     shadow_accepted=True, bank_inline_approved=True, tenant_inline_enabled=True,
                     findings=(replace(finding, **{field: value}),))
    with pytest.raises(TypeError):
        evaluate_poc_gate(packet)


@pytest.mark.parametrize("findings", [None, [], ({"severity": "critical"},)])
def test_malformed_finding_collections_are_rejected(findings: Any) -> None:
    with pytest.raises(TypeError, match="findings"):
        evaluate_poc_gate(replace(request(Stage.HISTORICAL), findings=findings))


@pytest.mark.parametrize("field", ("finding_id", "owner"))
@pytest.mark.parametrize(
    "invalid_value",
    (None, "", " ", "\t", 0, True, [], " leading", "trailing ", "embedded\nnewline", b"bytes"),
)
@pytest.mark.parametrize("severity", (FindingSeverity.HIGH, FindingSeverity.CRITICAL))
@pytest.mark.parametrize("resolved", (False, True))
def test_finding_identity_and_owner_must_be_canonical(
    field: str, invalid_value: Any, severity: FindingSeverity, resolved: bool
) -> None:
    finding = SecurityFinding("finding-1", severity, "security-team", resolved)
    malformed = replace(finding, **{field: invalid_value})
    packet = replace(
        request(Stage.INLINE_PREPARATION),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
        findings=(malformed,),
    )
    # Rejected before a ready result even for resolved or HIGH findings.
    with pytest.raises((TypeError, ValueError), match=field):
        evaluate_poc_gate(packet)


@pytest.mark.parametrize("stage", list(Stage))
def test_finding_shape_validation_precedes_all_stage_readiness(stage: Stage) -> None:
    finding = SecurityFinding("valid-id", FindingSeverity.HIGH, "", True)
    packet = replace(
        request(stage),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
        findings=(finding,),
    )
    with pytest.raises(ValueError, match="owner"):
        evaluate_poc_gate(packet)


@pytest.mark.parametrize(
    ("severity", "resolved", "should_be_ready"),
    [
        (FindingSeverity.HIGH, False, True),
        (FindingSeverity.HIGH, True, True),
        (FindingSeverity.CRITICAL, False, False),
        (FindingSeverity.CRITICAL, True, True),
    ],
)
def test_canonical_finding_keeps_existing_critical_only_veto(
    severity: FindingSeverity, resolved: bool, should_be_ready: bool
) -> None:
    finding = SecurityFinding("synthetic-id", severity, "security-team", resolved)
    packet = replace(
        request(Stage.INLINE_PREPARATION),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
        findings=(finding,),
    )
    result = evaluate_poc_gate(packet)
    assert result.ready is should_be_ready
    assert result.to_dict()["enforcement_activated"] is False
    assert ("unresolved_critical_security_finding" in result.blockers) is not should_be_ready


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize(
    ("first_resolved", "second_resolved"),
    ((False, False), (False, True), (True, False), (True, True)),
)
def test_duplicate_finding_id_is_rejected_at_every_stage(
    stage: Stage, first_resolved: bool, second_resolved: bool
) -> None:
    # A single traceability ID cannot name two different owners/severities/
    # dispositions, even when both are resolved or a stage requires less data.
    first = SecurityFinding(
        "synthetic-finding-1", FindingSeverity.CRITICAL, "security-a", first_resolved
    )
    conflicting = SecurityFinding(
        "synthetic-finding-1", FindingSeverity.HIGH, "security-b", second_resolved
    )
    packet = replace(
        request(stage),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
        findings=(first, conflicting),
    )
    with pytest.raises(ValueError, match="duplicate finding_id"):
        evaluate_poc_gate(packet)


def test_distinct_finding_ids_preserve_existing_critical_only_veto() -> None:
    packet = replace(
        request(Stage.INLINE_PREPARATION),
        historical_accepted=True,
        shadow_accepted=True,
        bank_inline_approved=True,
        tenant_inline_enabled=True,
        findings=(
            SecurityFinding("synthetic-finding-1", FindingSeverity.HIGH, "team-a", False),
            SecurityFinding("synthetic-finding-2", FindingSeverity.CRITICAL, "team-b", True),
        ),
    )
    report = evaluate_poc_gate(packet)
    assert report.ready is True
    assert report.to_dict()["enforcement_activated"] is False
