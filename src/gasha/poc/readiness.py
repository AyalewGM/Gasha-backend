"""Conservative, bank-neutral POC stage readiness evaluation (issue #49).

This module produces evidence reports; it never enables enforcement.
"""
from dataclasses import dataclass
from enum import StrEnum


class Stage(StrEnum):
    HISTORICAL = "historical"
    SHADOW = "shadow"
    INLINE_PREPARATION = "inline_preparation"


class EvidenceArea(StrEnum):
    FUNCTIONAL = "functional"
    INTEGRATION = "integration"
    DATA_QUALITY = "data_quality"
    PERFORMANCE = "performance"
    SECURITY = "security"
    OPERATIONS = "operations"


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str
    severity: FindingSeverity
    owner: str
    resolved: bool
    gasha_attributable: bool = True


@dataclass(frozen=True)
class POCGateRequest:
    tenant_id: str
    stage: Stage
    evidence: frozenset[EvidenceArea]
    historical_accepted: bool = False
    shadow_accepted: bool = False
    bank_inline_approved: bool = False
    tenant_inline_enabled: bool = False
    findings: tuple[SecurityFinding, ...] = ()


@dataclass(frozen=True)
class POCGateReport:
    tenant_id: str
    stage: Stage
    ready: bool
    missing_evidence: tuple[str, ...]
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "stage": self.stage.value,
            "ready": self.ready,
            "missing_evidence": list(self.missing_evidence),
            "blockers": list(self.blockers),
            "enforcement_activated": False,
        }


_REQUIRED: dict[Stage, frozenset[EvidenceArea]] = {
    Stage.HISTORICAL: frozenset({
        EvidenceArea.FUNCTIONAL, EvidenceArea.DATA_QUALITY, EvidenceArea.SECURITY,
    }),
    Stage.SHADOW: frozenset(EvidenceArea),
    Stage.INLINE_PREPARATION: frozenset(EvidenceArea),
}


def evaluate_poc_gate(request: POCGateRequest) -> POCGateReport:
    """Missing evidence or approval blocks progression; no implicit stage promotion."""
    if not request.tenant_id.strip():
        raise ValueError("tenant_id is required")
    missing = tuple(sorted(area.value for area in _REQUIRED[request.stage] - request.evidence))
    blockers: list[str] = []
    if request.stage in (Stage.SHADOW, Stage.INLINE_PREPARATION):
        if not request.historical_accepted:
            blockers.append("historical_acceptance_missing")
    if request.stage is Stage.INLINE_PREPARATION:
        if not request.shadow_accepted:
            blockers.append("shadow_acceptance_missing")
        if not request.bank_inline_approved:
            blockers.append("bank_inline_approval_missing")
        if not request.tenant_inline_enabled:
            blockers.append("tenant_inline_configuration_disabled")
        if any(
            f.gasha_attributable and not f.resolved and f.severity is FindingSeverity.CRITICAL
            for f in request.findings
        ):
            blockers.append("unresolved_critical_security_finding")
    return POCGateReport(
        tenant_id=request.tenant_id,
        stage=request.stage,
        ready=not missing and not blockers,
        missing_evidence=missing,
        blockers=tuple(blockers),
    )
