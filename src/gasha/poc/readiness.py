"""Conservative, bank-neutral POC stage readiness evaluation (issue #49).

Internal prototype only: categories and approval booleans are caller assertions,
not verified evidence or authorization. Do not expose this evaluator as an
authoritative bank-readiness gate. It never enables enforcement.
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
    _validate_request(request)
    if not request.tenant_id.strip():
        raise ValueError("tenant_id is required")
    missing = tuple(sorted(area.value for area in _REQUIRED[request.stage] - request.evidence))
    blockers: list[str] = []
    if (
        request.stage in (Stage.SHADOW, Stage.INLINE_PREPARATION)
        and not request.historical_accepted
    ):
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


def _validate_request(request: POCGateRequest) -> None:
    """Reject malformed internal assertions; type annotations do not validate at runtime.

    In particular, StrEnum strings compare equal in sets/dicts but do not satisfy
    enum identity checks. Reject them instead of silently skipping stage vetoes.
    This validates shape only, not evidence provenance or approval authority.
    """
    if not isinstance(request.tenant_id, str):
        raise TypeError("tenant_id must be a string")
    if not isinstance(request.stage, Stage):
        raise TypeError("stage must be a Stage enum")
    if not isinstance(request.evidence, frozenset) or any(
        not isinstance(area, EvidenceArea) for area in request.evidence
    ):
        raise TypeError("evidence must be a frozenset of EvidenceArea enums")
    for name in (
        "historical_accepted", "shadow_accepted", "bank_inline_approved", "tenant_inline_enabled",
    ):
        if type(getattr(request, name)) is not bool:
            raise TypeError(f"{name} must be a bool")
    if not isinstance(request.findings, tuple):
        raise TypeError("findings must be a tuple")
    for finding in request.findings:
        if not isinstance(finding, SecurityFinding):
            raise TypeError("findings must contain SecurityFinding records")
        # Finding IDs and owners must be unambiguous traceability references.
        # Reject malformed runtime input rather than trimming or guessing IDs.
        for name in ("finding_id", "owner"):
            value = getattr(finding, name)
            if type(value) is not str:
                raise TypeError(f"{name} must be a string")
            if not value or not value.isprintable() or value != value.strip():
                raise ValueError(f"{name} must be nonblank canonical printable text")
        if not isinstance(finding.severity, FindingSeverity):
            raise TypeError("severity must be a FindingSeverity enum")
        if type(finding.resolved) is not bool or type(finding.gasha_attributable) is not bool:
            raise TypeError("finding status and attribution must be bools")


