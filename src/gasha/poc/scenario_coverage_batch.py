"""Inactive, synthetic-only scenario-separated data-coverage report (#41/#48).

Reuses the eight-scenario observation contract. Presence of evidence is not
source authenticity, scenario detection, a mature label or Bank approval.
No production/API/worker/readiness imports or side effects are permitted.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
from json import dumps

from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
    SCENARIO_MAPPING_VERSION,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
    _digest,
    _instant,
    _revalidated_observation,
    _token,
    inspect_scenario_coverage,
)

REPORT_VERSION = "synthetic-scenario-coverage-batch-v1"


@dataclass(frozen=True, slots=True)
class ScenarioBatchScope:
    """Caller-asserted, one-installation/tenant/dataset/version report boundary."""

    installation_ref: str
    tenant_ref: str
    dataset_digest: str
    source_schema_version: str
    mapping_version: str
    configuration_version: str
    window_start: datetime
    window_end: datetime
    report_as_of: datetime

    def __post_init__(self) -> None:
        for name in (
            "installation_ref",
            "tenant_ref",
            "source_schema_version",
            "mapping_version",
            "configuration_version",
        ):
            _token(name, getattr(self, name))
        _digest("dataset_digest", self.dataset_digest)
        start = _instant("window_start", self.window_start)
        end = _instant("window_end", self.window_end)
        as_of = _instant("report_as_of", self.report_as_of)
        if not start <= end <= as_of:
            raise ScenarioContractError("invalid coverage window or report cutoff")
        object.__setattr__(self, "window_start", start)
        object.__setattr__(self, "window_end", end)
        object.__setattr__(self, "report_as_of", as_of)


@dataclass(frozen=True, slots=True)
class ScenarioBatchCoverageReport:
    scope: ScenarioBatchScope
    input_rows: int
    duplicate_rows: int
    batch_digest: str
    scenarios: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        """Fixed schema and aggregate keys only; never raw event or customer IDs."""
        return {
            "report_version": REPORT_VERSION,
            "scenario_mapping_version": SCENARIO_MAPPING_VERSION,
            "source": "synthetic_caller_asserted",
            "scope": {
                "installation_ref": self.scope.installation_ref,
                "tenant_ref": self.scope.tenant_ref,
                "dataset_digest": self.scope.dataset_digest,
                "source_schema_version": self.scope.source_schema_version,
                "mapping_version": self.scope.mapping_version,
                "configuration_version": self.scope.configuration_version,
                "window_start": self.scope.window_start.isoformat(),
                "window_end": self.scope.window_end.isoformat(),
                "report_as_of": self.scope.report_as_of.isoformat(),
            },
            "batch_digest": self.batch_digest,
            "input_rows": self.input_rows,
            "unique_scenario_events": self.input_rows - self.duplicate_rows,
            "duplicate_rows": self.duplicate_rows,
            "scenarios": list(self.scenarios),
            "downstream_evaluation": {
                "UC-04_alert_prioritization": "blocked_no_analyst_outcome_and_alert_budget",
                "UC-05_false_positive_reduction": "blocked_no_matured_labels_and_comparator",
                "confusion_counts": None,
                "precision": None,
                "recall": None,
                "false_positive_rate": None,
                "alert_budget_approved": False,
            },
            "bank_data_verified": False,
            "historical_replay_authorized": False,
            "detection_executed": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
            "limitations": [
                "The caller supplies installation, tenant, dataset and evidence identity.",
                "Evidence presence and matching digests do not authenticate Bank sources.",
                "Complete coverage is not a fraud hypothesis, labelled cohort or KPI result.",
                "UC-04/05 need mature labels, comparable cohorts, alerts and analyst outcomes.",
                "No Bank source, case-system, operational replay or #49 approval is connected.",
            ],
        }


def _rate(numerator: int, denominator: int) -> dict[str, object]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
        "undefined_reason": None if denominator else "no_scenario_events",
    }


def inspect_scenario_coverage_batch(
    scope: ScenarioBatchScope, observations: tuple[ScenarioObservation, ...]
) -> ScenarioBatchCoverageReport:
    """Inspect point-in-time *presence* for all eight scenarios, never score fraud.

    One event may appear in different scenarios. An identical within-scenario
    retry is counted once; conflicting packets for the same event fail closed
    instead of inflating or rewriting the aggregate denominator.
    """
    if type(scope) is not ScenarioBatchScope:
        raise ScenarioContractError("typed scenario batch scope required")
    try:
        checked_scope = replace(scope)
    except AttributeError:
        raise ScenarioContractError("missing scenario batch scope attribute") from None
    if type(observations) is not tuple:
        raise ScenarioContractError("scenario observations must be an immutable tuple")

    counts: dict[ScenarioId, Counter[str]] = {
        scenario: Counter() for scenario in ScenarioId
    }
    missing: dict[ScenarioId, Counter[str]] = {
        scenario: Counter() for scenario in ScenarioId
    }
    optional: dict[ScenarioId, Counter[str]] = {
        scenario: Counter() for scenario in ScenarioId
    }
    seen: dict[tuple[ScenarioId, str], str] = {}
    duplicate_rows = 0
    for untrusted in observations:
        row = _revalidated_observation(untrusted)
        if (
            row.source_schema_version != checked_scope.source_schema_version
            or row.mapping_version != checked_scope.mapping_version
            or row.configuration_version != checked_scope.configuration_version
        ):
            raise ScenarioContractError("scenario version scope mismatch")
        if not (
            checked_scope.window_start <= row.occurred_at <= checked_scope.window_end
            and row.decision_cutoff <= checked_scope.report_as_of
        ):
            raise ScenarioContractError("scenario outside report time boundary")
        coverage = inspect_scenario_coverage(
            row,
            expected_installation=checked_scope.installation_ref,
            expected_tenant=checked_scope.tenant_ref,
            expected_dataset_digest=checked_scope.dataset_digest,
        )
        identity = (row.scenario_id, str(row.event_id))
        previous_digest = seen.get(identity)
        if previous_digest is not None:
            if previous_digest != coverage.observation_digest:
                raise ScenarioContractError("conflicting scenario event evidence")
            duplicate_rows += 1
            continue
        seen[identity] = coverage.observation_digest
        counts[row.scenario_id]["unique"] += 1
        if coverage.missing_required:
            counts[row.scenario_id]["blocked"] += 1
        else:
            counts[row.scenario_id]["complete"] += 1
        missing[row.scenario_id].update(coverage.missing_required)
        optional[row.scenario_id].update(coverage.unavailable_optional)

    summaries: list[dict[str, object]] = []
    for scenario in ScenarioId:
        mapping = SCENARIO_FIELDS[scenario]
        total = counts[scenario]["unique"]
        complete = counts[scenario]["complete"]
        blocked = counts[scenario]["blocked"]
        status = (
            "no_observations" if not total else
            "blocked_by_data" if not complete else
            "partial_synthetic_coverage" if blocked else "synthetic_coverage_only"
        )
        summaries.append({
            "scenario_id": scenario.value,
            "use_case": mapping.use_case,
            "input_events": total,
            "complete_required_events": complete,
            "blocked_required_events": blocked,
            "required_coverage": _rate(complete, total),
            "missing_required_counts": {
                name: missing[scenario][name] for name in mapping.required
            },
            "unavailable_optional_counts": {
                name: optional[scenario][name] for name in mapping.optional
            },
            "status": status,
            "bank_evaluable": False,
        })

    canonical = dumps(
        {
            "domain": REPORT_VERSION,
            "scope": {
                "installation_ref": checked_scope.installation_ref,
                "tenant_ref": checked_scope.tenant_ref,
                "dataset_digest": checked_scope.dataset_digest,
                "source_schema_version": checked_scope.source_schema_version,
                "mapping_version": checked_scope.mapping_version,
                "configuration_version": checked_scope.configuration_version,
                "window_start": checked_scope.window_start.isoformat(),
                "window_end": checked_scope.window_end.isoformat(),
                "report_as_of": checked_scope.report_as_of.isoformat(),
            },
            "observation_digests": sorted(seen.values()),
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return ScenarioBatchCoverageReport(
        scope=checked_scope,
        input_rows=len(observations),
        duplicate_rows=duplicate_rows,
        batch_digest="sha256:" + sha256(canonical.encode("ascii")).hexdigest(),
        scenarios=tuple(summaries),
    )
