from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from pydantic import BaseModel, Field

from gasha.domain.models import DecisionPolicy
from gasha.poc.ablation import AblationReport
from gasha.poc.attribution import (
    SignalAttributionReport,
    SignalFamily,
    attribute_signals,
)
from gasha.poc.historical import (
    HistoricalReplayReport,
    MissingTenantPolicyError,
)
from gasha.poc.incumbent import IncumbentComparison, compare_incumbent


class ConfusionSummary(BaseModel):
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    recall: float
    precision: float
    false_positive_rate: float


class LatencySummary(BaseModel):
    mean_decision_latency_seconds: float | None = None
    mean_detection_lead_time_seconds: float | None = None
    mean_processing_latency_ms: float | None = None
    median_processing_latency_ms: float | None = None
    p95_processing_latency_ms: float | None = None
    p99_processing_latency_ms: float | None = None
    max_processing_latency_ms: float | None = None


class SignalFamilySummary(BaseModel):
    family: str
    alerts_influenced: int
    driving_alerts: int
    true_positives_influenced: int
    false_positives_influenced: int
    share_of_detected_fraud: float
    mean_risk_contribution: float | None
    max_risk_contribution: float | None
    reason_codes: list[str]


class AblationSummary(BaseModel):
    configuration_name: str
    removed_families: list[str]
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    recall: float
    precision: float
    false_positive_rate: float
    recall_delta: float
    incremental_recall_contribution: float
    false_positive_delta: int
    detections_lost: int


class UniqueDetectionSummary(BaseModel):
    family: str
    reason: str
    detections: int
    event_ids: list[str]


class MultiSignalSummary(BaseModel):
    detections: int
    family_combination_counts: dict[str, int]
    named_combination_detections: dict[str, int]


class IncumbentSummary(BaseModel):
    evaluated_cases: int
    missing_incumbent_outcomes: int
    both_detected: int
    gasha_only_detected: int
    incumbent_only_detected: int
    neither_detected: int
    incremental_confirmed_detection: int
    gasha: ConfusionSummary
    incumbent: ConfusionSummary


class POCReport(BaseModel):
    """Machine-readable POC evidence report for one tenant and dataset.

    ``limitations`` is intentionally required and non-empty: every report must
    state why its measurements should not be overstated (synthetic data,
    missing labels, tenant-local graph scope, missing incumbent outcomes, and
    similar caveats supplied by the caller or derived here).
    """

    report_version: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    dataset_id: str = Field(min_length=1)
    evaluation_period_start: datetime | None
    evaluation_period_end: datetime | None
    configuration_versions: list[str]
    policy_versions: list[str]
    rule_versions: list[str]
    model_versions: list[str]
    signal_policy_versions: list[str]
    total_events: int
    labeled_events: int
    unresolved_outcomes: int
    fraud_prevalence: float | None
    confusion: ConfusionSummary
    explainability_coverage: float
    latency: LatencySummary
    signal_attribution: list[SignalFamilySummary]
    ablation: list[AblationSummary]
    unique_detections: list[UniqueDetectionSummary]
    multi_signal: MultiSignalSummary
    incumbent_comparison: IncumbentSummary | None
    unmatched_outcomes: int
    limitations: list[str] = Field(min_length=1)


def build_poc_report(
    *,
    tenant_id: str,
    dataset_id: str,
    report: HistoricalReplayReport,
    policies: Mapping[str, DecisionPolicy],
    attribution: SignalAttributionReport | None = None,
    ablation: AblationReport | None = None,
    incumbent: IncumbentComparison | None = None,
    limitations: Sequence[str] = (),
    report_version: str = "poc-report-1",
    synthetic_dataset: bool = True,
) -> POCReport:
    """Assembles a tenant-scoped POC evidence report from replay outputs.

    All replayed results must belong to ``tenant_id``; a report can never
    aggregate tenants accidentally. Attribution is computed with each event's
    own tenant policy, and the incumbent comparison is only emitted when
    labeled incumbent outcomes exist.
    """

    for result in report.results:
        if result.decision.tenant_id != tenant_id:
            raise MissingTenantPolicyError(
                "POC report is tenant-scoped; "
                f"result {result.decision.event_id} belongs to "
                f"{result.decision.tenant_id!r}, not {tenant_id!r}"
            )
    if tenant_id not in policies and report.results:
        raise MissingTenantPolicyError(
            f"no decision policy registered for tenant {tenant_id!r}"
        )

    metrics = report.metrics
    if attribution is None:
        attribution = attribute_signals(report.results, policies)
    if incumbent is None and any(
        result.event.incumbent_outcome is not None
        for result in report.results
    ):
        incumbent = compare_incumbent(report.results)

    occurred = sorted(
        result.event.transaction.occurred_at for result in report.results
    )
    fraud_labeled = metrics.true_positives + metrics.false_negatives
    fraud_prevalence = (
        fraud_labeled / metrics.labeled_cases if metrics.labeled_cases else None
    )

    derived_limitations: list[str] = list(limitations)
    if synthetic_dataset:
        derived_limitations.append(
            "dataset is synthetic or sanitized; results are not production "
            "outcomes"
        )
    if metrics.unlabeled_cases:
        derived_limitations.append(
            f"incomplete outcome labels: {metrics.unlabeled_cases} events "
            "unlabeled"
        )
    if incumbent is None:
        derived_limitations.append(
            "incumbent control outcomes were not supplied; no incumbent "
            "comparison is possible"
        )
    elif incumbent.missing_incumbent_outcomes:
        derived_limitations.append(
            f"missing incumbent decisions for "
            f"{incumbent.missing_incumbent_outcomes} labeled events"
        )
    if report.unmatched_outcomes:
        derived_limitations.append(
            f"{len(report.unmatched_outcomes)} outcome records did not match "
            "any replayed event"
        )
    derived_limitations.append(
        "graph intelligence is limited to tenant-observed transactions; no "
        "authorized cross-bank data was used"
    )
    derived_limitations.append(
        "metrics are measurements on this dataset, not causal or comparative "
        "claims about other fraud platforms"
    )
    derived_limitations.append(
        "historical decision latency and detection lead time are unavailable: "
        "replay execution timestamps are not original bank decision or alert "
        "timestamps; only replay processing latency is measured"
    )

    return POCReport(
        report_version=report_version,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        evaluation_period_start=occurred[0] if occurred else None,
        evaluation_period_end=occurred[-1] if occurred else None,
        configuration_versions=sorted(
            {
                result.decision.configuration_version
                for result in report.results
            }
        ),
        policy_versions=sorted(
            {result.decision.policy_version for result in report.results}
        ),
        rule_versions=sorted(
            {result.decision.rule_version for result in report.results}
        ),
        model_versions=sorted(
            {
                result.decision.model_version
                for result in report.results
                if result.decision.model_version is not None
            }
        ),
        signal_policy_versions=sorted(
            {
                version
                for result in report.results
                for version in result.event.signal_policy_versions
            }
        ),
        total_events=metrics.cases,
        labeled_events=metrics.labeled_cases,
        unresolved_outcomes=metrics.unlabeled_cases,
        fraud_prevalence=fraud_prevalence,
        confusion=ConfusionSummary(
            true_positives=metrics.true_positives,
            false_positives=metrics.false_positives,
            true_negatives=metrics.true_negatives,
            false_negatives=metrics.false_negatives,
            recall=metrics.recall,
            precision=metrics.precision,
            false_positive_rate=metrics.false_positive_rate,
        ),
        explainability_coverage=metrics.explainability_coverage,
        latency=LatencySummary(
            mean_decision_latency_seconds=metrics.mean_decision_latency_seconds,
            mean_detection_lead_time_seconds=(
                metrics.mean_detection_lead_time_seconds
            ),
            mean_processing_latency_ms=metrics.mean_processing_latency_ms,
            median_processing_latency_ms=metrics.median_processing_latency_ms,
            p95_processing_latency_ms=metrics.p95_processing_latency_ms,
            p99_processing_latency_ms=metrics.p99_processing_latency_ms,
            max_processing_latency_ms=metrics.max_processing_latency_ms,
        ),
        signal_attribution=[
            SignalFamilySummary(
                family=family.value,
                alerts_influenced=summary.alerts_influenced,
                driving_alerts=summary.driving_alerts,
                true_positives_influenced=summary.true_positives_influenced,
                false_positives_influenced=summary.false_positives_influenced,
                share_of_detected_fraud=summary.share_of_detected_fraud,
                mean_risk_contribution=summary.mean_risk_contribution,
                max_risk_contribution=summary.max_risk_contribution,
                reason_codes=sorted(summary.reason_codes),
            )
            for family, summary in attribution.families.items()
        ],
        ablation=[
            AblationSummary(
                configuration_name=comparison.configuration_name,
                removed_families=[
                    family.value for family in comparison.removed_families
                ],
                true_positives=comparison.true_positives,
                false_positives=comparison.false_positives,
                true_negatives=comparison.true_negatives,
                false_negatives=comparison.false_negatives,
                recall=comparison.recall,
                precision=comparison.precision,
                false_positive_rate=comparison.false_positive_rate,
                recall_delta=comparison.recall_delta,
                incremental_recall_contribution=(
                    comparison.incremental_recall_contribution
                ),
                false_positive_delta=comparison.false_positive_delta,
                detections_lost=comparison.detections_lost,
            )
            for comparison in (ablation.comparisons if ablation else ())
        ],
        unique_detections=_unique_detection_summary(ablation),
        multi_signal=MultiSignalSummary(
            detections=len(attribution.multi_signal.detections),
            family_combination_counts={
                "+".join(family.value for family in families): count
                for families, count in (
                    attribution.multi_signal.family_combination_counts.items()
                )
            },
            named_combination_detections=dict(
                attribution.multi_signal.named_combination_detections
            ),
        ),
        incumbent_comparison=(
            IncumbentSummary(
                evaluated_cases=incumbent.evaluated_cases,
                missing_incumbent_outcomes=(
                    incumbent.missing_incumbent_outcomes
                ),
                both_detected=incumbent.both_detected,
                gasha_only_detected=incumbent.gasha_only_detected,
                incumbent_only_detected=incumbent.incumbent_only_detected,
                neither_detected=incumbent.neither_detected,
                incremental_confirmed_detection=(
                    incumbent.incremental_confirmed_detection
                ),
                gasha=ConfusionSummary(
                    true_positives=incumbent.gasha.true_positives,
                    false_positives=incumbent.gasha.false_positives,
                    true_negatives=incumbent.gasha.true_negatives,
                    false_negatives=incumbent.gasha.false_negatives,
                    recall=incumbent.gasha.recall,
                    precision=incumbent.gasha.precision,
                    false_positive_rate=incumbent.gasha.false_positive_rate,
                ),
                incumbent=ConfusionSummary(
                    true_positives=incumbent.incumbent.true_positives,
                    false_positives=incumbent.incumbent.false_positives,
                    true_negatives=incumbent.incumbent.true_negatives,
                    false_negatives=incumbent.incumbent.false_negatives,
                    recall=incumbent.incumbent.recall,
                    precision=incumbent.incumbent.precision,
                    false_positive_rate=incumbent.incumbent.false_positive_rate,
                ),
            )
            if incumbent
            else None
        ),
        unmatched_outcomes=len(report.unmatched_outcomes),
        limitations=derived_limitations,
    )


def _unique_detection_summary(
    ablation: AblationReport | None,
) -> list[UniqueDetectionSummary]:
    if ablation is None:
        return []
    grouped: dict[SignalFamily, list[str]] = {}
    reasons: dict[SignalFamily, str] = {}
    for detection in ablation.unique_detections:
        grouped.setdefault(detection.family, []).append(
            str(detection.event_id)
        )
        reasons[detection.family] = detection.reason.value
    return [
        UniqueDetectionSummary(
            family=family.value,
            reason=reasons[family],
            detections=len(event_ids),
            event_ids=sorted(event_ids),
        )
        for family, event_ids in sorted(
            grouped.items(), key=lambda item: item[0].value
        )
    ]
