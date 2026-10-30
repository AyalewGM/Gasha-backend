from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from math import isclose, isfinite
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

from gasha.domain.models import DecisionPolicy
from gasha.poc.ablation import AblationComparison, AblationReport
from gasha.poc.attribution import (
    SignalAttributionReport,
    SignalFamily,
    attribute_signals,
)
from gasha.poc.historical import (
    ALERT_ACTIONS,
    HistoricalReplayMetrics,
    HistoricalReplayReport,
    MissingTenantPolicyError,
)
from gasha.poc.incumbent import IncumbentComparison, compare_incumbent

# A schema identifier, not an evidence authenticity or approval indicator.
POC_REPORT_SCHEMA_VERSION: Literal["poc-report-2"] = "poc-report-2"


def _same_rate(actual: float | None, expected: float | None) -> bool:
    """Compare measured rates without accepting non-finite values or fake nulls."""

    if actual is None or expected is None:
        return actual is expected
    return isfinite(actual) and isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)


class RateEvidence(BaseModel):
    """Rate with a verified population and explicit zero-denominator semantics."""

    numerator: int = Field(ge=0, strict=True)
    denominator: int = Field(ge=0, strict=True)
    value: float | None
    undefined_reason: str | None = None

    @model_validator(mode="after")
    def verify_arithmetic(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("rate numerator exceeds denominator")
        if self.denominator == 0:
            if self.value is not None or not (
                self.undefined_reason and self.undefined_reason.strip()
            ):
                raise ValueError("zero-denominator rate requires null value and reason")
        elif self.undefined_reason is not None or not _same_rate(
            self.value, self.numerator / self.denominator
        ):
            raise ValueError("rate value must equal numerator / denominator")
        return self


class ConfusionSummary(BaseModel):
    true_positives: int = Field(ge=0, strict=True)
    false_positives: int = Field(ge=0, strict=True)
    true_negatives: int = Field(ge=0, strict=True)
    false_negatives: int = Field(ge=0, strict=True)
    recall: float | None
    precision: float | None
    false_positive_rate: float | None
    f1: float | None
    false_negative_rate: float | None
    rate_evidence: dict[str, RateEvidence]

    @model_validator(mode="after")
    def verify_confusion_rates(self) -> Self:
        tp, fp, tn, fn = (
            self.true_positives,
            self.false_positives,
            self.true_negatives,
            self.false_negatives,
        )
        expected = {
            "recall": (tp, tp + fn, "no_confirmed_fraud", self.recall),
            "precision": (tp, tp + fp, "no_labeled_alerts", self.precision),
            "f1": (2 * tp, 2 * tp + fp + fn, "no_positive_labels_or_alerts", self.f1),
            "false_positive_rate": (
                fp, fp + tn, "no_confirmed_legitimate", self.false_positive_rate
            ),
            "false_negative_rate": (fn, tp + fn, "no_confirmed_fraud", self.false_negative_rate),
        }
        if self.rate_evidence.keys() != expected.keys():
            raise ValueError("confusion rate_evidence must have exactly five required rates")
        for name, (numerator, denominator, empty_reason, reported) in expected.items():
            rate = self.rate_evidence[name]
            if (rate.numerator, rate.denominator) != (numerator, denominator):
                raise ValueError(f"{name} population contradicts confusion counts")
            if rate.undefined_reason != (empty_reason if denominator == 0 else None):
                raise ValueError(f"{name} undefined reason contradicts population")
            if not _same_rate(reported, rate.value):
                raise ValueError(f"{name} contradicts rate_evidence")
        return self


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
    share_of_detected_fraud: float | None
    share_of_detected_fraud_evidence: RateEvidence
    mean_risk_contribution: float | None
    max_risk_contribution: float | None
    reason_codes: list[str]

    @model_validator(mode="after")
    def verify_share(self) -> Self:
        if min(
            self.alerts_influenced,
            self.driving_alerts,
            self.true_positives_influenced,
            self.false_positives_influenced,
        ) < 0:
            raise ValueError("signal-family counts cannot be negative")
        if self.driving_alerts > self.alerts_influenced:
            raise ValueError("driving alerts exceed influenced alerts")
        if (
            self.true_positives_influenced + self.false_positives_influenced
            > self.alerts_influenced
        ):
            raise ValueError("classified influenced alerts exceed influenced alerts")
        rate = self.share_of_detected_fraud_evidence
        if (
            rate.numerator != self.true_positives_influenced
            or rate.undefined_reason != ("no_detected_fraud" if rate.denominator == 0 else None)
            or not _same_rate(rate.value, self.share_of_detected_fraud)
        ):
            raise ValueError("signal-family share contradicts its population evidence")
        return self


class AblationSummary(BaseModel):
    configuration_name: str
    removed_families: list[str]
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    recall: float | None
    precision: float | None
    false_positive_rate: float | None
    f1: float | None
    false_negative_rate: float | None
    rate_evidence: dict[str, RateEvidence]
    recall_delta: float | None
    incremental_recall_contribution: float | None
    recall_delta_undefined_reason: str | None
    false_positive_delta: int
    detections_lost: int

    @model_validator(mode="after")
    def verify_confusion_rates(self) -> Self:
        ConfusionSummary(
            true_positives=self.true_positives,
            false_positives=self.false_positives,
            true_negatives=self.true_negatives,
            false_negatives=self.false_negatives,
            recall=self.recall,
            precision=self.precision,
            false_positive_rate=self.false_positive_rate,
            f1=self.f1,
            false_negative_rate=self.false_negative_rate,
            rate_evidence=self.rate_evidence,
        )
        return self


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

    report_version: Literal["poc-report-2"]
    tenant_id: str = Field(min_length=1)
    dataset_id: str = Field(min_length=1)
    evaluation_period_start: datetime | None
    evaluation_period_end: datetime | None
    configuration_versions: list[str]
    policy_versions: list[str]
    rule_versions: list[str]
    model_versions: list[str]
    signal_policy_versions: list[str]
    total_events: int = Field(ge=0, strict=True)
    labeled_events: int = Field(ge=0, strict=True)
    unresolved_outcomes: int = Field(ge=0, strict=True)
    fraud_prevalence: float | None
    confusion: ConfusionSummary
    explainability_coverage: float | None
    explainability_coverage_evidence: RateEvidence
    latency: LatencySummary
    signal_attribution: list[SignalFamilySummary]
    ablation: list[AblationSummary]
    unique_detections: list[UniqueDetectionSummary]
    multi_signal: MultiSignalSummary
    incumbent_comparison: IncumbentSummary | None
    unmatched_outcomes: int = Field(ge=0, strict=True)
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def verify_report_arithmetic(self) -> Self:
        """Validate internal arithmetic, never provenance, identity or bank acceptance."""

        c = self.confusion
        if (
            self.total_events != self.labeled_events + self.unresolved_outcomes
            or self.labeled_events != (
                c.true_positives + c.false_positives + c.true_negatives + c.false_negatives
            )
        ):
            raise ValueError("POC event totals contradict confusion population")
        prevalence = (
            (c.true_positives + c.false_negatives) / self.labeled_events
            if self.labeled_events
            else None
        )
        if not _same_rate(self.fraud_prevalence, prevalence):
            raise ValueError("fraud prevalence contradicts labeled confusion population")

        explained = self.explainability_coverage_evidence
        if (
            not _same_rate(self.explainability_coverage, explained.value)
            or explained.undefined_reason
            != ("no_alerts" if explained.denominator == 0 else None)
            or explained.denominator < c.true_positives + c.false_positives
            or explained.denominator > self.total_events
        ):
            raise ValueError("explainability coverage contradicts alert population")

        for family in self.signal_attribution:
            if family.share_of_detected_fraud_evidence.denominator != c.true_positives:
                raise ValueError("signal-family share uses wrong detected-fraud population")

        for case in self.ablation:
            delta = (
                case.recall - c.recall
                if case.recall is not None and c.recall is not None
                else None
            )
            contribution = -delta if delta is not None else None
            if (
                not _same_rate(case.recall_delta, delta)
                or not _same_rate(case.incremental_recall_contribution, contribution)
                or case.recall_delta_undefined_reason
                != ("no_confirmed_fraud" if delta is None else None)
            ):
                raise ValueError("ablation recall delta contradicts full replay")

        incumbent = self.incumbent_comparison
        if incumbent is not None:
            counts = (
                incumbent.evaluated_cases,
                incumbent.missing_incumbent_outcomes,
                incumbent.both_detected,
                incumbent.gasha_only_detected,
                incumbent.incumbent_only_detected,
                incumbent.neither_detected,
                incumbent.incremental_confirmed_detection,
            )
            if (
                min(counts) < 0
                or incumbent.evaluated_cases
                != (
                    incumbent.both_detected + incumbent.gasha_only_detected
                    + incumbent.incumbent_only_detected + incumbent.neither_detected
                )
                or incumbent.evaluated_cases
                != sum((
                    incumbent.gasha.true_positives,
                    incumbent.gasha.false_positives,
                    incumbent.gasha.true_negatives,
                    incumbent.gasha.false_negatives,
                ))
                or incumbent.evaluated_cases
                != sum((
                    incumbent.incumbent.true_positives,
                    incumbent.incumbent.false_positives,
                    incumbent.incumbent.true_negatives,
                    incumbent.incumbent.false_negatives,
                ))
                or incumbent.evaluated_cases + incumbent.missing_incumbent_outcomes
                > self.labeled_events
                or incumbent.incremental_confirmed_detection > incumbent.gasha_only_detected
                or incumbent.both_detected + incumbent.gasha_only_detected
                != incumbent.gasha.true_positives + incumbent.gasha.false_positives
                or incumbent.both_detected + incumbent.incumbent_only_detected
                != incumbent.incumbent.true_positives + incumbent.incumbent.false_positives
                or incumbent.gasha.true_positives + incumbent.gasha.false_negatives
                != incumbent.incumbent.true_positives + incumbent.incumbent.false_negatives
                or incumbent.incremental_confirmed_detection > incumbent.gasha.true_positives
                or incumbent.incremental_confirmed_detection > incumbent.incumbent.false_negatives
            ):
                raise ValueError("incumbent comparison population is inconsistent")
        return self


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
    report_version: str = POC_REPORT_SCHEMA_VERSION,
    synthetic_dataset: bool = True,
) -> POCReport:
    """Assembles a tenant-scoped POC evidence report from replay outputs.

    All replayed results must belong to ``tenant_id``; a report can never
    aggregate tenants accidentally. Attribution is computed with each event's
    own tenant policy, and the incumbent comparison is only emitted when
    labeled incumbent outcomes exist.
    """

    if report_version != POC_REPORT_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported POC report schema version {report_version!r}; "
            f"expected {POC_REPORT_SCHEMA_VERSION!r}"
        )

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
    confusion = _confusion_summary(
        metrics.true_positives,
        metrics.false_positives,
        metrics.true_negatives,
        metrics.false_negatives,
    )
    all_alerts = sum(
        result.decision.action in ALERT_ACTIONS for result in report.results
    )
    explainability = _rate_evidence(
        metrics.explained_alerts,
        all_alerts,
        "no_alerts",
    )
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
    for name, rate in confusion.rate_evidence.items():
        if rate.value is None:
            derived_limitations.append(
                f"{name} undefined: {rate.undefined_reason}"
            )
    if explainability.value is None:
        derived_limitations.append(
            "explainability coverage undefined: no alerts"
        )
    if metrics.true_positives == 0:
        derived_limitations.append(
            "signal-family detected-fraud shares undefined: no detected fraud"
        )
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

    return POCReport(
        report_version=POC_REPORT_SCHEMA_VERSION,
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
        confusion=confusion,
        explainability_coverage=explainability.value,
        explainability_coverage_evidence=explainability,
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
                share_of_detected_fraud=_rate_evidence(
                    summary.true_positives_influenced,
                    metrics.true_positives,
                    "no_detected_fraud",
                ).value,
                share_of_detected_fraud_evidence=_rate_evidence(
                    summary.true_positives_influenced,
                    metrics.true_positives,
                    "no_detected_fraud",
                ),
                mean_risk_contribution=summary.mean_risk_contribution,
                max_risk_contribution=summary.max_risk_contribution,
                reason_codes=sorted(summary.reason_codes),
            )
            for family, summary in attribution.families.items()
        ],
        ablation=[
            _ablation_summary(comparison, metrics)
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
                gasha=_confusion_summary(
                    incumbent.gasha.true_positives,
                    incumbent.gasha.false_positives,
                    incumbent.gasha.true_negatives,
                    incumbent.gasha.false_negatives,
                ),
                incumbent=_confusion_summary(
                    incumbent.incumbent.true_positives,
                    incumbent.incumbent.false_positives,
                    incumbent.incumbent.true_negatives,
                    incumbent.incumbent.false_negatives,
                ),
            )
            if incumbent
            else None
        ),
        unmatched_outcomes=len(report.unmatched_outcomes),
        limitations=derived_limitations,
    )


def _rate_evidence(
    numerator: int, denominator: int, undefined_reason: str
) -> RateEvidence:
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError("inconsistent POC rate numerator/denominator")
    return RateEvidence(
        numerator=numerator,
        denominator=denominator,
        value=numerator / denominator if denominator else None,
        undefined_reason=undefined_reason if denominator == 0 else None,
    )


def _confusion_summary(
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
) -> ConfusionSummary:
    tp, fp, tn, fn = (
        true_positives,
        false_positives,
        true_negatives,
        false_negatives,
    )
    rates = {
        "recall": _rate_evidence(tp, tp + fn, "no_confirmed_fraud"),
        "precision": _rate_evidence(tp, tp + fp, "no_labeled_alerts"),
        "f1": _rate_evidence(
            2 * tp, 2 * tp + fp + fn, "no_positive_labels_or_alerts"
        ),
        "false_positive_rate": _rate_evidence(
            fp, fp + tn, "no_confirmed_legitimate"
        ),
        "false_negative_rate": _rate_evidence(
            fn, tp + fn, "no_confirmed_fraud"
        ),
    }
    return ConfusionSummary(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        recall=rates["recall"].value,
        precision=rates["precision"].value,
        false_positive_rate=rates["false_positive_rate"].value,
        f1=rates["f1"].value,
        false_negative_rate=rates["false_negative_rate"].value,
        rate_evidence=rates,
    )


def _ablation_summary(
    comparison: AblationComparison, full: HistoricalReplayMetrics
) -> AblationSummary:
    ablated = _confusion_summary(
        comparison.true_positives,
        comparison.false_positives,
        comparison.true_negatives,
        comparison.false_negatives,
    )
    full_recall = _rate_evidence(
        full.true_positives,
        full.true_positives + full.false_negatives,
        "no_confirmed_fraud",
    ).value
    recall_delta = (
        ablated.recall - full_recall
        if ablated.recall is not None and full_recall is not None
        else None
    )
    return AblationSummary(
        configuration_name=comparison.configuration_name,
        removed_families=[family.value for family in comparison.removed_families],
        true_positives=comparison.true_positives,
        false_positives=comparison.false_positives,
        true_negatives=comparison.true_negatives,
        false_negatives=comparison.false_negatives,
        recall=ablated.recall,
        precision=ablated.precision,
        false_positive_rate=ablated.false_positive_rate,
        f1=ablated.f1,
        false_negative_rate=ablated.false_negative_rate,
        rate_evidence=ablated.rate_evidence,
        recall_delta=recall_delta,
        incremental_recall_contribution=(
            -recall_delta if recall_delta is not None else None
        ),
        recall_delta_undefined_reason=(
            "no_confirmed_fraud" if recall_delta is None else None
        ),
        false_positive_delta=comparison.false_positive_delta,
        detections_lost=comparison.detections_lost,
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
