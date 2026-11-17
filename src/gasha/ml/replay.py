"""Offline model-versus-rules replay evaluation.

This is the promotion gate for candidate models: the same matured-label
cohort is replayed through the deterministic rules fusion and through the
model-backed fused scorer, and both reports feed the existing confusion
metrics. The evaluation is fully offline — it consumes
``HistoricalTransactionEvent`` point-in-time snapshots and never touches a
protected route, matching the #144 containment boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from math import isfinite
from typing import Any

from gasha.decision.fused import FusedDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import DecisionPolicy
from gasha.ml.scorer import ModelScorer
from gasha.poc.historical import (
    DecisionBackend,
    HistoricalReplayMetrics,
    HistoricalReplayReport,
    HistoricalTransactionEvent,
    replay_historical,
)


class ModelReplayRejected(ValueError):
    """A model replay could not resolve its scorer or inputs."""


def model_service_factory(
    resolve: Callable[[str], ModelScorer],
) -> Callable[[DecisionPolicy], DecisionBackend]:
    """Builds a replay backend factory bound to a scorer resolver.

    Policies without ``model_version`` keep the deterministic rules fusion;
    model policies bind the resolved scorer so a decision can never carry a
    score from an unexpected artifact version.
    """

    def factory(policy: DecisionPolicy) -> DecisionBackend:
        if policy.model_version is None:
            return DecisionService(policy)
        scorer = resolve(policy.model_version)
        return FusedDecisionService(policy, scorer)

    return factory


def replay_model(
    events: Sequence[HistoricalTransactionEvent],
    policies: Mapping[str, DecisionPolicy],
    resolve: Callable[[str], ModelScorer],
    *,
    clock: Callable[[], datetime] | None = None,
) -> HistoricalReplayReport:
    """Replays a matured cohort through model-backed decision services."""
    try:
        return replay_historical(
            events,
            policies,
            clock=clock,
            service_factory=model_service_factory(resolve),
        )
    except Exception as exc:
        raise ModelReplayRejected("model replay could not complete") from exc


@dataclass(frozen=True, slots=True)
class PromotionEvaluation:
    """Offline metrics and independently reproducible maturity evidence.

    Undefined rates and deltas use None, never a synthetic zero.
    """
    rules: HistoricalReplayMetrics
    model: HistoricalReplayMetrics
    label_cutoff: datetime
    total_events: int
    matured_labeled_events: int
    masked_unconfirmed_count: int
    masked_late_count: int
    fraud_positive_denominator: int
    legitimate_negative_denominator: int
    candidate_model_versions: tuple[tuple[str, str], ...]
    evidence_digest: str
    rules_fpr: float | None
    model_fpr: float | None
    rules_recall: float | None
    model_recall: float | None
    rules_precision: float | None
    model_precision: float | None
    fpr_delta: float | None
    recall_delta: float | None
    precision_delta: float | None
    non_promotion_reason: str | None
    promotes: bool


def _digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        .encode("utf-8")
    ).hexdigest()


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _delta(candidate: float | None, incumbent: float | None) -> float | None:
    if incumbent is None or candidate is None:
        return None
    return candidate - incumbent


def evaluate_candidate_model(
    events: Sequence[HistoricalTransactionEvent],
    *,
    label_cutoff: datetime,
    incumbent_policies: Mapping[str, DecisionPolicy],
    candidate_policies: Mapping[str, DecisionPolicy],
    resolve: Callable[[str], ModelScorer],
    clock: Callable[[], datetime] | None = None,
) -> PromotionEvaluation:
    """Compare one pinned cohort with labels confirmed on or before cutoff.

    Unconfirmed and late outcomes remain in decisions, not in confusion
    denominators. This synthetic-only gate never activates model serving.
    """
    if (
        not isinstance(label_cutoff, datetime)
        or label_cutoff.tzinfo is None
        or label_cutoff.utcoffset() is None
    ):
        raise ModelReplayRejected("timezone-aware label cutoff required")
    cutoff = label_cutoff.astimezone(UTC)

    # Verify caller-controlled populations and policies are unchanged between
    # the two replays, even if a scorer callback or stateful sequence mutates.
    def source_snapshot() -> dict[str, Any]:
        return {
            "events": [event.model_dump(mode="json") for event in events],
            "incumbent": {
                k: v.model_dump(mode="json")
                for k, v in sorted(incumbent_policies.items())
            },
            "candidate": {
                k: v.model_dump(mode="json")
                for k, v in sorted(candidate_policies.items())
            },
        }

    try:
        source = source_snapshot()
        source_digest = _digest(source)
        original_events = tuple(
            HistoricalTransactionEvent.model_validate(row)
            for row in source["events"]
        )
        incumbent = {
            k: DecisionPolicy.model_validate(v)
            for k, v in source["incumbent"].items()
        }
        candidate = {
            k: DecisionPolicy.model_validate(v)
            for k, v in source["candidate"].items()
        }
    except (TypeError, ValueError, AttributeError) as exc:
        raise ModelReplayRejected("invalid comparison inputs") from exc

    def verify_unchanged() -> None:
        try:
            if _digest(source_snapshot()) != source_digest:
                raise ModelReplayRejected("replay inputs mutated")
        except (TypeError, ValueError, AttributeError) as exc:
            raise ModelReplayRejected("replay inputs mutated") from exc

    tenants = {event.transaction.tenant_id for event in original_events}
    if set(incumbent) != set(candidate) or not tenants.issubset(incumbent):
        raise ModelReplayRejected("inconsistent tenant policy coverage")
    if any(incumbent[tenant].model_version is not None for tenant in tenants):
        raise ModelReplayRejected("incumbent must be rules-only")
    if any(not candidate[tenant].model_version for tenant in tenants):
        raise ModelReplayRejected("candidate must bind an explicit model")

    masked: list[HistoricalTransactionEvent] = []
    unconfirmed = late = 0
    for event in original_events:
        label = event.label
        if label is None:
            masked.append(event)
        elif label.confirmed_at is None:
            unconfirmed += 1
            masked.append(event.model_copy(update={"label": None}))
        elif label.confirmed_at.astimezone(UTC) > cutoff:
            late += 1
            masked.append(event.model_copy(update={"label": None}))
        else:
            masked.append(event)

    # Deserialize a fresh object graph for each backend to preclude any
    # shared mutable Event/Label/Intelligence object across the replays.
    masked_records = tuple(row.model_dump(mode="json") for row in masked)
    def replay_events() -> tuple[HistoricalTransactionEvent, ...]:
        return tuple(
            HistoricalTransactionEvent.model_validate(row)
            for row in masked_records
        )

    versions = tuple(
        sorted((tenant, candidate[tenant].model_version or "") for tenant in tenants)
    )
    digest = _digest({
        "cutoff": cutoff.isoformat(),
        "original_events": source["events"],
        "masked_events": masked_records,
        "incumbent": source["incumbent"],
        "candidate": source["candidate"],
        "candidate_versions": versions,
    })

    rules = replay_historical(replay_events(), incumbent, clock=clock)
    verify_unchanged()
    model = replay_model(replay_events(), candidate, resolve, clock=clock)
    verify_unchanged()

    def identities(report: HistoricalReplayReport) -> tuple[tuple[str, str, str], ...]:
        return tuple((
            row.event.transaction.tenant_id,
            str(row.event.transaction.event_id),
            _digest(row.event.label.model_dump(mode="json"))
            if row.event.label is not None else "",
        ) for row in report.results)

    if (
        len(rules.results) != len(masked)
        or identities(rules) != identities(model)
        or any(
            row.decision.model_version
            != candidate[row.event.transaction.tenant_id].model_version
            for row in model.results
        )
    ):
        raise ModelReplayRejected("model identity or cohort mismatch")

    rm, mm = rules.metrics, model.metrics
    positives = sum(
        row.label.is_fraud for row in masked if row.label is not None
    )
    negatives = sum(
        not row.label.is_fraud for row in masked if row.label is not None
    )
    matured = positives + negatives
    if any((
        rm.cases != len(masked),
        mm.cases != len(masked),
        rm.labeled_cases != matured,
        mm.labeled_cases != matured,
        rm.true_positives + rm.false_negatives != positives,
        mm.true_positives + mm.false_negatives != positives,
        rm.true_negatives + rm.false_positives != negatives,
        mm.true_negatives + mm.false_positives != negatives,
    )):
        raise ModelReplayRejected("different matured-label denominators")

    rules_fpr = _rate(rm.false_positives, negatives)
    model_fpr = _rate(mm.false_positives, negatives)
    rules_recall = _rate(rm.true_positives, positives)
    model_recall = _rate(mm.true_positives, positives)
    rules_precision = _rate(rm.true_positives, rm.true_positives + rm.false_positives)
    model_precision = _rate(mm.true_positives, mm.true_positives + mm.false_positives)
    fpr_delta = _delta(model_fpr, rules_fpr)
    recall_delta = _delta(model_recall, rules_recall)
    precision_delta = _delta(model_precision, rules_precision)
    rates = (rules_fpr, model_fpr, rules_recall, model_recall,
             rules_precision, model_precision, fpr_delta, recall_delta, precision_delta)
    # Return an auditable refusal instead of silently treating undefined
    # precision as zero. Even if FPR improves at unchanged zero recall, a
    # candidate that detects no matured fraud must not auto-promote.
    non_promotion_reason: str | None
    if positives == 0 or negatives == 0 or matured == 0:
        non_promotion_reason = "insufficient_matured_classes"
    elif mm.true_positives == 0:
        non_promotion_reason = "candidate_detects_no_fraud"
    elif model_precision is None:
        non_promotion_reason = "candidate_precision_undefined"
    elif not all(value is not None and isfinite(value) for value in rates):
        non_promotion_reason = "undefined_comparison_metrics"
    elif recall_delta is None or recall_delta < 0.0:
        non_promotion_reason = "recall_regressed"
    elif fpr_delta is None or fpr_delta >= 0.0:
        non_promotion_reason = "fpr_not_improved"
    else:
        non_promotion_reason = None
    promotes = non_promotion_reason is None
    return PromotionEvaluation(
        rules=rm,
        model=mm,
        label_cutoff=cutoff,
        total_events=len(masked),
        matured_labeled_events=matured,
        masked_unconfirmed_count=unconfirmed,
        masked_late_count=late,
        fraud_positive_denominator=positives,
        legitimate_negative_denominator=negatives,
        candidate_model_versions=versions,
        evidence_digest=digest,
        rules_fpr=rules_fpr,
        model_fpr=model_fpr,
        rules_recall=rules_recall,
        model_recall=model_recall,
        rules_precision=rules_precision,
        model_precision=model_precision,
        fpr_delta=fpr_delta,
        recall_delta=recall_delta,
        precision_delta=precision_delta,
        non_promotion_reason=non_promotion_reason,
        promotes=promotes,
    )
