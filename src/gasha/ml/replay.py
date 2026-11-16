"""Offline model-versus-rules replay evaluation.

This is the promotion gate for candidate models: the same matured-label
cohort is replayed through the deterministic rules fusion and through the
model-backed fused scorer, and both reports feed the existing confusion
metrics. The evaluation is fully offline — it consumes
``HistoricalTransactionEvent`` point-in-time snapshots and never touches a
protected route, matching the #144 containment boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

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
    """Side-by-side rules/model metrics with a promotion recommendation.

    ``promotes`` holds only when the candidate model does not regress
    recall *and* strictly reduces the false-positive rate — the UC-05
    criterion. All counts are visible so a reviewer can inspect the full
    confusion populations rather than trusting the summary verdict.
    """

    rules: HistoricalReplayMetrics
    model: HistoricalReplayMetrics
    fpr_delta: float
    recall_delta: float
    precision_delta: float
    promotes: bool


def evaluate_candidate_model(
    events: Sequence[HistoricalTransactionEvent],
    *,
    incumbent_policies: Mapping[str, DecisionPolicy],
    candidate_policies: Mapping[str, DecisionPolicy],
    resolve: Callable[[str], ModelScorer],
    clock: Callable[[], datetime] | None = None,
) -> PromotionEvaluation:
    """Replays one cohort through the incumbent rules and the candidate
    model policies, then compares matured-label confusion metrics.

    The incumbent replay uses the currently deployed rules policies and the
    candidate replay uses the model-bound policies (``model_version`` plus
    manifest-derived thresholds) — the honest UC-05 comparison. Both consume
    identical events; the cohort must contain matured labels or the
    comparison reports zeros.
    """
    rules = replay_historical(events, incumbent_policies, clock=clock)
    model = replay_model(events, candidate_policies, resolve, clock=clock)
    rules_metrics = rules.metrics
    model_metrics = model.metrics
    fpr_delta = model_metrics.false_positive_rate - rules_metrics.false_positive_rate
    recall_delta = model_metrics.recall - rules_metrics.recall
    precision_delta = model_metrics.precision - rules_metrics.precision
    promotes = (
        model_metrics.labeled_cases > 0
        and fpr_delta < 0.0
        and recall_delta >= 0.0
    )
    return PromotionEvaluation(
        rules=rules_metrics,
        model=model_metrics,
        fpr_delta=fpr_delta,
        recall_delta=recall_delta,
        precision_delta=precision_delta,
        promotes=promotes,
    )
