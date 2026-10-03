from __future__ import annotations

from dataclasses import dataclass

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)


@dataclass(frozen=True)
class SyntheticReplayCase:
    scenario_id: str
    transaction: CanonicalTransaction
    intelligence: IntelligenceSnapshot
    expected_fraud: bool
    evidence_reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReplayMetrics:
    cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    explained_alerts: int

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def explainability_coverage(self) -> float:
        alerts = self.true_positives + self.false_positives
        return self.explained_alerts / alerts if alerts else 1.0


def replay(policy: DecisionPolicy, cases: tuple[SyntheticReplayCase, ...]) -> ReplayMetrics:
    service = DecisionService(policy)
    tp = fp = tn = fn = explained = 0

    for case in cases:
        decision = service.decide(
            case.transaction,
            case.intelligence,
            evidence_reason_codes=case.evidence_reason_codes,
        )
        alerted = decision.action not in {DecisionAction.ALLOW, DecisionAction.MONITOR}
        if alerted and case.expected_fraud:
            tp += 1
        elif alerted:
            fp += 1
        elif case.expected_fraud:
            fn += 1
        else:
            tn += 1

        if alerted and decision.reason_codes and decision.reason_codes != ["NO_HIGH_RISK_SIGNAL"]:
            explained += 1

    return ReplayMetrics(
        cases=len(cases),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        explained_alerts=explained,
    )
