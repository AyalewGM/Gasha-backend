"""Offline model-vs-rules replay evaluation tests (UC-05 promotion gate)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.ml.replay import (
    ModelReplayRejected,
    evaluate_candidate_model,
    replay_model,
)
from gasha.ml.scorer import ScoringError
from gasha.poc.historical import ConfirmedOutcomeLabel, HistoricalTransactionEvent

AT = datetime(2026, 1, 1, 9, tzinfo=UTC)
CUTOFF = AT + timedelta(days=30)


class CorroborationScorer:
    """Fixture model: alerts only when at least two signals are elevated.

    Mimics what a learned model discovers on the crafted cohort: the rules
    fusion fires on any single spiking signal, while corroborated risk is
    the actual fraud pattern.
    """

    def __init__(self, model_version: str = "model-1") -> None:
        self._version = model_version

    @property
    def model_version(self) -> str:
        return self._version

    def score(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> float:
        ordered = sorted(
            float(getattr(intelligence, name))
            for name in IntelligenceSnapshot.model_fields
        )
        return ordered[-2] if ordered[-2] >= 0.7 else 0.05

    def contributions(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> Mapping[str, float]:
        return {}


def event(
    number: int,
    *,
    fraud: bool,
    lone_spike: bool = False,
) -> HistoricalTransactionEvent:
    occurred = AT + timedelta(minutes=number)
    if fraud:
        snapshot = IntelligenceSnapshot(
            **{name: 0.8 for name in IntelligenceSnapshot.model_fields}
        )
    elif lone_spike:
        # The classic rules false positive: one spiking signal, benign rest.
        snapshot = IntelligenceSnapshot(velocity_risk=0.95)
    else:
        snapshot = IntelligenceSnapshot()
    return HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id="tenant-a",
            event_id=UUID(int=number + 1),
            occurred_at=occurred,
            channel="mobile",
            transaction_type="transfer",
            amount=Decimal(500),
            currency="ETB",
            sender_customer_id=f"customer-{number}",
            sender_account_id=f"account-{number}",
            beneficiary_id=f"beneficiary-{number}",
            beneficiary_type=BeneficiaryType.EXTERNAL,
            destination_institution_id="external-bank",
            correlation_id=f"corr-{number}",
        ),
        intelligence=snapshot,
        label=ConfirmedOutcomeLabel(
            is_fraud=fraud,
            label_source="synthetic-analyst",
            confirmed_at=occurred + timedelta(days=5),
        ),
    )


def cohort() -> list[HistoricalTransactionEvent]:
    return (
        [event(n, fraud=True) for n in range(4)]
        + [event(n, fraud=False, lone_spike=True) for n in range(4, 8)]
        + [event(n, fraud=False) for n in range(8, 16)]
    )


def policies(model_version: str | None = "model-1") -> dict[str, DecisionPolicy]:
    return {
        "tenant-a": DecisionPolicy(
            configuration_version="config-1",
            policy_version="policy-1",
            rule_version="rules-1",
            model_version=model_version,
        )
    }


def incumbent() -> dict[str, DecisionPolicy]:
    """Currently deployed rules policy (no model binding)."""
    return policies(model_version=None)


def resolver(version: str) -> CorroborationScorer:
    if version != "model-1":
        raise ScoringError("unknown artifact")
    return CorroborationScorer(model_version=version)


def test_replay_model_uses_fused_backend_for_model_policies() -> None:
    report = replay_model(cohort(), policies(), resolver)
    assert all(
        result.decision.model_version == "model-1" for result in report.results
    )
    assert report.metrics.labeled_cases == 16


def test_replay_model_uses_rules_when_policy_has_no_model() -> None:
    report = replay_model(cohort(), policies(model_version=None), resolver)
    assert all(
        result.decision.model_version is None for result in report.results
    )
    # Rules fire on lone-spike legitimate events: 4 false positives.
    assert report.metrics.false_positives == 4


def test_unresolvable_model_version_fails_closed() -> None:
    with pytest.raises(ModelReplayRejected):
        replay_model(cohort(), policies(model_version="model-absent"), resolver)


def test_candidate_evaluation_reports_fpr_reduction() -> None:
    evaluation = evaluate_candidate_model(
        label_cutoff=CUTOFF,
        cohort(),
        incumbent_policies=incumbent(),
        candidate_policies=policies(),
        resolve=resolver,
    )
    # Rules: 4 lone-spike FPs over 12 legit negatives; model: none.
    assert evaluation.rules.false_positives == 4
    assert evaluation.model.false_positives == 0
    assert evaluation.fpr_delta < 0.0
    # Recall preserved: all 4 fraud events still alert.
    assert evaluation.rules.recall == 1.0
    assert evaluation.model.recall == 1.0
    assert evaluation.recall_delta == 0.0
    assert evaluation.precision_delta > 0.0
    assert evaluation.promotes is True


def test_no_promotion_when_model_regresses_recall() -> None:
    class BlindScorer(CorroborationScorer):
        def score(self, transaction, intelligence) -> float:
            return 0.0  # suppresses every alert: no FPs but no TPs either

    evaluation = evaluate_candidate_model(
        label_cutoff=CUTOFF,
        cohort(),
        incumbent_policies=incumbent(),
        candidate_policies=policies(),
        resolve=lambda _v: BlindScorer(model_version="model-1"),
    )
    assert evaluation.fpr_delta < 0.0
    assert evaluation.recall_delta == -1.0
    assert evaluation.promotes is False


def test_no_promotion_without_labeled_cases() -> None:
    unlabeled = [
        item.model_copy(update={"label": None}) for item in cohort()
    ]
    evaluation = evaluate_candidate_model(
        label_cutoff=CUTOFF,
        unlabeled,
        incumbent_policies=incumbent(),
        candidate_policies=policies(),
        resolve=resolver,
    )
    assert evaluation.model.labeled_cases == 0
    assert evaluation.promotes is False


def test_mixed_label_maturity_masks_only_confusion_denominators() -> None:
    items = cohort()
    # Two real mature classes remain; a later fraud and an unconfirmed
    # legitimate outcome are still scored, but cannot enter confusion rates.
    items[0] = items[0].model_copy(update={
        "label": ConfirmedOutcomeLabel(
            is_fraud=True, label_source="synthetic",
            confirmed_at=CUTOFF + timedelta(seconds=1),
        )
    })
    items[4] = items[4].model_copy(update={
        "label": ConfirmedOutcomeLabel(
            is_fraud=False, label_source="synthetic",
            confirmed_at=None,
        )
    })
    evaluation = evaluate_candidate_model(
        items, label_cutoff=CUTOFF, incumbent_policies=incumbent(),
        candidate_policies=policies(), resolve=resolver,
    )
    assert evaluation.total_events == 16
    assert evaluation.matured_labeled_events == 14
    assert evaluation.masked_late_count == 1
    assert evaluation.masked_unconfirmed_count == 1
    assert evaluation.fraud_positive_denominator == 3
    assert evaluation.legitimate_negative_denominator == 11
    assert evaluation.rules.cases == evaluation.model.cases == 16
    assert evaluation.rules.unlabeled_cases == evaluation.model.unlabeled_cases == 2
    assert evaluation.promotes


def test_cutoff_inclusive_and_stable_evidence_digest() -> None:
    records = cohort()
    # Confirmed exactly at the cutoff must be eligible.
    records[0] = records[0].model_copy(update={
        "label": ConfirmedOutcomeLabel(
            is_fraud=True, label_source="synthetic", confirmed_at=CUTOFF,
        )
    })
    first = evaluate_candidate_model(
        records, label_cutoff=CUTOFF, incumbent_policies=incumbent(),
        candidate_policies=policies(), resolve=resolver,
    )
    second = evaluate_candidate_model(
        records, label_cutoff=CUTOFF, incumbent_policies=incumbent(),
        candidate_policies=policies(), resolve=resolver,
    )
    assert first == second
    assert len(first.evidence_digest) == 64
    assert first.matured_labeled_events == 16
    assert first.candidate_model_versions == (("tenant-a", "model-1"),)


@pytest.mark.parametrize("selection", ["none", "unconfirmed", "late", "legit", "fraud"])
def test_missing_or_one_class_labels_never_promote(selection: str) -> None:
    records = cohort()
    if selection == "none":
        records = []
    elif selection == "unconfirmed":
        records = [
            record.model_copy(update={
                "label": ConfirmedOutcomeLabel(
                    is_fraud=record.label.is_fraud,
                    label_source="synthetic", confirmed_at=None,
                )
            })
            for record in records if record.label is not None
        ]
    elif selection == "late":
        records = [
            record.model_copy(update={
                "label": ConfirmedOutcomeLabel(
                    is_fraud=record.label.is_fraud,
                    label_source="synthetic",
                    confirmed_at=CUTOFF + timedelta(seconds=1),
                )
            })
            for record in records if record.label is not None
        ]
    elif selection == "legit":
        records = [record for record in records if not record.label.is_fraud]
    else:
        records = [record for record in records if record.label.is_fraud]
    evaluation = evaluate_candidate_model(
        records, label_cutoff=CUTOFF, incumbent_policies=incumbent(),
        candidate_policies=policies(), resolve=resolver,
    )
    assert not evaluation.promotes
    assert evaluation.matured_labeled_events == (
        0 if selection in {"none", "unconfirmed", "late"} else len(records)
    )
    if selection == "legit":
        assert evaluation.rules_recall is None
        assert evaluation.recall_delta is None
    if selection == "fraud":
        assert evaluation.rules_fpr is None
        assert evaluation.fpr_delta is None


def test_naive_cutoff_and_missing_candidate_model_fail_closed() -> None:
    with pytest.raises(ModelReplayRejected, match="cutoff"):
        evaluate_candidate_model(
            cohort(), label_cutoff=CUTOFF.replace(tzinfo=None),
            incumbent_policies=incumbent(), candidate_policies=policies(),
            resolve=resolver,
        )
    with pytest.raises(ModelReplayRejected, match="model"):
        evaluate_candidate_model(
            cohort(), label_cutoff=CUTOFF,
            incumbent_policies=incumbent(),
            candidate_policies=policies(model_version=None),
            resolve=resolver,
        )
    with pytest.raises(ModelReplayRejected, match="tenant"):
        evaluate_candidate_model(
            cohort(), label_cutoff=CUTOFF,
            incumbent_policies=incumbent(),
            candidate_policies={"wrong-tenant": list(policies().values())[0]},
            resolve=resolver,
        )


def test_mutating_input_during_replay_rejected() -> None:
    records = cohort()

    def changing_resolver(version: str) -> CorroborationScorer:
        records.pop()
        return resolver(version)

    with pytest.raises(ModelReplayRejected, match="mutated"):
        evaluate_candidate_model(
            records, label_cutoff=CUTOFF,
            incumbent_policies=incumbent(), candidate_policies=policies(),
            resolve=changing_resolver,
        )




def test_equal_false_positive_rate_cannot_promote() -> None:
    records = [
        record for record in cohort()
        if record.label.is_fraud or not record.intelligence.velocity_risk
    ]
    evaluation = evaluate_candidate_model(
        records, label_cutoff=CUTOFF,
        incumbent_policies=incumbent(), candidate_policies=policies(),
        resolve=resolver,
    )
    assert evaluation.fpr_delta == 0.0
    assert evaluation.promotes is False
