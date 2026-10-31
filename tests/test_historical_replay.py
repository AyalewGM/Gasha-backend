from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    MissingTenantPolicyError,
    ReplayClassification,
    pseudonymize_transaction,
    reconcile_outcomes,
    replay_historical,
)
from gasha.poc.outcomes import OutcomeRecord, OutcomeType

T0 = datetime(2026, 1, 10, 9, 0, 0, tzinfo=UTC)


def transaction(
    *,
    tenant_id: str = "tenant-a",
    occurred_at: datetime = T0,
    suffix: str = "1",
) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid4(),
        occurred_at=occurred_at,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("2500.00"),
        currency="ETB",
        sender_customer_id=f"customer-{suffix}",
        sender_account_id=f"account-{suffix}",
        beneficiary_id=f"beneficiary-{suffix}",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="external-bank",
        correlation_id=f"corr-{suffix}",
    )


def policy(version: str = "policy-1") -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version=version,
        rule_version="rules-1",
    )


def event(
    *,
    tenant_id: str = "tenant-a",
    occurred_at: datetime = T0,
    intelligence: IntelligenceSnapshot | None = None,
    label: ConfirmedOutcomeLabel | None = None,
    suffix: str = "1",
    evidence_reason_codes: tuple[str, ...] = (),
    signal_policy_versions: tuple[str, ...] = (),
) -> HistoricalTransactionEvent:
    return HistoricalTransactionEvent(
        transaction=transaction(
            tenant_id=tenant_id, occurred_at=occurred_at, suffix=suffix
        ),
        intelligence=intelligence or IntelligenceSnapshot(),
        evidence_reason_codes=evidence_reason_codes,
        signal_policy_versions=signal_policy_versions,
        label=label,
    )


def test_replay_captures_decisions_versions_and_event_timestamps() -> None:
    occurred_at = T0 - timedelta(days=30)
    report = replay_historical(
        (
            event(
                occurred_at=occurred_at,
                intelligence=IntelligenceSnapshot(network_risk=0.96),
                evidence_reason_codes=("INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER",),
                signal_policy_versions=("graph-policy-2",),
                label=ConfirmedOutcomeLabel(
                    is_fraud=True, label_source="synthetic-case-review"
                ),
            ),
        ),
        {"tenant-a": policy("policy-9")},
    )

    result = report.results[0]
    assert result.decision.action == DecisionAction.BLOCK
    assert result.decision.risk_score == 0.96
    assert "INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER" in result.decision.reason_codes
    assert result.decision.policy_version == "policy-9"
    assert result.decision.tenant_id == "tenant-a"
    assert result.event.transaction.occurred_at == occurred_at
    assert result.event.signal_policy_versions == ("graph-policy-2",)
    assert result.classification == ReplayClassification.TRUE_POSITIVE
    assert result.decision_latency is None
    assert report.metrics.true_positives == 1
    assert report.metrics.mean_decision_latency_seconds is None
    assert result.processing_latency is not None
    assert report.metrics.mean_processing_latency_ms is not None


def test_replay_produces_confusion_matrix_inputs_for_poc_metrics() -> None:
    report = replay_historical(
        (
            event(
                intelligence=IntelligenceSnapshot(beneficiary_risk=0.91),
                label=ConfirmedOutcomeLabel(
                    is_fraud=True, label_source="synthetic"
                ),
                suffix="tp",
            ),
            event(
                intelligence=IntelligenceSnapshot(transaction_risk=0.73),
                evidence_reason_codes=("UNUSUAL_TRANSFER_PATTERN",),
                label=ConfirmedOutcomeLabel(
                    is_fraud=False, label_source="synthetic"
                ),
                suffix="fp",
            ),
            event(
                intelligence=IntelligenceSnapshot(relationship_risk=0.60),
                label=ConfirmedOutcomeLabel(
                    is_fraud=True, label_source="synthetic"
                ),
                suffix="fn",
            ),
            event(
                label=ConfirmedOutcomeLabel(
                    is_fraud=False, label_source="synthetic"
                ),
                suffix="tn",
            ),
            event(suffix="unlabeled"),
        ),
        {"tenant-a": policy()},
    )

    metrics = report.metrics
    assert metrics.cases == 5
    assert metrics.labeled_cases == 4
    assert metrics.unlabeled_cases == 1
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_negatives == 1
    assert metrics.recall == 0.5
    assert metrics.precision == 0.5
    assert metrics.false_positive_rate == 0.5
    assert metrics.explainability_coverage == 1.0


def test_confirmed_label_does_not_infer_replay_detection_lead_time() -> None:
    confirmed_at = T0 + timedelta(hours=48)
    report = replay_historical(
        (
            event(
                intelligence=IntelligenceSnapshot(beneficiary_risk=0.91),
                label=ConfirmedOutcomeLabel(
                    is_fraud=True,
                    label_source="confirmed-chargeback",
                    confirmed_at=confirmed_at,
                ),
            ),
        ),
        {"tenant-a": policy()},
    )

    result = report.results[0]
    assert result.classification == ReplayClassification.TRUE_POSITIVE
    assert result.detection_lead_time is None
    assert report.metrics.mean_detection_lead_time_seconds is None


def test_detection_lead_time_is_none_when_timestamps_do_not_permit() -> None:
    report = replay_historical(
        (
            event(
                intelligence=IntelligenceSnapshot(beneficiary_risk=0.91),
                label=ConfirmedOutcomeLabel(
                    is_fraud=True, label_source="synthetic"
                ),
                suffix="no-confirm-time",
            ),
            event(
                intelligence=IntelligenceSnapshot(transaction_risk=0.80),
                label=ConfirmedOutcomeLabel(
                    is_fraud=False,
                    label_source="confirmed-case-review",
                    confirmed_at=datetime.now(UTC) + timedelta(hours=1),
                ),
                suffix="not-fraud",
            ),
        ),
        {"tenant-a": policy()},
    )

    assert report.results[0].detection_lead_time is None
    assert report.results[1].detection_lead_time is None
    assert report.metrics.mean_detection_lead_time_seconds is None


def test_events_replay_in_chronological_order() -> None:
    report = replay_historical(
        (
            event(occurred_at=T0, suffix="later"),
            event(occurred_at=T0 - timedelta(days=5), suffix="earlier"),
        ),
        {"tenant-a": policy()},
    )

    assert report.results[0].event.transaction.occurred_at == T0 - timedelta(
        days=5
    )
    assert report.results[1].event.transaction.occurred_at == T0


def test_each_tenant_is_decided_by_its_own_policy() -> None:
    shared_intelligence = IntelligenceSnapshot(beneficiary_risk=0.80)
    report = replay_historical(
        (
            event(
                tenant_id="tenant-a",
                intelligence=shared_intelligence,
                label=ConfirmedOutcomeLabel(
                    is_fraud=True, label_source="synthetic"
                ),
            ),
            event(
                tenant_id="tenant-b",
                intelligence=shared_intelligence,
                label=ConfirmedOutcomeLabel(
                    is_fraud=True, label_source="synthetic"
                ),
            ),
        ),
        {
            "tenant-a": policy("policy-tenant-a"),
            "tenant-b": DecisionPolicy(
                configuration_version="tenant-b-config",
                policy_version="policy-tenant-b",
                rule_version="rules-tenant-b",
                monitor_threshold=0.90,
                review_threshold=0.95,
                hold_threshold=0.97,
                block_threshold=0.99,
            ),
        },
    )

    decision_a = report.results[0].decision
    decision_b = report.results[1].decision
    assert decision_a.action == DecisionAction.REVIEW
    assert decision_a.policy_version == "policy-tenant-a"
    assert decision_a.tenant_id == "tenant-a"
    assert report.results[0].classification == ReplayClassification.TRUE_POSITIVE
    assert decision_b.action == DecisionAction.ALLOW
    assert decision_b.policy_version == "policy-tenant-b"
    assert decision_b.tenant_id == "tenant-b"
    assert report.results[1].classification == ReplayClassification.FALSE_NEGATIVE


def test_event_without_tenant_policy_fails_closed() -> None:
    with pytest.raises(MissingTenantPolicyError):
        replay_historical(
            (event(tenant_id="tenant-unknown"),),
            {"tenant-a": policy()},
        )


def test_pseudonymization_preserves_linkage_and_event_facts() -> None:
    original = transaction()
    sanitized = pseudonymize_transaction(original, salt="synthetic-salt")

    assert sanitized.sender_customer_id != original.sender_customer_id
    assert sanitized.sender_account_id != original.sender_account_id
    assert sanitized.beneficiary_id != original.beneficiary_id
    assert sanitized.correlation_id != original.correlation_id
    assert sanitized.destination_institution_id is not None
    assert (
        sanitized.destination_institution_id
        != original.destination_institution_id
    )
    assert sanitized.tenant_id == original.tenant_id
    assert sanitized.event_id == original.event_id
    assert sanitized.occurred_at == original.occurred_at
    assert sanitized.amount == original.amount

    repeat = pseudonymize_transaction(original, salt="synthetic-salt")
    other_salt = pseudonymize_transaction(original, salt="other-salt")
    assert repeat.sender_customer_id == sanitized.sender_customer_id
    assert other_salt.sender_customer_id != sanitized.sender_customer_id

def test_late_outcome_reconciliation_does_not_invent_lead_time() -> None:
    source = event(
        intelligence=IntelligenceSnapshot(network_risk=0.96),
        suffix="late-confirmation",
    )
    replayed = replay_historical((source,), {"tenant-a": policy()})
    reconciled = reconcile_outcomes(
        replayed,
        (
            OutcomeRecord(
                tenant_id=source.transaction.tenant_id,
                event_id=source.transaction.event_id,
                outcome=OutcomeType.CONFIRMED_FRAUD,
                outcome_source="synthetic-case-review",
                outcome_version="labels-1",
                confirmed_at=T0 + timedelta(days=3),
            ),
        ),
    )
    assert reconciled.results[0].classification == ReplayClassification.TRUE_POSITIVE
    assert reconciled.results[0].detection_lead_time is None
    assert reconciled.results[0].decision_latency is None
    assert reconciled.metrics.mean_detection_lead_time_seconds is None
    assert reconciled.metrics.mean_decision_latency_seconds is None


@pytest.mark.parametrize(
    ("receipt_offset", "label_offset", "expected_message"),
    [
        (timedelta(microseconds=-1), None, "historical receipt precedes"),
        (None, timedelta(microseconds=-1), "historical label confirmation precedes"),
    ],
)
def test_historical_event_rejects_impossible_clock_order(
    receipt_offset: timedelta | None,
    label_offset: timedelta | None,
    expected_message: str,
) -> None:
    with pytest.raises(ValueError, match=expected_message):
        HistoricalTransactionEvent(
            transaction=transaction(),
            intelligence=IntelligenceSnapshot(),
            received_at=(T0 + receipt_offset if receipt_offset is not None else None),
            label=(
                ConfirmedOutcomeLabel(
                    is_fraud=True,
                    label_source="synthetic",
                    confirmed_at=T0 + label_offset,
                )
                if label_offset is not None
                else None
            ),
        )


@pytest.mark.parametrize("naive_field", ["event", "receipt", "label"])
def test_historical_event_rejects_naive_recorded_timestamps(
    naive_field: str,
) -> None:
    occurred = T0.replace(tzinfo=None) if naive_field == "event" else T0
    received = T0.replace(tzinfo=None) if naive_field == "receipt" else T0
    confirmed = T0.replace(tzinfo=None) if naive_field == "label" else T0
    with pytest.raises(ValueError, match="timezone-aware"):
        HistoricalTransactionEvent(
            transaction=transaction(occurred_at=occurred),
            intelligence=IntelligenceSnapshot(),
            received_at=received,
            label=ConfirmedOutcomeLabel(
                is_fraud=True,
                label_source="synthetic",
                confirmed_at=confirmed,
            ),
        )


def test_historical_event_accepts_equal_clocks_and_later_confirmation() -> None:
    source = HistoricalTransactionEvent(
        transaction=transaction(),
        intelligence=IntelligenceSnapshot(network_risk=0.96),
        received_at=T0,
        label=ConfirmedOutcomeLabel(
            is_fraud=True,
            label_source="synthetic",
            confirmed_at=T0 + timedelta(days=2),
        ),
    )
    report = replay_historical((source,), {"tenant-a": policy()})
    assert report.results[0].classification == ReplayClassification.TRUE_POSITIVE
    assert report.results[0].decision_latency is None
    assert report.results[0].detection_lead_time is None


def test_missing_receipt_and_confirmation_remain_synthetic_unknowns() -> None:
    source = HistoricalTransactionEvent(
        transaction=transaction(),
        intelligence=IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(
            is_fraud=False,
            label_source="synthetic",
        ),
    )
    report = replay_historical((source,), {"tenant-a": policy()})
    assert report.results[0].classification == ReplayClassification.TRUE_NEGATIVE
    assert report.results[0].decision_latency is None


@pytest.mark.parametrize("include_label", [False, True])
def test_event_only_naive_clock_is_rejected(include_label: bool) -> None:
    """The required event clock is mandatory even without optional times."""
    label = (
        ConfirmedOutcomeLabel(is_fraud=False, label_source="synthetic")
        if include_label
        else None
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        event(
            occurred_at=T0.replace(tzinfo=None),
            label=label,
            suffix="naive-no-optional-times",
        )


def test_mixed_clock_batch_rejects_before_sort_or_partial_replay() -> None:
    """Even an unchecked model copy must not provoke sort TypeError or decisions."""
    valid = event(suffix="valid")
    unchecked = event(suffix="unchecked").model_copy(
        update={
            "transaction": transaction(
                occurred_at=T0.replace(tzinfo=None), suffix="unchecked"
            )
        }
    )
    clock_calls: list[datetime] = []

    def clock() -> datetime:
        clock_calls.append(T0)
        return T0

    with pytest.raises(ValueError, match="timezone-aware"):
        replay_historical(
            (valid, unchecked),
            {"tenant-a": policy()},
            clock=clock,
        )
    assert clock_calls == []
