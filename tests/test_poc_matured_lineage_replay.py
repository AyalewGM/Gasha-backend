"""Issue #48: offline point-in-time replay and matured-label population tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from json import dumps
from uuid import UUID

import pytest

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    ReplayClassification,
)
from gasha.poc.matured_lineage_replay import (
    OfflineCohortScope,
    replay_offline_matured_lineage,
)
from gasha.poc.temporal_lineage import (
    HistoricalFeatureEnvelope,
    HistoricalLineageRejected,
    SignalLineage,
)

AT = datetime(2026, 1, 10, 9, tzinfo=UTC)
DATASET = "sha256:" + "a" * 64


def scope(**changes: object) -> OfflineCohortScope:
    values: dict[str, object] = {
        "tenant_id": "synthetic-tenant",
        "dataset_digest": DATASET,
        "cohort_version": "cohort-v1",
        "mapping_version": "map-v1",
        "configuration_version": "config-v1",
        "policy_version": "policy-v1",
        "rule_version": "rules-v1",
        "signal_policy_version": "signals-v1",
        "window_start": AT,
        "window_end": AT + timedelta(minutes=5),
        "label_cutoff": AT + timedelta(days=10),
    }
    values.update(changes)
    return OfflineCohortScope(**values)  # type: ignore[arg-type]


def policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="config-v1",
        policy_version="policy-v1",
        rule_version="rules-v1",
    )


def sample(
    number: int = 1, *, risk: float = 0.95,
    label: bool | None = True, confirmed_at: datetime | None = None,
) -> tuple[HistoricalTransactionEvent, HistoricalFeatureEnvelope]:
    event_id = UUID(int=number)
    snapshot = IntelligenceSnapshot(
        **{name: (risk if name == "beneficiary_risk" else 0.2)
           for name in IntelligenceSnapshot.model_fields}
    )
    event = HistoricalTransactionEvent(
        transaction=CanonicalTransaction(
            tenant_id="synthetic-tenant", event_id=event_id,
            occurred_at=AT, channel="mobile", transaction_type="transfer",
            amount=Decimal("10"), currency="ETB",
            sender_customer_id="private-customer-123",
            sender_account_id="private-account-123",
            beneficiary_id="private-beneficiary-123",
            beneficiary_type=BeneficiaryType.INTERNAL,
            correlation_id="private-correlation-123",
        ),
        intelligence=snapshot,
        signal_policy_versions=("signals-v1",),
        received_at=AT + timedelta(seconds=1),
        label=(
            ConfirmedOutcomeLabel(
                is_fraud=label, label_source="synthetic-analyst",
                confirmed_at=confirmed_at,
            ) if label is not None else None
        ),
    )
    lineage = HistoricalFeatureEnvelope(
        tenant_id="synthetic-tenant", event_id=event_id,
        dataset_digest=DATASET, cohort_version="cohort-v1",
        mapping_version="map-v1", configuration_version="config-v1",
        policy_version="policy-v1", signal_policy_version="signals-v1",
        occurred_at=AT, decision_cutoff=AT + timedelta(seconds=2),
        signals=tuple(
            SignalLineage(
                name=name, value=float(getattr(snapshot, name)),
                source_ref="synthetic-fixture", source_version="signals-v1",
                as_of=AT, available_at=AT,
            ) for name in IntelligenceSnapshot.model_fields
        ),
    )
    return event, lineage


def check(
    *rows: tuple[HistoricalTransactionEvent, HistoricalFeatureEnvelope],
) -> dict[str, object]:
    return replay_offline_matured_lineage(
        scope(), tuple(e for e, _ in rows), tuple(l for _, l in rows),
        policy(),
    ).to_dict()


def test_complete_preflight_masks_late_unconfirmed_and_missing_labels() -> None:
    rows = (
        sample(1, confirmed_at=AT + timedelta(days=2)),
        sample(2, risk=0.2, label=False, confirmed_at=AT + timedelta(days=1)),
        sample(3, label=True, confirmed_at=AT + timedelta(days=11)),
        sample(4, label=True),
        sample(5, label=None),
    )
    result = replay_offline_matured_lineage(
        scope(), tuple(e for e, _ in rows), tuple(l for _, l in rows), policy(),
    )
    assert [item.classification for item in result.replay.results] == [
        ReplayClassification.TRUE_POSITIVE,
        ReplayClassification.TRUE_NEGATIVE,
        ReplayClassification.UNLABELED,
        ReplayClassification.UNLABELED,
        ReplayClassification.UNLABELED,
    ]
    summary = result.to_dict()
    assert summary["maturity"] == {
        "matured_positive": 1, "matured_negative": 1,
        "excluded_future_labels": 1, "excluded_unconfirmed_labels": 1,
        "absent_labels": 1,
    }
    assert summary["confusion_counts"] == {
        "true_positive": 1, "false_positive": 0, "true_negative": 1,
        "false_negative": 0, "unlabeled": 3,
    }
    assert summary["precision"]["value"] == 1.0
    assert summary["recall"]["value"] == 1.0
    assert summary["false_positive_rate"]["value"] == 0.0
    assert not any(summary[flag] for flag in (
        "bank_data_verified", "bank_kpi_approved", "readiness_authorized",
        "enforcement_activated",
    ))
    assert rows[2][0].label is not None
    assert result.replay.results[2].event.label is None
    assert result.replay.metrics.cases == 5


def test_no_matured_cohort_labels_yield_undefined_not_perfect_metrics() -> None:
    only_future = sample(1, confirmed_at=AT + timedelta(days=11))
    result = check(only_future)
    for name in ("precision", "recall", "false_positive_rate"):
        rate = result[name]
        assert rate["numerator"] == 0
        assert rate["denominator"] == 0
        assert rate["value"] is None
        assert rate["undefined_reason"]
    assert result["confusion_counts"]["unlabeled"] == 1
    assert check()["precision"]["value"] is None
    assert check()["cases"] == 0


def test_preflight_rejects_late_signal_without_any_decision_clock_call() -> None:
    event, lineage = sample()
    signal = replace(
        lineage.signals[0], as_of=AT + timedelta(seconds=3),
        available_at=AT + timedelta(seconds=3),
    )
    object.__setattr__(lineage, "signals", (signal, *lineage.signals[1:]))
    calls = 0

    def decision_clock() -> datetime:
        nonlocal calls
        calls += 1
        return AT

    with pytest.raises(HistoricalLineageRejected, match="post-cutoff"):
        replay_offline_matured_lineage(
            scope(), (event,), (lineage,), policy(), clock=decision_clock,
        )
    assert calls == 0


@pytest.mark.parametrize("field,replacement", [
    ("tenant_id", "other-tenant"),
    ("dataset_digest", "sha256:" + "b" * 64),
    ("cohort_version", "other-cohort"),
    ("mapping_version", "other-map"),
    ("configuration_version", "other-config"),
    ("policy_version", "other-policy"),
    ("signal_policy_version", "other-signals"),
])
def test_scope_substitution_rejected_before_replay(
    field: str, replacement: str,
) -> None:
    event, lineage = sample()
    altered = replace(lineage, **{field: replacement})
    with pytest.raises(HistoricalLineageRejected):
        replay_offline_matured_lineage(
            scope(), (event,), (altered,), policy(),
        )


def test_missing_duplicate_or_orphan_lineage_is_rejected() -> None:
    event, lineage = sample()
    other_event, other_lineage = sample(2)
    with pytest.raises(HistoricalLineageRejected, match="missing"):
        replay_offline_matured_lineage(scope(), (event,), (), policy())
    with pytest.raises(HistoricalLineageRejected, match="duplicate"):
        replay_offline_matured_lineage(
            scope(), (event,), (lineage, lineage), policy(),
        )
    with pytest.raises(HistoricalLineageRejected, match="orphan"):
        replay_offline_matured_lineage(
            scope(), (event,), (lineage, other_lineage), policy(),
        )
    with pytest.raises(HistoricalLineageRejected, match="duplicate"):
        replay_offline_matured_lineage(
            scope(), (event, event), (lineage,), policy(),
        )
    assert check((other_event, other_lineage))["cases"] == 1


def test_unavailable_signal_cannot_be_numeric_zero_in_replay() -> None:
    event, lineage = sample()
    unavailable = SignalLineage(
        name="beneficiary_risk", value=None, unavailable_reason="missing-source",
    )
    signals = tuple(
        unavailable if signal.name == "beneficiary_risk" else signal
        for signal in lineage.signals
    )
    with pytest.raises(HistoricalLineageRejected, match="unavailable telemetry"):
        replay_offline_matured_lineage(
            scope(), (event,), (replace(lineage, signals=signals),), policy(),
        )


def test_original_receipt_must_be_present_and_not_after_decision_cutoff() -> None:
    event, lineage = sample()
    for received_at in (None, AT + timedelta(seconds=3)):
        forged = event.model_copy(update={"received_at": received_at})
        with pytest.raises(HistoricalLineageRejected, match="receipt/cutoff"):
            replay_offline_matured_lineage(
                scope(), (forged,), (lineage,), policy(),
            )


def test_policy_versions_cannot_be_substituted() -> None:
    event, lineage = sample()
    wrong_policy = policy().model_copy(update={"rule_version": "rules-v2"})
    with pytest.raises(HistoricalLineageRejected, match="version mismatch"):
        replay_offline_matured_lineage(
            scope(), (event,), (lineage,), wrong_policy,
        )
    wrong_source = event.model_copy(update={"signal_policy_versions": ("signals-v2",)})
    with pytest.raises(HistoricalLineageRejected, match="lineage mismatch"):
        replay_offline_matured_lineage(
            scope(), (wrong_source,), (lineage,), policy(),
        )


def test_report_is_aggregate_only_and_dataset_bound() -> None:
    positive = sample(1, confirmed_at=AT + timedelta(days=2))
    other = sample(2, label=None)
    output = check(positive, other)
    encoded = dumps(output, sort_keys=True)
    assert output["source"] == "synthetic_caller_asserted"
    assert output["scope"]["dataset_digest"] == DATASET
    assert output["cohort_digest"].startswith("sha256:")
    for forbidden in (
        "private-customer-123", "private-account-123",
        "private-beneficiary-123", "private-correlation-123",
        str(positive[0].transaction.event_id), "synthetic-fixture",
    ):
        assert forbidden not in encoded
    assert check(other, positive)["cohort_digest"] == output["cohort_digest"]
    changed = sample(1, label=False, confirmed_at=AT + timedelta(days=2))
    assert check(changed, other)["cohort_digest"] != output["cohort_digest"]


def test_malformed_batch_scope_and_time_are_rejected() -> None:
    with pytest.raises(HistoricalLineageRejected):
        scope(dataset_digest="not-a-digest")
    with pytest.raises(HistoricalLineageRejected):
        scope(window_end=AT - timedelta(seconds=1))
    with pytest.raises(HistoricalLineageRejected):
        scope(label_cutoff=AT)
    with pytest.raises(HistoricalLineageRejected, match="immutable"):
        replay_offline_matured_lineage(scope(), [], (), policy())  # type: ignore[arg-type]
