"""Synthetic-only MM-01 flow hypothesis; never Bank source or fraud authority."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.mm01_synthetic import (
    MM01Context,
    MM01Direction,
    MM01RelationshipEvidence,
    MM01RelationshipKind,
    MM01Status,
    MM01SyntheticMetrics,
    MM01SyntheticPolicy,
    MM01TransferStatus,
    evaluate_mm01_synthetic,
)
from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
    FieldEvidence,
    FieldState,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
)

AT = datetime(2026, 11, 3, 10, tzinfo=UTC)
EVENT_ID = UUID("d8077844-c0da-4b85-93dc-59815ab972e0")
DATASET = "sha256:" + "a" * 64


def evidence(name: str) -> FieldEvidence:
    return FieldEvidence(
        name=name, state=FieldState.OBSERVED, source_ref="synthetic-source",
        source_version="1", evidence_digest="sha256:" + "b" * 64,
        observed_at=AT - timedelta(minutes=3), available_at=AT - timedelta(minutes=1),
    )


def packet(*, include_context: bool = False) -> ScenarioObservation:
    names = list(SCENARIO_FIELDS[ScenarioId.MM_01].required)
    if include_context:
        names.extend(SCENARIO_FIELDS[ScenarioId.MM_01].optional)
    return ScenarioObservation(
        scenario_id=ScenarioId.MM_01,
        installation_ref="synthetic-install", tenant_ref="synthetic-tenant",
        dataset_digest=DATASET, event_id=EVENT_ID,
        source_system="synthetic-source", source_schema_version="1",
        mapping_version="1", configuration_version="1",
        occurred_at=AT, received_at=AT, decision_cutoff=AT,
        fields=tuple(evidence(name) for name in names),
    )


def policy() -> MM01SyntheticPolicy:
    return MM01SyntheticPolicy(
        version="synthetic-v1", configuration_version="1",
        max_credit_to_debit_seconds=300,
        min_credit_amount=Decimal(100),
        min_outbound_ratio=Decimal("0.80"), currency="ETB",
    )


def metrics(row: ScenarioObservation) -> MM01SyntheticMetrics:
    relation = next(
        (field for field in row.fields if field.name == "own_account_relationship"
         and field.state is FieldState.OBSERVED), None
    )
    relationship = (
        MM01RelationshipEvidence(
            kind=MM01RelationshipKind.DISTINCT_OWNERS,
            source_ref=relation.source_ref, source_version=relation.source_version,
            evidence_digest=relation.evidence_digest,
            snapshot_digest=row.fingerprint(), installation_ref=row.installation_ref,
            tenant_ref=row.tenant_ref, dataset_digest=row.dataset_digest,
            observed_at=relation.observed_at, available_at=relation.available_at,
            permitted_purpose="synthetic_mm01_own_account_exclusion",
        ) if relation is not None else None
    )
    return MM01SyntheticMetrics(
        observation_digest=row.fingerprint(), policy_version="synthetic-v1",
        account_ref="synthetic-acct", inbound_account_ref="synthetic-acct",
        outbound_account_ref="synthetic-acct", inbound_event_ref="credit-event-1",
        outbound_event_ref=str(EVENT_ID), inbound_direction=MM01Direction.INBOUND,
        outbound_direction=MM01Direction.OUTBOUND,
        inbound_status=MM01TransferStatus.POSTED,
        outbound_status=MM01TransferStatus.POSTED,
        inbound_occurred_at=AT - timedelta(minutes=3),
        outbound_occurred_at=AT,
        inbound_available_at=AT - timedelta(minutes=2),
        outbound_available_at=AT,
        inbound_amount=Decimal(1000), outbound_amount=Decimal(800),
        currency="ETB", own_account_relationship=relationship,
    )


def evaluate(
    row: ScenarioObservation, *,
    values: MM01SyntheticMetrics | None,
    thresholds: MM01SyntheticPolicy | None = None,
) -> dict[str, object]:
    return evaluate_mm01_synthetic(
        row, policy=policy() if thresholds is None else thresholds, metrics=values,
        expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    ).to_dict()


def test_missing_optional_context_is_review_not_confirmed_flow() -> None:
    row = packet()
    result = evaluate(row, values=metrics(row))
    assert result["status"] == MM01Status.CONTEXT_REVIEW.value
    assert result["reasons"] == ["optional_context_unavailable"]
    for name in (
        "bank_verified", "fraud_determined", "funds_traced", "funds_stopped",
        "readiness_authorized", "enforcement_activated",
    ):
        assert result[name] is False
    for name in ("risk_score", "account_ref", "inbound_amount", "outbound_amount",
                 "customer_id", "payment_action", "prevented_loss"):
        assert name not in result


def test_explicit_observed_exception_absence_yields_only_synthetic_hypothesis() -> None:
    row = packet(include_context=True)
    vals = replace(
        metrics(row),
        own_account_context=MM01Context.REPORTED_ABSENT,
        reversal_context=MM01Context.REPORTED_ABSENT,
    )
    result = evaluate(row, values=vals)
    assert result["status"] == MM01Status.SYNTHETIC_HYPOTHESIS.value
    assert result["effective_input_digest"] is not None
    assert result["funds_traced"] is False


@pytest.mark.parametrize("name", ["own_account_context", "reversal_context"])
def test_known_legitimate_or_reversal_context_excludes_hypothesis(name: str) -> None:
    row = packet(include_context=True)
    vals = replace(metrics(row), **{name: MM01Context.REPORTED})
    if name == "own_account_context":
        assert vals.own_account_relationship is not None
        vals = replace(vals, own_account_relationship=replace(
            vals.own_account_relationship, kind=MM01RelationshipKind.SAME_OWNER,
        ))
    assert evaluate(row, values=vals)["status"] == MM01Status.CONTEXT_EXCLUSION.value


@pytest.mark.parametrize("name", ["own_account_context", "reversal_context"])
def test_claimed_optional_evidence_must_be_present(name: str) -> None:
    row = packet()
    vals = replace(metrics(row), **{name: MM01Context.REPORTED_ABSENT})
    with pytest.raises(ScenarioContractError, match="without observed"):
        evaluate(row, values=vals)


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("outbound_account_ref", "different", MM01Status.BLOCKED_LINKAGE),
        ("inbound_status", MM01TransferStatus.ATTEMPTED, MM01Status.BLOCKED_STATUS),
        ("outbound_status", MM01TransferStatus.ATTEMPTED, MM01Status.BLOCKED_STATUS),
        ("inbound_status", MM01TransferStatus.REVERSED, MM01Status.BLOCKED_STATUS),
        ("outbound_status", MM01TransferStatus.FAILED, MM01Status.BLOCKED_STATUS),
        ("inbound_amount", Decimal(99), MM01Status.BELOW_CREDIT_FLOOR),
        ("outbound_amount", Decimal("799.99"), MM01Status.BELOW_RATIO),
    ],
)
def test_matched_negative_and_exact_amount_boundaries(
    field: str, value: object, expected: MM01Status,
) -> None:
    row = packet(include_context=True)
    vals = replace(metrics(row), **{field: value})
    assert evaluate(row, values=vals)["status"] == expected.value


def test_credit_at_same_instant_as_debit_is_not_onward_movement() -> None:
    row = packet()
    vals = replace(
        metrics(row), inbound_occurred_at=AT, inbound_available_at=AT,
    )
    assert evaluate(row, values=vals)["status"] == MM01Status.BLOCKED_CHRONOLOGY.value


def test_time_window_exact_inside_and_outside() -> None:
    row = packet(include_context=True)
    vals = metrics(row)
    inside = replace(
        vals, inbound_occurred_at=AT - timedelta(seconds=300),
        inbound_available_at=AT - timedelta(seconds=299),
    )
    assert evaluate(row, values=inside)["status"] == MM01Status.CONTEXT_REVIEW.value
    outside = replace(
        vals, inbound_occurred_at=AT - timedelta(seconds=301),
        inbound_available_at=AT - timedelta(seconds=300),
    )
    assert evaluate(row, values=outside)["status"] == MM01Status.OUTSIDE_WINDOW.value


def test_missing_fields_and_metrics_block_without_zero_risk() -> None:
    row = packet()
    missing = replace(row, fields=tuple(
        x for x in row.fields if x.name != "inbound_credit_status"
    ))
    assert evaluate(missing, values=None)["status"] == "blocked_required_fields"
    assert evaluate(row, values=None)["status"] == "blocked_metrics"
    result = evaluate_mm01_synthetic(
        row, policy=None, metrics=None, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    )
    assert result.status is MM01Status.BLOCKED_POLICY


@pytest.mark.parametrize(
    "change",
    [
        {"observation_digest": "sha256:" + "c" * 64},
        {"policy_version": "other"},
        {"outbound_event_ref": "wrong"},
        {"inbound_event_ref": str(EVENT_ID)},
        {"outbound_occurred_at": AT - timedelta(seconds=1)},
        {"outbound_available_at": AT + timedelta(seconds=1)},
        {"currency": "USD"},
        {"inbound_direction": MM01Direction.OUTBOUND},
        {"outbound_direction": MM01Direction.INBOUND},
    ],
)
def test_wrong_versions_event_link_or_direction_rejected(change: dict[str, object]) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=replace(metrics(row), **change))


@pytest.mark.parametrize("name", ["inbound_amount", "outbound_amount"])
@pytest.mark.parametrize("invalid", [Decimal("NaN"), Decimal("Infinity"), Decimal(0), True])
def test_invalid_strict_amount_rejected(name: str, invalid: object) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), **{name: invalid})


def test_policy_version_scope_currency_and_ratio_strictness() -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=metrics(row),
                 thresholds=replace(policy(), configuration_version="other"))
    for bad in (Decimal("NaN"), Decimal(0), Decimal("1.01"), True):
        with pytest.raises(ScenarioContractError):
            replace(policy(), min_outbound_ratio=bad)
    with pytest.raises(ScenarioContractError):
        replace(policy(), max_credit_to_debit_seconds=True)
    with pytest.raises(ScenarioContractError, match="mismatch"):
        evaluate_mm01_synthetic(
            row, policy=policy(), metrics=metrics(row),
            expected_installation="synthetic-install", expected_tenant="another",
            expected_dataset_digest=DATASET,
        )


def test_mutation_revalidated_and_effective_digest_changes() -> None:
    row = packet(include_context=True)
    vals = replace(metrics(row), own_account_context=MM01Context.REPORTED_ABSENT,
                   reversal_context=MM01Context.REPORTED_ABSENT)
    first = evaluate(row, values=vals)
    amended = evaluate(row, values=replace(vals, outbound_amount=Decimal(900)))
    assert first["effective_input_digest"] != amended["effective_input_digest"]
    object.__setattr__(vals, "outbound_status", "settled")
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=vals)
    thresholds = policy()
    object.__setattr__(thresholds, "min_outbound_ratio", Decimal("NaN"))
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=metrics(row), thresholds=thresholds)


@pytest.mark.parametrize("field", ["currency", "outbound_event_ref", "inbound_amount"])
def test_deleted_required_field_is_redacted_domain_error(field: str) -> None:
    row = packet()
    vals = metrics(row)
    object.__delattr__(vals, field)
    with pytest.raises(ScenarioContractError, match="missing required synthetic flow field"):
        evaluate(row, values=vals)


def test_timezone_offset_and_dst_fold_normalized_for_same_instant() -> None:
    row = packet()
    vals = metrics(row)
    local = vals.inbound_occurred_at.astimezone(ZoneInfo("America/New_York"))
    alternative = replace(vals, inbound_occurred_at=local)
    assert alternative.inbound_occurred_at == vals.inbound_occurred_at
    assert evaluate(row, values=alternative)["effective_input_digest"] == (
        evaluate(row, values=vals)["effective_input_digest"]
    )
    zone = ZoneInfo("America/New_York")
    early = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=0)
    late = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    assert early.astimezone(UTC) < late.astimezone(UTC)


@pytest.mark.parametrize(
    "path",
    ["src/gasha/api/main.py", "src/gasha/worker.py",
     "src/gasha/decision/service.py", "src/gasha/poc/readiness.py",
     "src/gasha/poc/replay.py", "src/gasha/ingestion/postgres_atomic_outcomes.py"],
)
def test_mm01_not_wired_into_bank_runtime_or_readiness(path: str) -> None:
    assert "mm01_synthetic" not in Path(path).read_text(encoding="utf-8")


@pytest.mark.parametrize("context_name,field_name", [
    ("own_account_context", "own_account_relationship"),
    ("reversal_context", "reversal_status"),
])
@pytest.mark.parametrize("source_state", ["missing", "unavailable"])
@pytest.mark.parametrize("branch", [
    "linkage", "chronology", "status", "window", "floor", "ratio",
    "context_exclusion", "candidate",
])
def test_unsubstantiated_optional_claim_never_escapes_early_return(
    context_name: str, field_name: str, source_state: str, branch: str,
) -> None:
    row = packet(include_context=True)
    if source_state == "missing":
        row = replace(row, fields=tuple(
            field for field in row.fields if field.name != field_name
        ))
    else:
        row = replace(row, fields=tuple(
            FieldEvidence(name=field_name, state=FieldState.UNAVAILABLE,
                          unavailable_reason="not_authorized")
            if field.name == field_name else field for field in row.fields
        ))
    changes: dict[str, object] = {}
    if branch == "linkage":
        changes["outbound_account_ref"] = "different"
    elif branch == "chronology":
        changes["inbound_occurred_at"] = AT
        changes["inbound_available_at"] = AT
    elif branch == "status":
        changes["inbound_status"] = MM01TransferStatus.FAILED
    elif branch == "window":
        changes["inbound_occurred_at"] = AT - timedelta(seconds=301)
        changes["inbound_available_at"] = AT - timedelta(seconds=300)
    elif branch == "floor":
        changes["inbound_amount"] = Decimal(99)
    elif branch == "ratio":
        changes["outbound_amount"] = Decimal(799)
    elif branch == "context_exclusion":
        changes["own_account_context"] = MM01Context.REPORTED
        changes["reversal_context"] = MM01Context.REPORTED
    changes[context_name] = MM01Context.REPORTED_ABSENT
    vals = replace(metrics(row), **changes)
    with pytest.raises(ScenarioContractError, match="without observed evidence"):
        evaluate(row, values=vals)


@pytest.mark.parametrize("name", ["inbound_amount", "outbound_amount"])
@pytest.mark.parametrize("bad", [
    Decimal("1e-1000000"), Decimal("0.0000001"), Decimal("1.0000000"),
    Decimal("1e19"), Decimal("1e1000000"), Decimal(12345678901234567890123456),
])
def test_synthetic_v1_amount_domain_rejects_unrepresentable_claims(
    name: str, bad: Decimal,
) -> None:
    row = packet()
    with pytest.raises(ScenarioContractError):
        replace(metrics(row), **{name: bad})


@pytest.mark.parametrize("bad", [
    Decimal("1e-1000000"), Decimal("0.0000001"), Decimal("0.8000000"),
    Decimal("1.0000000"), Decimal("1.000001"),
])
def test_synthetic_v1_ratio_domain_rejects_overscale(bad: Decimal) -> None:
    with pytest.raises(ScenarioContractError):
        replace(policy(), min_outbound_ratio=bad)


def test_exact_micro_unit_ratio_comparison_and_max_amount() -> None:
    row = packet(include_context=True)
    vals = replace(metrics(row), own_account_context=MM01Context.REPORTED_ABSENT,
                   reversal_context=MM01Context.REPORTED_ABSENT)
    assert evaluate(row, values=replace(
        vals, outbound_amount=Decimal("800.000000"),
    ))["status"] == MM01Status.SYNTHETIC_HYPOTHESIS.value
    assert evaluate(row, values=replace(
        vals, outbound_amount=Decimal("799.999999"),
    ))["status"] == MM01Status.BELOW_RATIO.value
    assert evaluate(row, values=replace(
        vals, outbound_amount=Decimal("800.000001"),
    ))["status"] == MM01Status.SYNTHETIC_HYPOTHESIS.value
    maximum = Decimal("1e18")
    upper = replace(vals, inbound_amount=maximum, outbound_amount=maximum)
    assert evaluate(row, values=upper, thresholds=replace(
        policy(), min_credit_amount=maximum, min_outbound_ratio=Decimal(1),
    ))["status"] == MM01Status.SYNTHETIC_HYPOTHESIS.value
    tiny = Decimal("0.000001")
    lower = replace(vals, inbound_amount=tiny, outbound_amount=tiny)
    assert evaluate(row, values=lower, thresholds=replace(
        policy(), min_credit_amount=tiny, min_outbound_ratio=Decimal(1),
    ))["status"] == MM01Status.SYNTHETIC_HYPOTHESIS.value


def test_counterparty_identifier_alone_cannot_authorize_same_owner_exclusion() -> None:
    row = packet(include_context=True)
    row = replace(row, fields=tuple(
        field for field in row.fields if field.name != "own_account_relationship"
    ))
    vals = replace(metrics(row), own_account_context=MM01Context.REPORTED)
    assert "counterparty_pseudonym" in {field.name for field in row.fields}
    with pytest.raises(ScenarioContractError, match="without observed evidence"):
        evaluate(row, values=vals)


@pytest.mark.parametrize("change", [
    {"source_version": "different"},
    {"source_ref": "spliced-source"},
    {"evidence_digest": "sha256:" + "c" * 64},
    {"tenant_ref": "foreign-tenant"},
    {"dataset_digest": "sha256:" + "d" * 64},
    {"snapshot_digest": "sha256:" + "e" * 64},
    {"permitted_purpose": "general_analytics"},
    {"available_at": AT + timedelta(seconds=1)},
])
def test_claimed_relationship_rejects_scope_or_provenance_splicing(
    change: dict[str, object],
) -> None:
    row = packet(include_context=True)
    vals = metrics(row)
    assert vals.own_account_relationship is not None
    vals = replace(vals, own_account_context=MM01Context.REPORTED_ABSENT,
                   own_account_relationship=replace(vals.own_account_relationship, **change))
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=vals)


def test_same_owner_claim_requires_consistent_explicit_classification() -> None:
    row = packet(include_context=True)
    vals = replace(metrics(row), own_account_context=MM01Context.REPORTED)
    with pytest.raises(ScenarioContractError, match="classification mismatch"):
        evaluate(row, values=vals)
    assert vals.own_account_relationship is not None
    same = replace(vals, own_account_relationship=replace(
        vals.own_account_relationship, kind=MM01RelationshipKind.SAME_OWNER,
    ))
    assert evaluate(row, values=same)["status"] == MM01Status.CONTEXT_EXCLUSION.value


def test_claimed_relationship_rejects_unavailable_or_late_evidence() -> None:
    row = packet(include_context=True)
    changed = replace(row, fields=tuple(
        FieldEvidence(name=field.name, state=FieldState.UNAVAILABLE,
                      unavailable_reason="not_authorized")
        if field.name == "own_account_relationship" else field for field in row.fields
    ))
    vals = replace(metrics(changed), own_account_context=MM01Context.REPORTED)
    with pytest.raises(ScenarioContractError):
        evaluate(changed, values=vals)
    vals = metrics(row)
    assert vals.own_account_relationship is not None
    late = replace(vals, own_account_context=MM01Context.REPORTED_ABSENT,
                   own_account_relationship=replace(
                       vals.own_account_relationship,
                       available_at=AT + timedelta(seconds=1),
                   ))
    with pytest.raises(ScenarioContractError):
        evaluate(row, values=late)
