"""Synthetic, non-bank scenario observation mapping and PIT regression tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.scenario_observations import (
    SCENARIO_FIELDS,
    SCENARIO_MAPPING_VERSION,
    FieldEvidence,
    FieldState,
    ScenarioContractError,
    ScenarioId,
    ScenarioObservation,
    inspect_scenario_coverage,
)

AT = datetime(2026, 10, 30, 12, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
FIELD_DIGEST = "sha256:" + "b" * 64
EVENT_ID = UUID("e6ecba61-e59a-4c9a-b42b-1c1c252fab11")


def measured(
    name: str, *, observed_at: datetime = AT, available_at: datetime = AT,
) -> FieldEvidence:
    return FieldEvidence(
        name=name, state=FieldState.OBSERVED, source_ref="synthetic-source",
        source_version="1.0", evidence_digest=FIELD_DIGEST,
        observed_at=observed_at, available_at=available_at,
    )


def observation(
    scenario: ScenarioId, *, fields: tuple[FieldEvidence, ...] | None = None,
) -> ScenarioObservation:
    if fields is None:
        fields = tuple(measured(name) for name in SCENARIO_FIELDS[scenario].required)
    return ScenarioObservation(
        scenario_id=scenario, installation_ref="synthetic-install",
        tenant_ref="synthetic-tenant", dataset_digest=DIGEST, event_id=EVENT_ID,
        source_system="synthetic-only", source_schema_version="1",
        mapping_version="1", configuration_version="1", occurred_at=AT,
        received_at=AT, decision_cutoff=AT, fields=fields,
    )


def inspect(row: ScenarioObservation) -> dict[str, object]:
    return inspect_scenario_coverage(
        row, expected_installation="synthetic-install",
        expected_tenant="synthetic-tenant", expected_dataset_digest=DIGEST,
    ).to_dict()


def test_selected_eight_matrix_is_unique_and_versioned() -> None:
    assert len(SCENARIO_FIELDS) == 8
    assert set(SCENARIO_FIELDS) == set(ScenarioId)
    assert SCENARIO_MAPPING_VERSION == "dashen-synthetic-observation-v1"
    assert {mapping.use_case for mapping in SCENARIO_FIELDS.values()} == {
        "UC-01", "UC-02", "UC-03",
    }
    for mapping in SCENARIO_FIELDS.values():
        assert len(mapping.required) == len(set(mapping.required)) > 0
        assert not set(mapping.required).intersection(mapping.optional)


@pytest.mark.parametrize("scenario", list(ScenarioId))
def test_complete_synthetic_evidence_never_claims_fraud_or_bank_readiness(
    scenario: ScenarioId,
) -> None:
    result = inspect(observation(scenario))
    assert result["scenario_id"] == scenario.value
    assert result["use_case"] == SCENARIO_FIELDS[scenario].use_case
    assert result["status"] == "synthetic_coverage_only"
    assert result["missing_required"] == []
    assert result["source"] == "synthetic_caller_asserted"
    for flag in ("bank_verified", "detection_executed", "readiness_authorized",
                 "enforcement_activated"):
        assert result[flag] is False
    assert result["observation_digest"] == observation(scenario).fingerprint()


@pytest.mark.parametrize(
    "scenario,missing",
    [(scenario, field) for scenario, mapping in SCENARIO_FIELDS.items()
     for field in mapping.required],
)
def test_every_missing_required_source_blocks_scenario(
    scenario: ScenarioId, missing: str,
) -> None:
    row = observation(scenario)
    partial = replace(
        row, fields=tuple(f for f in row.fields if f.name != missing),
    )
    result = inspect(partial)
    assert result["status"] == "blocked_by_data"
    assert result["missing_required"] == [missing]
    explicit = replace(partial, fields=partial.fields + (
        FieldEvidence(name=missing, state=FieldState.UNAVAILABLE,
                      unavailable_reason="blocked_by_data"),
    ))
    assert inspect(explicit)["missing_required"] == [missing]


@pytest.mark.parametrize("scenario", list(ScenarioId))
def test_optional_missing_or_unavailable_is_not_zero_risk(scenario: ScenarioId) -> None:
    optional = SCENARIO_FIELDS[scenario].optional
    assert optional
    row = observation(scenario)
    before = inspect(row)
    assert before["unavailable_optional"] == sorted(optional)
    explicit = replace(row, fields=row.fields + (
        FieldEvidence(name=optional[0], state=FieldState.UNAVAILABLE,
                      unavailable_reason="not_authorized"),
    ))
    after = inspect(explicit)
    assert before["status"] == after["status"]
    assert after["unavailable_optional"] == sorted(optional)
    assert "risk_score" not in after


@pytest.mark.parametrize("field", ["installation_ref", "tenant_ref", "dataset_digest"])
def test_caller_scope_substitution_rejected(field: str) -> None:
    row = observation(ScenarioId.MM_05)
    replaced = replace(row, **{field: "sha256:" + "c" * 64
                               if field == "dataset_digest" else "other"})
    with pytest.raises(ScenarioContractError, match="mismatch"):
        inspect(replaced)


@pytest.mark.parametrize("scenario", list(ScenarioId))
def test_late_synthetic_signal_never_becomes_available(scenario: ScenarioId) -> None:
    row = observation(scenario)
    earliest = row.fields[0]
    after = AT + timedelta(microseconds=1)
    for item in (
        replace(earliest, observed_at=AT, available_at=after),
        replace(earliest, observed_at=after, available_at=after),
    ):
        with pytest.raises(ScenarioContractError, match="post-cutoff"):
            replace(row, fields=(item,) + row.fields[1:])


def test_utc_instant_comparisons_and_digest_across_dst_fold() -> None:
    zone = ZoneInfo("America/New_York")
    occurred = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    received = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    cutoff = datetime(2026, 11, 1, 1, 45, tzinfo=zone, fold=1)
    row = observation(ScenarioId.ATO_02)
    local_fields = tuple(measured(name, observed_at=occurred, available_at=received)
                         for name in SCENARIO_FIELDS[ScenarioId.ATO_02].required)
    local = replace(row, occurred_at=occurred, received_at=received,
                    decision_cutoff=cutoff, fields=local_fields)
    equivalent = replace(
        row, occurred_at=occurred.astimezone(UTC),
        received_at=received.astimezone(UTC),
        decision_cutoff=cutoff.astimezone(UTC),
        fields=tuple(measured(name, observed_at=occurred.astimezone(UTC),
                              available_at=received.astimezone(UTC))
                     for name in SCENARIO_FIELDS[ScenarioId.ATO_02].required),
    )
    assert inspect(local)["status"] == "synthetic_coverage_only"
    assert local.fingerprint() == equivalent.fingerprint()
    with pytest.raises(ScenarioContractError, match="chronology"):
        replace(local, received_at=datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=0))


@pytest.mark.parametrize("source", [None, "", " source", "source\n", "bank/email@example.com"])
def test_invalid_source_reference_rejected(source: object) -> None:
    with pytest.raises(ScenarioContractError):
        replace(measured("payment_amount"), source_ref=source)


@pytest.mark.parametrize("bad", [None, "", "SHA256:" + "b" * 64, "bank-raw-amount"])
def test_raw_or_invalid_value_evidence_rejected(bad: object) -> None:
    with pytest.raises(ScenarioContractError):
        replace(measured("payment_amount"), evidence_digest=bad)


@pytest.mark.parametrize("bad", [None, "", "  ", "unauthorized\n"])
def test_unavailable_reason_requires_canonical_code(bad: object) -> None:
    with pytest.raises(ScenarioContractError):
        FieldEvidence(name="payment_status", state=FieldState.UNAVAILABLE,
                      unavailable_reason=bad)


def test_unavailable_must_not_disguise_an_observation() -> None:
    with pytest.raises(ScenarioContractError, match="must not claim"):
        FieldEvidence(
            name="payment_status", state=FieldState.UNAVAILABLE,
            unavailable_reason="not_provided", evidence_digest=FIELD_DIGEST,
        )


def test_no_external_labels_remote_coaching_or_raw_values_in_schema() -> None:
    row = observation(ScenarioId.APP_05)
    for prohibited in ("confirmed_fraud", "remote_coaching", "risk_score",
                       "raw_customer_id", "label_observed_after_event"):
        with pytest.raises(ScenarioContractError, match="unknown"):
            replace(row, fields=row.fields + (measured(prohibited),))


def test_duplicate_evidence_and_mutable_containers_rejected() -> None:
    row = observation(ScenarioId.MM_02)
    with pytest.raises(ScenarioContractError, match="duplicated"):
        replace(row, fields=row.fields + (row.fields[0],))
    with pytest.raises(ScenarioContractError, match="immutable"):
        replace(row, fields=list(row.fields))


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("available_at", AT + timedelta(microseconds=1)),
        ("observed_at", datetime(2026, 10, 30, 12)),
        ("evidence_digest", "not-a-digest"),
        ("source_ref", "raw customer identifier"),
    ],
)
def test_coverage_revalidates_forged_field_before_claiming_coverage(
    attribute: str, value: object,
) -> None:
    # An unchecked deserializer or object.__setattr__ can bypass frozen
    # dataclass construction; consumption must not trust prior validation.
    row = observation(ScenarioId.MM_05)
    object.__setattr__(row.fields[0], attribute, value)
    with pytest.raises(ScenarioContractError):
        inspect(row)


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("decision_cutoff", AT - timedelta(seconds=1)),
        ("mapping_version", "bad version with spaces"),
    ],
)
def test_coverage_revalidates_forged_packet_before_claiming_coverage(
    attribute: str, value: object,
) -> None:
    row = observation(ScenarioId.APP_01)
    object.__setattr__(row, attribute, value)
    with pytest.raises(ScenarioContractError):
        inspect(row)


def test_coverage_rejects_forged_mutable_evidence_container() -> None:
    row = observation(ScenarioId.APP_05)
    object.__setattr__(row, "fields", list(row.fields))
    with pytest.raises(ScenarioContractError, match="immutable"):
        inspect(row)


def test_immutable_and_field_order_independent_digest() -> None:
    row = observation(ScenarioId.APP_01)
    assert row.fingerprint() == replace(row, fields=tuple(reversed(row.fields))).fingerprint()
    assert row.fingerprint() != replace(
        row, mapping_version="2",
    ).fingerprint()
    with pytest.raises(FrozenInstanceError):
        row.tenant_ref = "other"  # type: ignore[misc]


def test_chronology_naive_timestamp_and_wrong_dataset_shapes_rejected() -> None:
    row = observation(ScenarioId.ATO_06)
    with pytest.raises(ScenarioContractError, match="chronology"):
        replace(row, received_at=AT - timedelta(seconds=1))
    with pytest.raises(ScenarioContractError, match="chronology"):
        replace(row, decision_cutoff=AT - timedelta(seconds=1))
    with pytest.raises(ScenarioContractError, match="timezone-aware"):
        replace(row, occurred_at=datetime(2026, 10, 30, 12))
    with pytest.raises(ScenarioContractError, match="digest"):
        replace(row, dataset_digest="not-a-digest")


@pytest.mark.parametrize(
    "path", ["src/gasha/api/main.py", "src/gasha/worker.py",
             "src/gasha/decision/service.py", "src/gasha/poc/readiness.py",
             "src/gasha/ingestion/postgres_atomic_outcomes.py"],
)
def test_contract_not_wired_to_protected_or_authoritative_paths(path: str) -> None:
    assert "scenario_observations" not in Path(path).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "attribute,bad",
    [
        ("available_at", AT + timedelta(seconds=1)),
        ("observed_at", AT + timedelta(seconds=1)),
        ("evidence_digest", "forged"),
        ("source_version", "untrusted source"),
        ("state", "observed"),
    ],
)
def test_direct_fingerprint_rejects_mutated_field_evidence(
    attribute: str, bad: object,
) -> None:
    row = observation(ScenarioId.MM_02)
    object.__setattr__(row.fields[0], attribute, bad)
    with pytest.raises(ScenarioContractError):
        row.fingerprint()


@pytest.mark.parametrize(
    "attribute,bad",
    [
        ("decision_cutoff", AT - timedelta(seconds=1)),
        ("mapping_version", "bad version"),
        ("tenant_ref", "other-tenant"),
    ],
)
def test_direct_fingerprint_revalidates_mutated_packet(
    attribute: str, bad: object,
) -> None:
    row = observation(ScenarioId.ATO_02)
    object.__setattr__(row, attribute, bad)
    if attribute == "tenant_ref":
        # A changed but well-formed tenant reference is a *different* digest;
        # scope authentication belongs to coverage's expected_tenant check.
        assert row.fingerprint() != observation(ScenarioId.ATO_02).fingerprint()
    else:
        with pytest.raises(ScenarioContractError):
            row.fingerprint()


def test_direct_fingerprint_rejects_mutated_field_container() -> None:
    row = observation(ScenarioId.APP_05)
    object.__setattr__(row, "fields", list(row.fields))
    with pytest.raises(ScenarioContractError, match="immutable"):
        row.fingerprint()


@pytest.mark.parametrize("target,attribute", [
    ("packet", "tenant_ref"), ("packet", "fields"),
    ("field", "observed_at"), ("field", "evidence_digest"),
])
def test_missing_slotted_attributes_fail_closed_at_digest_and_coverage(
    target: str, attribute: str,
) -> None:
    row = observation(ScenarioId.MM_02)
    object.__delattr__(row if target == "packet" else row.fields[0], attribute)
    with pytest.raises(ScenarioContractError, match="missing required"):
        row.fingerprint()
    with pytest.raises(ScenarioContractError, match="missing required"):
        inspect(row)
