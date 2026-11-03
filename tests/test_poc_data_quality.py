"""#48: synthetic aggregate-only data-quality negative and positive evidence."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5
from zoneinfo import ZoneInfo

import pytest

from gasha.ingestion.contracts import InboundBankEvent
from gasha.poc.data_quality import (
    DataQualityScope,
    QualityObservation,
    UseCase,
    inspect_reference_quality,
)

AT = datetime(2026, 1, 1, 12, tzinfo=UTC)


def scope(**changes: object) -> DataQualityScope:
    values = {
        "tenant_id": "synthetic-tenant",
        "dataset_digest": "a" * 64,
        "schema_version": "1.0",
        "mapping_version": "reference-1",
        "configuration_version": "config-1",
        "window_start": AT - timedelta(days=1),
        "window_end": AT + timedelta(days=1),
        "label_cutoff": AT + timedelta(days=4),
    }
    values.update(changes)
    return DataQualityScope(**values)


def candidate(
    name: str = "normal",
    *,
    uc: UseCase = UseCase.UC01,
    payload_changes: dict[str, object] | None = None,
    event_changes: dict[str, object] | None = None,
    label: bool | None = None,
    confirmed_at: datetime | None = None,
    alerted: bool | None = None,
) -> QualityObservation:
    payload: dict[str, object] = {
        "event_id": str(uuid5(NAMESPACE_URL, f"synthetic-data-quality:{name}")),
        "occurred_at": AT.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "125.00",
        "currency": "ETB",
        "sender_customer_id": "synthetic-customer-secret",
        "sender_account_id": "synthetic-account-secret",
        "beneficiary_id": "synthetic-beneficiary-secret",
        "beneficiary_type": "external",
        "destination_institution_id": "synthetic-institution-secret",
        "correlation_id": "synthetic-correlation-secret",
        "kind": "authentication",
        "subtype": "login_success",
        "customer_id": "synthetic-customer-secret",
    }
    if payload_changes:
        payload.update(payload_changes)
    kwargs = {
        "tenant_id": "synthetic-tenant",
        "schema_version": "1.0",
        "source_system": "synthetic-system",
        "received_at": AT + timedelta(minutes=1),
        "payload": payload,
    }
    if event_changes:
        kwargs.update(event_changes)
    event = InboundBankEvent(**kwargs)
    return QualityObservation(
        use_case=uc, event=event, confirmed_fraud=label,
        confirmed_at=confirmed_at, alerted=alerted,
    )


def result_for(*observations: QualityObservation, uc: UseCase = UseCase.UC01) -> dict:
    report = inspect_reference_quality(scope(), observations).to_dict()
    return next(row for row in report["use_cases"] if row["use_case"] == uc.value)


def test_synthetic_mixed_uc_population_and_non_pii_serialization() -> None:
    cases = (
        candidate("a", payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
                  label=True, confirmed_at=AT + timedelta(days=1), alerted=True),
        candidate("b", uc=UseCase.UC02, alerted=False),
        candidate("c", uc=UseCase.UC03),
    )
    report = inspect_reference_quality(scope(), cases).to_dict()
    a, b, c = report["use_cases"]
    assert [row["accepted"] for row in (a, b, c)] == [1, 1, 1]
    assert a["labels"] == {"positive": 1, "negative": 0, "unlabelled": 0}
    assert a["alerts"] == {"alerted": 1, "not_alerted": 0, "unknown": 0}
    assert a["optional_signals"]["beneficiary_risk"]["available"] == {
        "count": 1, "denominator": 1, "rate": 1.0, "undefined_reason": None
    }
    assert a["optional_signals"]["relationship_risk"]["unavailable"] == 1
    assert b["labels"]["unlabelled"] == 1 and c["alerts"]["unknown"] == 1
    assert report["bank_data_verified"] is False
    assert report["enforcement_activated"] is False
    serialized = json.dumps(report, allow_nan=False)
    for secret in ("synthetic-customer-secret", "synthetic-account-secret",
                   "synthetic-beneficiary-secret", "synthetic-correlation-secret"):
        assert secret not in serialized
    assert "synthetic-data-quality:a" not in serialized


@pytest.mark.parametrize("field", [
    "event_id", "occurred_at", "channel", "transaction_type", "amount", "currency",
    "sender_customer_id", "sender_account_id", "beneficiary_id",
    "beneficiary_type", "correlation_id", "destination_institution_id",
])
def test_missing_required_payment_field_rejected(field: str) -> None:
    row = result_for(candidate(payload_changes={field: None}))
    assert row["rejected"] == 1
    assert row["accepted"] == 0
    assert "missing." + field in row["checks"] or "invalid." + field in row["checks"]


@pytest.mark.parametrize("field", ["event_id", "occurred_at", "kind", "subtype", "customer_id"])
def test_missing_journey_field_rejected(field: str) -> None:
    row = result_for(candidate(uc=UseCase.UC03, payload_changes={field: None}), uc=UseCase.UC03)
    assert row["rejected"] == 1


@pytest.mark.parametrize("changes,code", [
    ({"event_id": "not-a-uuid"}, "invalid.event_id"),
    ({"occurred_at": "2026-01-01T12:00:00"}, "invalid.occurred_at"),
    ({"occurred_at": (AT + timedelta(days=2)).isoformat()}, "event_outside_window"),
    ({"amount": "NaN"}, "invalid.amount"),
    ({"amount": "Infinity"}, "invalid.amount"),
    ({"amount": "-1"}, "invalid.amount"),
    ({"currency": "eth"}, "invalid.currency"),
    ({"beneficiary_type": "external", "destination_institution_id": ""},
     "missing.destination_institution_id"),
    ({"sender_customer_id": "  "}, "invalid.sender_customer_id"),
])
def test_invalid_payment_value_rejected(changes: dict[str, object], code: str) -> None:
    row = result_for(candidate(payload_changes=changes))
    assert row["rejected"] == 1
    assert code in row["checks"]


def test_wrong_tenant_schema_duplicate_and_receive_clock() -> None:
    valid = candidate()
    wrong_tenant = candidate("wrong", event_changes={"tenant_id": "other-tenant"})
    wrong_schema = candidate("schema", event_changes={"schema_version": "2.0"})
    early_receipt = candidate("early", event_changes={"received_at": AT - timedelta(minutes=1)})
    row = result_for(valid, valid, wrong_tenant, wrong_schema, early_receipt)
    assert row["total"] == 5 and row["accepted"] == 1 and row["rejected"] == 4
    assert row["checks"]["duplicate.event_id"] == 1
    assert row["checks"]["tenant_mismatch"] == 1
    assert row["checks"]["schema_mismatch"] == 1
    assert row["checks"]["invalid.receipt_order"] == 1


def test_future_and_naive_receipt_rejected() -> None:
    row = result_for(
        candidate("a", event_changes={"received_at": datetime(2026, 1, 1, 12)}),
        candidate("b", event_changes={"received_at": AT + timedelta(days=5)}),
        candidate("c", event_changes={"received_at": None}),
    )
    assert row["rejected"] == 3
    assert row["checks"]["invalid.received_at"] == 2
    assert row["checks"]["invalid.receipt_order"] == 1


@pytest.mark.parametrize("invalid_received", [
    "not-a-datetime", 0, False, [], {}, None, datetime(2026, 1, 1, 12),
])
def test_unvalidated_receipt_type_quarantined_without_poisoning_valid_row(
    invalid_received: object,
) -> None:
    """Bad adapter model_copy data must not crash inspection or reserve an event ID."""
    valid = candidate(
        "malformed-receipt",
        payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    baseline = result_for(valid)
    corrupted = replace(valid, event=valid.event.model_copy(
        update={"received_at": invalid_received},
    ))
    for observed in ((corrupted, valid), (valid, corrupted)):
        row = result_for(*observed)
        assert row["total"] == 2
        assert row["accepted"] == 1
        assert row["rejected"] == 1
        assert row["checks"] == {"invalid.received_at": 1}
        assert row["labels"] == {"positive": 1, "negative": 0, "unlabelled": 0}
        assert row["alerts"] == {"alerted": 1, "not_alerted": 0, "unknown": 0}
        assert row["optional_signals"] == baseline["optional_signals"]
        assert row["acceptance"] == {
            "count": 1, "denominator": 2, "rate": 0.5, "undefined_reason": None,
        }


def test_malformed_receipt_does_not_suppress_independent_quality_failures() -> None:
    """Aggregate error counts retain all independently detectable defects."""
    good = candidate(
        "multi-defect", payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    damaged_event = good.event.model_copy(update={
        "received_at": None,
        "tenant_id": "synthetic-other-tenant",
        "schema_version": "wrong-schema",
        "payload": dict(good.event.payload, sender_customer_id=None),
    })
    damaged = replace(
        good, event=damaged_event, confirmed_at=AT - timedelta(minutes=1),
    )
    baseline = result_for(good)
    for observed in ((damaged, good), (good, damaged)):
        row = result_for(*observed)
        assert row["total"] == 2 and row["accepted"] == 1 and row["rejected"] == 1
        assert row["checks"] == {
            "invalid.label_order": 1,
            "invalid.received_at": 1,
            "invalid.sender_customer_id": 1,
            "missing.sender_customer_id": 1,
            "schema_mismatch": 1,
            "tenant_mismatch": 1,
        }
        assert "duplicate.event_id" not in row["checks"]
        assert row["labels"] == baseline["labels"]
        assert row["alerts"] == baseline["alerts"]
        assert row["optional_signals"] == baseline["optional_signals"]
        assert row["acceptance"]["count"] == 1
        assert row["acceptance"]["denominator"] == 2


def test_received_at_utc_order_and_cutoff_across_dst_fold() -> None:
    """A repeated local hour must compare actual instants, not wall-clock values."""
    zone = ZoneInfo("America/New_York")
    occurred = datetime(2026, 11, 1, 1, 45, tzinfo=zone, fold=0)
    received = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    assert occurred.astimezone(UTC) < received.astimezone(UTC)
    test_scope = scope(
        window_start=occurred.astimezone(UTC) - timedelta(minutes=1),
        window_end=received.astimezone(UTC),
        label_cutoff=received.astimezone(UTC),
    )
    observation = candidate(
        "dst-fold-receipt",
        payload_changes={"occurred_at": occurred.isoformat()},
        event_changes={"received_at": received},
    )

    def inspect(rewritten: QualityObservation) -> dict[str, object]:
        report = inspect_reference_quality(test_scope, (rewritten,)).to_dict()
        return report["use_cases"][0]

    assert inspect(observation)["accepted"] == 1
    equivalent = replace(observation, event=observation.event.model_copy(update={
        "received_at": received.astimezone(timezone(timedelta(hours=-5))),
    }))
    assert inspect(equivalent)["accepted"] == 1
    late = replace(observation, event=observation.event.model_copy(update={
        "received_at": received.astimezone(UTC) + timedelta(microseconds=1),
    }))
    assert inspect(late)["checks"] == {"invalid.receipt_order": 1}
    early = replace(observation, event=observation.event.model_copy(update={
        "received_at": datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=0),
    }))
    assert inspect(early)["checks"] == {"invalid.receipt_order": 1}


@pytest.mark.parametrize("invalid_payload", [
    None, "not-an-object", [], ["event_id"], (), ("event_id",), range(2), 0, False,
])
def test_unvalidated_nonmapping_payload_is_quarantined_without_crashing(
    invalid_payload: object,
) -> None:
    """Synthetic adapter bypasses must not abort the report or poison deduplication."""
    valid = candidate(
        "nonmapping-body", payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    baseline = result_for(valid)
    corrupted = replace(valid, event=valid.event.model_copy(
        update={"payload": invalid_payload},
    ))
    for rows in ((corrupted, valid), (valid, corrupted)):
        report = result_for(*rows)
        assert report["total"] == 2
        assert report["accepted"] == 1 and report["rejected"] == 1
        assert report["checks"]["invalid.payload"] == 1
        assert "duplicate.event_id" not in report["checks"]
        assert report["labels"] == baseline["labels"]
        assert report["alerts"] == baseline["alerts"]
        assert report["optional_signals"] == baseline["optional_signals"]
        assert report["acceptance"] == {
            "count": 1, "denominator": 2, "rate": 0.5, "undefined_reason": None,
        }


def test_nonmapping_payload_preserves_independent_scope_failures() -> None:
    """A corrupt body must not hide an independently wrong tenant or schema."""
    valid = candidate("nonmapping-scope")
    invalid = replace(valid, event=valid.event.model_copy(update={
        "payload": [],
        "tenant_id": "other-tenant",
        "schema_version": "different-schema",
    }))
    for rows in ((invalid, valid), (valid, invalid)):
        report = result_for(*rows)
        assert report["accepted"] == 1 and report["rejected"] == 1
        assert report["checks"]["invalid.payload"] == 1
        assert report["checks"]["tenant_mismatch"] == 1
        assert report["checks"]["schema_mismatch"] == 1
        assert "duplicate.event_id" not in report["checks"]



@pytest.mark.parametrize("invalid_payload", [
    None, "invalid-opaque-body", [], ["event_id"], (), ("event_id",), range(2), 0, False,
])
@pytest.mark.parametrize("invalid_received", [
    "invalid-receipt", None, 0, False, datetime(2026, 1, 1, 12),
])
def test_combined_nonmapping_payload_and_invalid_receipt_are_quarantined(
    invalid_payload: object, invalid_received: object,
) -> None:
    """Two adapter-bypass defects must coexist without crashes or dedup poisoning."""
    valid = candidate(
        "combined-adapter-bypass",
        payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    baseline = result_for(valid)
    bad = replace(valid, event=valid.event.model_copy(update={
        "payload": invalid_payload,
        "received_at": invalid_received,
    }))
    before = result_for(bad, valid)
    after = result_for(valid, bad)
    assert before == after
    for row in (before, after):
        assert row["total"] == 2
        assert row["accepted"] == 1 and row["rejected"] == 1
        assert row["checks"]["invalid.payload"] == 1
        assert row["checks"]["invalid.received_at"] == 1
        # A structurally invalid body also produces deterministic missing and
        # invalid field codes, but must not create extra raw observation rows.
        assert row["checks"]["missing.event_id"] == 1
        assert row["checks"]["invalid.event_id"] == 1
        assert row["checks"]["missing.occurred_at"] == 1
        assert row["checks"]["invalid.occurred_at"] == 1
        assert "duplicate.event_id" not in row["checks"]
        assert all(count == 1 for count in row["checks"].values())
        assert row["labels"] == baseline["labels"]
        assert row["alerts"] == baseline["alerts"]
        assert row["optional_signals"] == baseline["optional_signals"]
        assert row["acceptance"] == {
            "count": 1, "denominator": 2, "rate": 0.5, "undefined_reason": None,
        }
        assert row["optional_signals"]["beneficiary_risk"]["available"] == {
            "count": 1, "denominator": 1, "rate": 1.0, "undefined_reason": None,
        }


def test_combined_corruption_keeps_independent_scope_and_schema_failures() -> None:
    valid = candidate(
        "combined-scope", payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    bad = replace(valid, event=valid.event.model_copy(update={
        "payload": ("not", "a", "mapping"),
        "received_at": "invalid",
        "tenant_id": "wrong-tenant",
        "schema_version": "wrong-schema",
    }))
    for observations in ((bad, valid), (valid, bad)):
        row = result_for(*observations)
        assert row["total"] == 2 and row["accepted"] == 1 and row["rejected"] == 1
        for code in (
            "invalid.payload", "invalid.received_at",
            "tenant_mismatch", "schema_mismatch",
            "missing.event_id", "invalid.event_id",
        ):
            assert row["checks"][code] == 1
        assert "duplicate.event_id" not in row["checks"]
        assert row["labels"] == {"positive": 1, "negative": 0, "unlabelled": 0}
        assert row["alerts"] == {"alerted": 1, "not_alerted": 0, "unknown": 0}
        assert row["optional_signals"]["beneficiary_risk"]["available"]["count"] == 1
        assert row["acceptance"]["denominator"] == 2


def test_optional_missing_is_unavailable_not_zero_or_rejection() -> None:
    good_zero = candidate("zero", payload_changes={"intelligence": {"device_session_risk": 0.0}},
                          uc=UseCase.UC03)
    missing = candidate("missing", uc=UseCase.UC03)
    invalid = candidate("invalid", uc=UseCase.UC03,
                        payload_changes={"intelligence": {"device_session_risk": "nope"}})
    row = result_for(good_zero, missing, invalid, uc=UseCase.UC03)
    assert row["accepted"] == 3
    assert row["optional_signals"]["device_session_risk"]["available"]["count"] == 1
    assert row["optional_signals"]["device_session_risk"]["unavailable"] == 2
    assert row["checks"]["invalid_optional.device_session_risk"] == 1


def test_post_cutoff_label_unmatured_and_no_label_never_count_as_negative() -> None:
    row = result_for(
        candidate("future-label", label=True, confirmed_at=AT + timedelta(days=5)),
        candidate("unknown-time", label=False),
        candidate("unknown-label"),
        candidate("mature-negative", label=False, confirmed_at=AT + timedelta(days=3)),
    )
    assert row["accepted"] == 4
    assert row["labels"] == {"positive": 0, "negative": 1, "unlabelled": 3}


def test_different_offsets_same_instant_are_equivalent() -> None:
    shifted = timezone(timedelta(hours=-5))
    normal = candidate("normal")
    clock_rewritten = replace(normal, event=normal.event.model_copy(update={
        "payload": dict(normal.event.payload, occurred_at=AT.astimezone(shifted).isoformat()),
        "received_at": (AT + timedelta(minutes=1)).astimezone(shifted),
    }))
    row = result_for(clock_rewritten)
    assert row["accepted"] == 1


@pytest.mark.parametrize("changes", [
    {"tenant_id": " white space "}, {"tenant_id": "a@example.com"},
    {"dataset_digest": "A" * 64}, {"dataset_digest": "g" * 64},
    {"mapping_version": ""}, {"window_start": datetime(2025, 1, 1)},
    {"window_end": AT - timedelta(days=10)},
    {"label_cutoff": AT - timedelta(days=2)},
])
def test_bad_scope_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        scope(**changes)


@pytest.mark.parametrize("value", [0, 1, "true", 1.0, []])
def test_strict_label_types(value: object) -> None:
    if type(value) is bool:
        return
    with pytest.raises(ValueError):
        replace(candidate(), confirmed_fraud=value)


def test_empty_population_has_explicit_undefined_rates() -> None:
    report = inspect_reference_quality(scope(), ()).to_dict()
    assert all(row["total"] == 0 for row in report["use_cases"])
    assert all(row["acceptance"]["rate"] is None for row in report["use_cases"])
    assert all(row["acceptance"]["undefined_reason"] == "no_records"
               for row in report["use_cases"])
    json.dumps(report, allow_nan=False)


def test_invalid_label_before_event_quarantines_record() -> None:
    row = result_for(candidate(label=True, confirmed_at=AT - timedelta(minutes=1)))
    assert row["accepted"] == 0
    assert row["checks"]["invalid.label_order"] == 1


def test_unhashable_beneficiary_type_fails_closed_not_crashes() -> None:
    row = result_for(candidate(payload_changes={"beneficiary_type": ["external"]}))
    assert row["rejected"] == 1
    assert row["checks"]["invalid.beneficiary_type"] == 1


def test_invalid_optional_bool_and_oversized_integer_are_unavailable() -> None:
    row = result_for(candidate("bool", uc=UseCase.UC03,
                               payload_changes={"intelligence": {"device_session_risk": True}}),
                     candidate("huge", uc=UseCase.UC03,
                               payload_changes={"intelligence": {
                                   "device_session_risk": 10 ** 1000,
                               }}), uc=UseCase.UC03)
    assert row["accepted"] == 2
    assert row["optional_signals"]["device_session_risk"]["unavailable"] == 2
    assert row["checks"]["invalid_optional.device_session_risk"] == 2


def test_untrusted_quality_helper_has_no_live_python_consumer() -> None:
    from pathlib import Path

    code_root = Path(__file__).resolve().parents[1] / "src" / "gasha"
    for path in code_root.rglob("*.py"):
        if path.name == "data_quality.py":
            continue
        text = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(text, filename=str(path))):
            if isinstance(node, ast.Import):
                assert all(alias.name != "gasha.poc.data_quality"
                           for alias in node.names), str(path)
            if isinstance(node, ast.ImportFrom):
                assert node.module != "gasha.poc.data_quality", str(path)
                if node.module == "gasha.poc":
                    assert all(alias.name != "data_quality"
                               for alias in node.names), str(path)
        assert "inspect_reference_quality(" not in text, str(path)


@pytest.mark.parametrize(("reason", "payload_changes", "event_changes", "failure"), [
    ("wrong-tenant", {}, {"tenant_id": "other-tenant"}, "tenant_mismatch"),
    ("wrong-schema", {}, {"schema_version": "2.0"}, "schema_mismatch"),
    ("invalid-event-clock", {"occurred_at": "not-a-timestamp"}, {},
     "invalid.occurred_at"),
    ("invalid-receipt-clock", {}, {"received_at": AT - timedelta(minutes=1)},
     "invalid.receipt_order"),
    ("missing-required", {"sender_account_id": None}, {},
     "missing.sender_account_id"),
])
def test_quarantined_row_cannot_poison_in_scope_duplicate(
    reason: str, payload_changes: dict[str, object],
    event_changes: dict[str, object], failure: str,
) -> None:
    """Same UUID across scopes and malformed rows must be order-invariant."""
    observed_signal = {"intelligence": {"beneficiary_risk": 0.0}}
    valid = candidate(
        "shared-uuid-" + reason, payload_changes=observed_signal,
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    invalid = candidate(
        "shared-uuid-" + reason,
        payload_changes={**observed_signal, **payload_changes},
        event_changes=event_changes, label=False,
        confirmed_at=AT + timedelta(days=2), alerted=False,
    )
    baseline = result_for(valid)
    preceding = result_for(invalid, valid)
    following = result_for(valid, invalid)
    assert preceding == following
    for row in (preceding, following):
        assert row["total"] == 2
        assert row["accepted"] == 1 and row["rejected"] == 1
        assert row["checks"][failure] == 1
        assert "duplicate.event_id" not in row["checks"]
        assert row["labels"] == baseline["labels"] == {
            "positive": 1, "negative": 0, "unlabelled": 0,
        }
        assert row["alerts"] == baseline["alerts"] == {
            "alerted": 1, "not_alerted": 0, "unknown": 0,
        }
        assert row["optional_signals"] == baseline["optional_signals"]
        assert row["optional_signals"]["beneficiary_risk"]["available"]["count"] == 1


def test_same_scope_two_valid_same_uuid_still_reject_one_duplicate() -> None:
    valid = candidate(
        "actual-duplicate", payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    row = result_for(valid, valid)
    assert row["total"] == 2 and row["accepted"] == 1 and row["rejected"] == 1
    assert row["checks"] == {"duplicate.event_id": 1}
    assert row["labels"]["positive"] == 1
    assert row["alerts"]["alerted"] == 1
    assert row["optional_signals"]["beneficiary_risk"]["available"]["count"] == 1


@pytest.mark.parametrize(("uc", "expected"), [
    (UseCase.UC01, ("beneficiary_risk", "relationship_risk")),
    (UseCase.UC02, ("beneficiary_risk", "network_risk", "velocity_risk")),
    (UseCase.UC03, ("device_session_risk", "journey_risk")),
])
def test_versioned_provisional_uc_coverage_exact_contract(
    uc: UseCase, expected: tuple[str, ...],
) -> None:
    report = inspect_reference_quality(scope(), (candidate("matrix-" + uc, uc=uc),)).to_dict()
    assert report["schema_version"] == "gasha-synthetic-data-quality-2"
    assert report["provisional_coverage_matrix_version"] == "synthetic-uc-coverage-v2"
    row = next(row for row in report["use_cases"] if row["use_case"] == uc.value)
    assert tuple(row["optional_signals"]) == expected
    assert all(signal["available"]["count"] == 0 and signal["unavailable"] == 1
               for signal in row["optional_signals"].values())

@pytest.mark.parametrize("invalid_source", [
    None, "", " ", "bad source", "bad\\nsource", "vendor/source",
    0, False, [], {}, "x" * 81, "\\u00e9",
])
def test_corrupt_reference_source_is_quarantined_without_poisoning_id(
    invalid_source: object,
) -> None:
    """Unvalidated adapter updates cannot erase the synthetic source identity."""
    valid = candidate(
        "source-shared-id",
        payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
        label=True, confirmed_at=AT + timedelta(days=1), alerted=True,
    )
    damaged = replace(
        valid, event=valid.event.model_copy(update={"source_system": invalid_source}),
    )
    for observations in ((damaged, valid), (valid, damaged)):
        row = result_for(*observations)
        assert (row["total"], row["accepted"], row["rejected"]) == (2, 1, 1)
        assert row["checks"] == {"invalid.source_system": 1}
        assert row["labels"] == {"positive": 1, "negative": 0, "unlabelled": 0}
        assert row["alerts"] == {"alerted": 1, "not_alerted": 0, "unknown": 0}
        assert row["optional_signals"]["beneficiary_risk"]["available"]["count"] == 1


@pytest.mark.parametrize("use_case", list(UseCase))
@pytest.mark.parametrize("invalid_intelligence", [
    None, "", [], ["untrusted"], 17, True,
])
def test_malformed_optional_telemetry_container_is_visible_but_not_fabricated(
    use_case: UseCase, invalid_intelligence: object,
) -> None:
    """Malformed optional telemetry is unknown, not measured zero or a valid signal."""
    valid = candidate("telemetry-valid-" + use_case.value, uc=use_case, alerted=True)
    malformed = candidate(
        "telemetry-invalid-" + use_case.value, uc=use_case,
        payload_changes={"intelligence": invalid_intelligence}, alerted=False,
    )
    for observations in ((valid, malformed), (malformed, valid)):
        row = result_for(*observations, uc=use_case)
        assert (row["total"], row["accepted"], row["rejected"]) == (2, 2, 0)
        assert row["checks"] == {"invalid_optional.intelligence": 1}
        assert row["alerts"] == {"alerted": 1, "not_alerted": 1, "unknown": 0}
        for coverage in row["optional_signals"].values():
            assert coverage["available"]["count"] == 0
            assert coverage["unavailable"] == 2


def test_absent_optional_telemetry_has_no_false_malformed_warning() -> None:
    row = result_for(candidate("no-telemetry"))
    assert row["accepted"] == 1
    assert row["checks"] == {}
    assert all(
        coverage["unavailable"] == 1
        for coverage in row["optional_signals"].values()
    )


@pytest.mark.parametrize(("field", "corrupt", "check"), [
    ("confirmed_fraud", "true", "invalid.confirmed_fraud"),
    ("confirmed_fraud", 1, "invalid.confirmed_fraud"),
    ("confirmed_fraud", [], "invalid.confirmed_fraud"),
    ("alerted", "false", "invalid.alerted"),
    ("alerted", 1, "invalid.alerted"),
    ("alerted", {}, "invalid.alerted"),
    ("confirmed_at", "2026-01-01T12:00:00Z", "invalid.confirmed_at"),
    ("confirmed_at", datetime(2026, 1, 1, 12), "invalid.confirmed_at"),
    ("confirmed_at", False, "invalid.confirmed_at"),
])
def test_post_construction_quality_assertion_tamper_quarantined(
    field: str, corrupt: object, check: str,
) -> None:
    """Forged label and alert data must not contaminate valid KPI populations."""
    good = candidate(
        "tampered-quality-label", label=True,
        confirmed_at=AT + timedelta(days=1), alerted=True,
        payload_changes={"intelligence": {"beneficiary_risk": 0.0}},
    )
    bad = replace(good)
    object.__setattr__(bad, field, corrupt)
    for rows in ((bad, good), (good, bad)):
        row = result_for(*rows)
        assert (row["total"], row["accepted"], row["rejected"]) == (2, 1, 1)
        assert row["checks"] == {check: 1}
        assert "duplicate.event_id" not in row["checks"]
        assert row["labels"] == {"positive": 1, "negative": 0, "unlabelled": 0}
        assert row["alerts"] == {"alerted": 1, "not_alerted": 0, "unknown": 0}
        assert row["optional_signals"]["beneficiary_risk"]["available"]["count"] == 1


@pytest.mark.parametrize(("field", "corrupt"), [
    ("tenant_id", "raw@example.com"),
    ("dataset_digest", "A" * 64),
    ("window_start", AT + timedelta(days=7)),
    ("label_cutoff", "invalid-date"),
])
def test_tampered_quality_scope_rejected_before_report(
    field: str, corrupt: object,
) -> None:
    forged = scope()
    object.__setattr__(forged, field, corrupt)
    with pytest.raises(ValueError):
        inspect_reference_quality(forged, (candidate(),))


def test_quality_report_retains_validated_scope_snapshot() -> None:
    original = scope()
    report = inspect_reference_quality(original, (candidate(),))
    object.__setattr__(original, "tenant_id", "raw@example.com")
    assert report.to_dict()["scope"]["tenant_id"] == "synthetic-tenant"
    assert report.to_dict()["use_cases"][0]["accepted"] == 1


@pytest.mark.parametrize(("field", "corrupt"), [
    ("use_case", "UC-01"),
    ("event", "not-an-InboundBankEvent"),
])
def test_corrupted_quality_observation_type_rejected(
    field: str, corrupt: object,
) -> None:
    forged = candidate()
    object.__setattr__(forged, field, corrupt)
    with pytest.raises(ValueError):
        inspect_reference_quality(scope(), (forged,))
