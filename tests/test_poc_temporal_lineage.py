"""Issue #48 source-only historical feature lineage negative/positive tests."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.domain.models import BeneficiaryType, CanonicalTransaction, IntelligenceSnapshot
from gasha.poc.temporal_lineage import (
    HistoricalFeatureEnvelope,
    HistoricalLineageRejected,
    SignalLineage,
    assert_historical_snapshot_bound,
)

EVENT_TIME = datetime(2025, 6, 2, 12, tzinfo=UTC)
CUTOFF = EVENT_TIME + timedelta(seconds=2)
DATASET = "sha256:" + "a" * 64
EVENT = UUID(int=81)


def observation(name: str = "customer_risk") -> SignalLineage:
    return SignalLineage(
        name=name, value=0.2, source_ref="synthetic-source", source_version="signals-v1",
        as_of=EVENT_TIME - timedelta(minutes=5), available_at=EVENT_TIME,
    )


def envelope() -> HistoricalFeatureEnvelope:
    return HistoricalFeatureEnvelope(
        tenant_id="synthetic-tenant", event_id=EVENT, dataset_digest=DATASET,
        cohort_version="cohort-1", mapping_version="map-1",
        configuration_version="config-1", policy_version="policy-1",
        signal_policy_version="signals-1", occurred_at=EVENT_TIME,
        decision_cutoff=CUTOFF,
        signals=tuple(observation(name) for name in IntelligenceSnapshot.model_fields),
    )


def transaction() -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id="synthetic-tenant", event_id=EVENT, occurred_at=EVENT_TIME,
        channel="synthetic-channel", transaction_type="synthetic-payment",
        amount=Decimal("1.0"), currency="ETB", sender_customer_id="sample-1",
        sender_account_id="sample-2", beneficiary_id="sample-3",
        beneficiary_type=BeneficiaryType.INTERNAL, correlation_id="synthetic-4",
    )


def validate(env: HistoricalFeatureEnvelope | None = None) -> None:
    assert_historical_snapshot_bound(
        envelope() if env is None else env, transaction=transaction(),
        snapshot=IntelligenceSnapshot(**{n: 0.2 for n in IntelligenceSnapshot.model_fields}),
        expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
    )


def test_complete_synthetic_context_is_value_bound_but_not_verified() -> None:
    original = envelope()
    validate(original)
    reordered = replace(original, signals=tuple(reversed(original.signals)))
    assert original.fingerprint() == reordered.fingerprint()
    assert original.fingerprint().startswith("sha256:")
    assert original.unavailable_signals() == ()
    assert not hasattr(original, "verified")
    assert not hasattr(original, "ready")


@pytest.mark.parametrize("field", [
    "tenant_id", "event_id", "dataset_digest", "cohort_version", "mapping_version",
    "configuration_version", "policy_version", "signal_policy_version",
    "occurred_at", "decision_cutoff",
])
def test_material_scope_changes_alter_fingerprint(field: str) -> None:
    original = envelope()
    replacements: dict[str, Any] = {
        "tenant_id": "other-tenant", "event_id": UUID(int=82),
        "dataset_digest": "sha256:" + "b" * 64, "cohort_version": "cohort-2",
        "mapping_version": "map-2", "configuration_version": "config-2",
        "policy_version": "policy-2", "signal_policy_version": "signals-2",
        "occurred_at": EVENT_TIME - timedelta(seconds=1),
        "decision_cutoff": CUTOFF + timedelta(seconds=1),
    }
    other = replace(original, **{field: replacements[field]})
    assert other.fingerprint() != original.fingerprint()


@pytest.mark.parametrize("field", [
    "value", "source_ref", "source_version", "as_of", "available_at",
])
def test_each_signal_provenance_change_alters_fingerprint(field: str) -> None:
    replacements: dict[str, Any] = {
        "value": 0.3, "source_ref": "other-source", "source_version": "signals-v2",
        "as_of": EVENT_TIME - timedelta(minutes=7),
        "available_at": EVENT_TIME + timedelta(seconds=1),
    }
    original = envelope()
    new = replace(original.signals[0], **{field: replacements[field]})
    modified = replace(original, signals=(new, *original.signals[1:]))
    assert modified.fingerprint() != original.fingerprint()
    if field == "value":
        with pytest.raises(HistoricalLineageRejected, match="value contradicts"):
            validate(modified)


def test_newer_source_values_cannot_enter_old_decision() -> None:
    original = envelope()
    late = replace(
        original.signals[0],
        as_of=CUTOFF + timedelta(seconds=1),
        available_at=CUTOFF + timedelta(seconds=1),
    )
    with pytest.raises(HistoricalLineageRejected, match="post-cutoff feature"):
        replace(original, signals=(late, *original.signals[1:]))


def test_as_of_cannot_follow_recorded_availability() -> None:
    with pytest.raises(HistoricalLineageRejected, match="as-of follows"):
        replace(observation(), as_of=CUTOFF, available_at=EVENT_TIME)


def test_feature_available_exactly_at_cutoff_is_accepted() -> None:
    original = envelope()
    newest = replace(original.signals[0], as_of=CUTOFF, available_at=CUTOFF)
    validate(replace(original, signals=(newest, *original.signals[1:])))


def test_unavailable_telemetry_is_explicit_and_blocks_numeric_replay() -> None:
    original = envelope()
    missing = SignalLineage(name="customer_risk", value=None, unavailable_reason="not-collected")
    deficient = replace(original, signals=(missing, *original.signals[1:]))
    assert deficient.unavailable_signals() == ("customer_risk",)
    assert deficient.fingerprint() != original.fingerprint()
    with pytest.raises(HistoricalLineageRejected, match="unavailable telemetry"):
        validate(deficient)


@pytest.mark.parametrize("fields", [
    {"source_ref": "source-1"},
    {"source_version": "signals-v1"},
    {"as_of": EVENT_TIME},
    {"available_at": EVENT_TIME},
])
def test_unavailable_signal_cannot_claim_measured_source(fields: dict[str, Any]) -> None:
    with pytest.raises(HistoricalLineageRejected, match="unavailable signal"):
        SignalLineage(name="customer_risk", value=None, unavailable_reason="missing", **fields)


@pytest.mark.parametrize("value", [True, 0, float("nan"), float("inf"), -0.1, 1.1])
def test_invalid_signal_measurements_fail_closed(value: Any) -> None:
    with pytest.raises(HistoricalLineageRejected):
        replace(observation(), value=value)


@pytest.mark.parametrize("bad", ["", "has space", "raw\npii", "é", " source", "x" * 129])
def test_identifier_input_is_bounded_ascii(bad: str) -> None:
    with pytest.raises(HistoricalLineageRejected):
        replace(observation(), source_ref=bad)


def test_duplicate_or_missing_signal_fails_before_fingerprint() -> None:
    original = envelope()
    with pytest.raises(HistoricalLineageRejected, match="duplicate"):
        replace(original, signals=(*original.signals[:-1], original.signals[0]))
    with pytest.raises(HistoricalLineageRejected, match="missing explicit"):
        replace(original, signals=original.signals[:-1])


@pytest.mark.parametrize("altered", ["tenant", "event", "dataset", "timestamp", "risk"])
def test_reject_cross_scope_and_changed_scores(altered: str) -> None:
    env = envelope()
    tx = transaction()
    snapshot = IntelligenceSnapshot(**{n: 0.2 for n in IntelligenceSnapshot.model_fields})
    tenant = "synthetic-tenant"
    dataset = DATASET
    if altered == "tenant":
        tenant = "other-tenant"
    elif altered == "event":
        tx = tx.model_copy(update={"event_id": UUID(int=82)})
    elif altered == "dataset":
        dataset = "sha256:" + "b" * 64
    elif altered == "timestamp":
        tx = tx.model_copy(update={"occurred_at": EVENT_TIME + timedelta(seconds=1)})
    else:
        snapshot = snapshot.model_copy(update={"customer_risk": 0.9})
    with pytest.raises(HistoricalLineageRejected):
        assert_historical_snapshot_bound(
            env, transaction=tx, snapshot=snapshot,
            expected_tenant=tenant, expected_dataset_digest=dataset,
        )


def test_dst_repeated_local_time_cannot_alias_same_source_provenance() -> None:
    zone = ZoneInfo("America/New_York")
    first = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    second = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=1)
    base = replace(envelope(), occurred_at=datetime(2026, 11, 1, 4, tzinfo=UTC),
                   decision_cutoff=datetime(2026, 11, 1, 7, tzinfo=UTC))
    early = replace(base.signals[0], as_of=first, available_at=first)
    late = replace(base.signals[0], as_of=second, available_at=second)
    first_env = replace(base, signals=(early, *base.signals[1:]))
    second_env = replace(base, signals=(late, *base.signals[1:]))
    assert first_env.fingerprint() != second_env.fingerprint()
    assert early.available_at != late.available_at


def test_equivalent_utc_instants_in_offsets_hash_same() -> None:
    original = envelope()
    offset = timezone(timedelta(hours=-4))
    signals = tuple(
        replace(s, as_of=s.as_of.astimezone(offset), available_at=s.available_at.astimezone(offset))
        for s in original.signals
    )
    equivalent = replace(
        original, occurred_at=EVENT_TIME.astimezone(offset),
        decision_cutoff=CUTOFF.astimezone(offset), signals=signals,
    )
    assert original.fingerprint() == equivalent.fingerprint()


def test_timestamp_and_metadata_forgery_are_rejected_when_invalid() -> None:
    with pytest.raises(HistoricalLineageRejected, match="timezone-aware"):
        replace(envelope(), decision_cutoff=datetime(2025, 6, 2, 12))
    with pytest.raises(HistoricalLineageRejected, match="precedes event"):
        replace(envelope(), decision_cutoff=EVENT_TIME - timedelta(seconds=1))
    with pytest.raises(HistoricalLineageRejected, match="dataset_digest"):
        replace(envelope(), dataset_digest="sha256:" + "Z" * 64)
    with pytest.raises(HistoricalLineageRejected, match="opaque canonical"):
        replace(envelope(), policy_version="bad\nversion")


def test_lineage_helper_is_not_imported_or_consulted_by_live_paths() -> None:
    """Do not wire caller-supplied fingerprints into live replay or readiness."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "gasha"
    helper = root / "poc" / "temporal_lineage.py"
    offline = root / "poc" / "matured_lineage_replay.py"
    assert helper.is_file()
    assert offline.is_file()
    forbidden = ("temporal_lineage", "HistoricalFeatureEnvelope", "assert_historical_snapshot_bound")
    consumers = []
    wired_offline = []
    for candidate in root.rglob("*.py"):
        if candidate == helper:
            continue
        source = candidate.read_text(encoding="utf-8")
        if candidate == offline:
            # Only the intentionally opt-in, synthetic-only preflight may use
            # lineage. Never let its caller assertions reach a runtime path.
            assert "from gasha.poc.temporal_lineage import" in source
            assert "from gasha.poc.historical import" in source
            continue
        if any(marker in source for marker in forbidden):
            consumers.append(candidate.relative_to(root).as_posix())
        if "matured_lineage_replay" in source or "replay_offline_matured_lineage" in source:
            wired_offline.append(candidate.relative_to(root).as_posix())
    assert consumers == [], f"Unreviewed production lineage integration: {consumers}"
    assert wired_offline == [], f"Offline helper wired into production path: {wired_offline}"


@pytest.mark.parametrize(("field", "bad"), [
    ("available_at", CUTOFF + timedelta(microseconds=1)),
    ("as_of", CUTOFF + timedelta(microseconds=1)),
    ("as_of", EVENT_TIME + timedelta(seconds=1)),  # later than availability
    ("source_version", "bad\nsource"),
    ("value", 2.0),
    ("value", float("nan")),
    ("value", True),
    ("unavailable_reason", "invented"),
])
def test_tampered_signal_is_revalidated_at_every_consumer(
    field: str, bad: Any,
) -> None:
    original = envelope()
    object.__setattr__(original.signals[0], field, bad)
    with pytest.raises(HistoricalLineageRejected):
        original.fingerprint()
    with pytest.raises(HistoricalLineageRejected):
        original.unavailable_signals()
    with pytest.raises(HistoricalLineageRejected):
        validate(original)


@pytest.mark.parametrize(("field", "bad"), [
    ("tenant_id", "bad\ntenant"),
    ("decision_cutoff", EVENT_TIME - timedelta(microseconds=1)),
    ("signals", ("untyped",)),
    ("signals", ()),
])
def test_tampered_envelope_cannot_bypass_historical_assertion(
    field: str, bad: Any,
) -> None:
    original = envelope()
    object.__setattr__(original, field, bad)
    with pytest.raises(HistoricalLineageRejected):
        original.fingerprint()
    with pytest.raises(HistoricalLineageRejected):
        validate(original)



@pytest.mark.parametrize("consumer", ["fingerprint", "unavailable_signals", "snapshot_binding"])
@pytest.mark.parametrize(("kind", "field"), [
    ("envelope", "signals"),
    ("envelope", "tenant_id"),
    ("envelope", "event_id"),
    ("envelope", "dataset_digest"),
    ("envelope", "decision_cutoff"),
    ("envelope", "occurred_at"),
    ("envelope", "policy_version"),
    ("signal", "name"),
    ("signal", "value"),
    ("signal", "source_ref"),
    ("signal", "source_version"),
    ("signal", "as_of"),
    ("signal", "available_at"),
    ("signal", "unavailable_reason"),
])
def test_deleted_slotted_fields_reject_at_every_consumer(
    kind: str, field: str, consumer: str,
) -> None:
    """A deleted required member cannot escape expected quarantine as AttributeError."""
    original = envelope()
    record = original if kind == "envelope" else original.signals[0]
    object.__delattr__(record, field)
    with pytest.raises(
        HistoricalLineageRejected, match="missing required historical lineage field",
    ) as rejected:
        if consumer == "fingerprint":
            original.fingerprint()
        elif consumer == "unavailable_signals":
            original.unavailable_signals()
        else:
            validate(original)
    assert "synthetic-tenant" not in str(rejected.value)
    assert "synthetic-source" not in str(rejected.value)

def test_valid_low_level_score_change_gets_new_identity_but_not_trusted_replay() -> None:
    original = envelope()
    original_fingerprint = original.fingerprint()
    object.__setattr__(original.signals[0], "value", 0.3)
    assert original.fingerprint() != original_fingerprint
    with pytest.raises(HistoricalLineageRejected, match="value contradicts"):
        validate(original)


class _LineageCallbackTZ(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self.calls += 1
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        return "untrusted"


class _LineageCallbackDateTime(datetime):
    calls = 0

    def utcoffset(self) -> timedelta:
        type(self).calls += 1
        return timedelta(0)


def _lineage_hostile_clock(kind: str, at: datetime) -> tuple[datetime, _LineageCallbackTZ | None]:
    if kind == "tzinfo":
        zone = _LineageCallbackTZ()
        return datetime(
            at.year, at.month, at.day, at.hour, at.minute, at.second,
            at.microsecond, tzinfo=zone,
        ), zone
    _LineageCallbackDateTime.calls = 0
    return _LineageCallbackDateTime(
        at.year, at.month, at.day, at.hour, at.minute, at.second,
        at.microsecond, tzinfo=UTC,
    ), None


def _assert_lineage_clock_uninvoked(zone: _LineageCallbackTZ | None) -> None:
    assert (zone.calls if zone is not None else _LineageCallbackDateTime.calls) == 0


@pytest.mark.parametrize("kind", ["tzinfo", "datetime_subclass"])
@pytest.mark.parametrize(("object_kind", "field", "at"), [
    ("signal", "as_of", EVENT_TIME),
    ("signal", "available_at", EVENT_TIME),
    ("envelope", "occurred_at", EVENT_TIME),
    ("envelope", "decision_cutoff", CUTOFF),
])
def test_offline_lineage_constructor_rejects_callback_clocks_before_execution(
    kind: str, object_kind: str, field: str, at: datetime,
) -> None:
    hostile, zone = _lineage_hostile_clock(kind, at)
    with pytest.raises(HistoricalLineageRejected, match="timezone-aware"):
        if object_kind == "signal":
            replace(observation(), **{field: hostile})
        else:
            replace(envelope(), **{field: hostile})
    _assert_lineage_clock_uninvoked(zone)


@pytest.mark.parametrize("kind", ["tzinfo", "datetime_subclass"])
@pytest.mark.parametrize("consumer", ["fingerprint", "unavailable", "snapshot_binding"])
def test_mutated_historical_lineage_clock_cannot_execute_hook_on_revalidation(
    kind: str, consumer: str,
) -> None:
    env = envelope()
    original_identity = env.fingerprint()
    hostile, zone = _lineage_hostile_clock(kind, EVENT_TIME)
    object.__setattr__(env.signals[0], "available_at", hostile)
    with pytest.raises(HistoricalLineageRejected, match="timezone-aware"):
        if consumer == "fingerprint":
            env.fingerprint()
        elif consumer == "unavailable":
            env.unavailable_signals()
        else:
            validate(env)
    _assert_lineage_clock_uninvoked(zone)
    # No new digest can be produced for the altered caller-held signal.
    assert original_identity.startswith("sha256:")


@pytest.mark.parametrize("kind", ["tzinfo", "datetime_subclass"])
def test_bypassed_transaction_clock_is_rejected_before_timezone_callbacks(kind: str) -> None:
    hostile, zone = _lineage_hostile_clock(kind, EVENT_TIME)
    damaged = transaction().model_copy(update={"occurred_at": hostile})
    with pytest.raises(HistoricalLineageRejected, match="timezone-aware"):
        assert_historical_snapshot_bound(
            envelope(), transaction=damaged,
            snapshot=IntelligenceSnapshot(**{
                n: 0.2 for n in IntelligenceSnapshot.model_fields
            }),
            expected_tenant="synthetic-tenant", expected_dataset_digest=DATASET,
        )
    _assert_lineage_clock_uninvoked(zone)
