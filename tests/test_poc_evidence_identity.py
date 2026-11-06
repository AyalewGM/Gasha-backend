"""Issue #49 isolated evidence identity/freshness tests; never Bank approval."""
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.evidence_identity import (
    EvidenceBinding,
    EvidenceIdentityRejected,
    EvidencePacket,
    EvidenceRecord,
    assert_packet_current,
)
from gasha.poc.evidence_lifecycle import EvidenceLifecycle, LifecycleRejected
from gasha.poc.readiness import EvidenceArea, Stage

NOW = datetime(2026, 10, 31, 20, 0, tzinfo=UTC)


def binding() -> EvidenceBinding:
    return EvidenceBinding(
        tenant_id="synthetic-tenant", installation_id="synthetic-poc",
        stage=Stage.SHADOW, use_case="uc-01", commit_sha="a" * 40,
        image_digest="sha256:" + "b" * 64, dataset_digest="sha256:" + "c" * 64,
        config_version="config-1", policy_version="policy-1", rule_version="rules-1",
        signal_version="signals-1", adapter_version="adapter-1",
        window_start=NOW - timedelta(hours=2), window_end=NOW - timedelta(hours=1),
    )


def record(evidence_id: int = 1, *, scope: EvidenceBinding | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=UUID(int=evidence_id),
        binding=binding() if scope is None else scope,
        area=EvidenceArea.SECURITY,
        artifact_ref=f"synthetic-artifact-{evidence_id}",
        artifact_digest="sha256:" + "d" * 64,
        source_system="synthetic-runner",
        collector_actor_ref="e" * 64,
        collected_at=NOW - timedelta(minutes=30),
        expires_at=NOW + timedelta(hours=1),
    )


def packet() -> EvidencePacket:
    return EvidencePacket(binding(), "evaluator-1", (record(1), record(2)))


def test_complete_synthetic_packet_is_deterministic_but_not_approved() -> None:
    original = packet()
    swapped = replace(original, records=tuple(reversed(original.records)))
    assert original.packet_digest() == swapped.packet_digest()
    assert original.packet_digest().startswith("sha256:")
    assert len(original.packet_digest()) == 71
    assert_packet_current(original, expected=binding(), now=NOW)
    assert not hasattr(original, "ready")
    assert not hasattr(original, "enforcement_activated")
    assert not hasattr(original, "verified")


def test_equivalent_timezone_instants_have_identical_identity() -> None:
    offset = timezone(timedelta(hours=-4))
    other = replace(
        binding(),
        window_start=binding().window_start.astimezone(offset),
        window_end=binding().window_end.astimezone(offset),
    )
    source = record()
    shifted = replace(
        source, binding=other, collected_at=source.collected_at.astimezone(offset),
        expires_at=source.expires_at.astimezone(offset),
    )
    first = EvidencePacket(binding(), "evaluator-1", (source,))
    second = EvidencePacket(other, "evaluator-1", (shifted,))
    assert first.packet_digest() == second.packet_digest()


@pytest.mark.parametrize(("field", "value"), [
    ("tenant_id", "other-tenant"),
    ("installation_id", "other-installation"),
    ("stage", Stage.HISTORICAL),
    ("use_case", "uc-02"),
    ("commit_sha", "f" * 40),
    ("image_digest", "sha256:" + "f" * 64),
    ("dataset_digest", "sha256:" + "f" * 64),
    ("config_version", "config-2"),
    ("policy_version", "policy-2"),
    ("rule_version", "rules-2"),
    ("signal_version", "signals-2"),
    ("adapter_version", "adapter-2"),
    ("window_start", NOW - timedelta(hours=3)),
    ("window_end", NOW - timedelta(minutes=45)),
])
def test_each_material_scope_change_invalidates_packet_identity(
    field: str, value: Any
) -> None:
    original = packet()
    changed = replace(original.binding, **{field: value})
    with pytest.raises(EvidenceIdentityRejected, match="binding mismatch"):
        assert_packet_current(original, expected=changed, now=NOW)
    changed_packet = EvidencePacket(
        changed, original.evaluator_version,
        tuple(replace(item, binding=changed) for item in original.records),
    )
    assert changed_packet.packet_digest() != original.packet_digest()


@pytest.mark.parametrize(("field", "value"), [
    ("artifact_ref", "other-artifact"),
    ("artifact_digest", "sha256:" + "f" * 64),
    ("source_system", "other-system"),
    ("collector_actor_ref", "f" * 64),
    ("collected_at", NOW - timedelta(minutes=20)),
    ("expires_at", NOW + timedelta(minutes=20)),
    ("area", EvidenceArea.PERFORMANCE),
    ("evidence_id", UUID(int=3)),
])
def test_each_record_identity_change_alters_packet_digest(field: str, value: Any) -> None:
    original = packet()
    amended = replace(original.records[0], **{field: value})
    newer = replace(original, records=(amended, original.records[1]))
    assert newer.packet_digest() != original.packet_digest()


def test_changed_evaluator_version_and_removed_record_change_digest() -> None:
    original = packet()
    assert replace(original, evaluator_version="evaluator-2").packet_digest() != (
        original.packet_digest()
    )
    assert replace(original, records=original.records[:1]).packet_digest() != (
        original.packet_digest()
    )


def test_reject_duplicate_evidence_id_and_cross_scope_packet() -> None:
    with pytest.raises(EvidenceIdentityRejected, match="duplicate evidence_id"):
        EvidencePacket(binding(), "evaluator-1", (record(), record()))
    with pytest.raises(EvidenceIdentityRejected, match="cross-scope"):
        EvidencePacket(binding(), "evaluator-1", (
            record(), record(2, scope=replace(binding(), tenant_id="other-tenant")),
        ))
    with pytest.raises(EvidenceIdentityRejected, match="nonempty immutable tuple"):
        EvidencePacket(binding(), "evaluator-1", ())


def test_source_mutation_cannot_change_frozen_identity() -> None:
    original = packet()
    before = original.packet_digest()
    with pytest.raises(FrozenInstanceError):
        original.records[0].artifact_ref = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        original.binding.tenant_id = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        original.records = ()  # type: ignore[misc]
    assert original.packet_digest() == before


@pytest.mark.parametrize("field", [
    "tenant_id", "installation_id", "config_version", "policy_version",
    "rule_version", "signal_version", "adapter_version",
])
@pytest.mark.parametrize("value", ["", " raw", "raw ", "raw\ntext", "raw\x00text", "téxt"])
def test_reject_noncanonical_scope_identifiers(field: str, value: str) -> None:
    with pytest.raises(EvidenceIdentityRejected):
        replace(binding(), **{field: value})


@pytest.mark.parametrize(("field", "value"), [
    ("stage", "shadow"), ("stage", None), ("use_case", "UC-01"),
    ("use_case", "uc-04"), ("commit_sha", "a" * 39),
    ("commit_sha", "Z" * 40), ("image_digest", "b" * 64),
    ("dataset_digest", "sha256:" + "Z" * 64),
    ("window_start", datetime(2026, 10, 31, 18)),
    ("window_end", NOW - timedelta(hours=3)),
])
def test_reject_malformed_binding(field: str, value: Any) -> None:
    with pytest.raises(EvidenceIdentityRejected):
        replace(binding(), **{field: value})


@pytest.mark.parametrize(("field", "value"), [
    ("evidence_id", "not-uuid"), ("area", "security"),
    ("artifact_ref", "raw customer@example.org"),
    ("artifact_digest", "d" * 64),
    ("source_system", "source\nleak"),
    ("collector_actor_ref", "real-analyst-name"),
    ("collected_at", datetime(2026, 10, 31, 19, 30)),
    ("expires_at", NOW - timedelta(minutes=31)),
])
def test_reject_malformed_record(field: str, value: Any) -> None:
    with pytest.raises(EvidenceIdentityRejected):
        replace(record(), **{field: value})


def test_collection_must_follow_observation_window() -> None:
    with pytest.raises(EvidenceIdentityRejected, match="collection predates"):
        replace(record(), collected_at=NOW - timedelta(hours=2))


def test_future_and_expired_evidence_fail_closed_at_exact_clock_boundary() -> None:
    original = packet()
    with pytest.raises(EvidenceIdentityRejected, match="future-dated"):
        assert_packet_current(original, expected=binding(), now=NOW - timedelta(hours=1))
    with pytest.raises(EvidenceIdentityRejected, match="expired"):
        assert_packet_current(original, expected=binding(), now=NOW + timedelta(hours=1))
    assert_packet_current(original, expected=binding(), now=NOW - timedelta(minutes=30))


def test_reject_naive_or_untyped_clock_and_packet() -> None:
    with pytest.raises(EvidenceIdentityRejected, match="timezone-aware"):
        assert_packet_current(packet(), expected=binding(), now=datetime(2026, 10, 31))
    with pytest.raises(EvidenceIdentityRejected, match="typed packet"):
        assert_packet_current(None, expected=binding(), now=NOW)  # type: ignore[arg-type]


def test_reconstructed_packet_cannot_attest_external_artifact_or_approval() -> None:
    original = packet()
    other = replace(
        original, records=tuple(
            replace(item, artifact_digest="sha256:" + "f" * 64)
            for item in original.records
        ),
    )
    # Both are constructible and mechanically current. A digest cannot say which
    # one was collected or verified by a Bank-controlled authority.
    assert_packet_current(other, expected=binding(), now=NOW)
    assert other.packet_digest() != original.packet_digest()
    assert not hasattr(other, "bank_inline_approved")


def _fold_scope(fold: int) -> EvidenceBinding:
    """The repeated local 01:30 refers to two distinct real UTC instants."""
    ny = ZoneInfo("America/New_York")
    return replace(
        binding(),
        window_start=datetime(2026, 11, 1, 4, 0, tzinfo=UTC),
        window_end=datetime(2026, 11, 1, 1, 30, tzinfo=ny, fold=fold),
    )


def _fold_record(scope: EvidenceBinding) -> EvidenceRecord:
    return replace(
        record(), binding=scope,
        collected_at=datetime(2026, 11, 1, 7, 0, tzinfo=UTC),
        expires_at=datetime(2026, 11, 1, 10, 0, tzinfo=UTC),
    )


def test_fall_back_different_instants_reject_wrong_expected_binding() -> None:
    early = _fold_scope(0)
    late = _fold_scope(1)
    assert early.window_end == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    assert late.window_end == datetime(2026, 11, 1, 6, 30, tzinfo=UTC)
    assert early.window_end.tzinfo is UTC
    assert late.window_end.tzinfo is UTC
    assert early != late
    sample = EvidencePacket(early, "evaluator-1", (_fold_record(early),))
    assert_packet_current(sample, expected=early, now=datetime(2026, 11, 1, 8, tzinfo=UTC))
    with pytest.raises(EvidenceIdentityRejected, match="binding mismatch"):
        assert_packet_current(
            sample, expected=late, now=datetime(2026, 11, 1, 8, tzinfo=UTC)
        )


def test_fall_back_cross_scope_record_rejected() -> None:
    early = _fold_scope(0)
    late = _fold_scope(1)
    with pytest.raises(EvidenceIdentityRejected, match="cross-scope"):
        EvidencePacket(early, "evaluator-1", (_fold_record(late),))


def test_fall_back_different_instants_change_packet_fingerprint() -> None:
    early = _fold_scope(0)
    late = _fold_scope(1)
    first = EvidencePacket(early, "evaluator-1", (_fold_record(early),))
    second = EvidencePacket(late, "evaluator-1", (_fold_record(late),))
    assert first.packet_digest() != second.packet_digest()


def test_same_instant_different_offsets_have_same_scope_and_digest() -> None:
    early = _fold_scope(0)
    offset = timezone(timedelta(hours=-3))
    equivalent = replace(
        early,
        window_start=early.window_start.astimezone(offset),
        window_end=early.window_end.astimezone(offset),
    )
    original = _fold_record(early)
    equivalent_record = replace(
        original, binding=equivalent,
        collected_at=original.collected_at.astimezone(offset),
        expires_at=original.expires_at.astimezone(offset),
    )
    first = EvidencePacket(early, "evaluator-1", (original,))
    second = EvidencePacket(equivalent, "evaluator-1", (equivalent_record,))
    assert early == equivalent
    assert original == equivalent_record
    assert first.packet_digest() == second.packet_digest()
    assert_packet_current(first, expected=equivalent, now=original.collected_at)
    assert_packet_current(second, expected=early, now=original.collected_at)


def test_dst_collection_and_expiry_exact_instant_boundaries() -> None:
    late = _fold_scope(1)
    local_cutoff = datetime(
        2026, 11, 1, 1, 30, tzinfo=ZoneInfo("America/New_York"), fold=1
    )
    expiry = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
    on_boundary = replace(
        record(), binding=late, collected_at=local_cutoff,
        expires_at=expiry.astimezone(timezone(timedelta(hours=-3))),
    )
    assert on_boundary.collected_at == late.window_end
    assert on_boundary.collected_at.tzinfo is UTC
    assert on_boundary.expires_at.tzinfo is UTC
    with pytest.raises(EvidenceIdentityRejected, match="collection predates"):
        replace(on_boundary, collected_at=late.window_end - timedelta(microseconds=1))

    sample = EvidencePacket(late, "evaluator-1", (on_boundary,))
    assert_packet_current(sample, expected=late, now=late.window_end)
    with pytest.raises(EvidenceIdentityRejected, match="future-dated"):
        assert_packet_current(
            sample, expected=late, now=late.window_end - timedelta(microseconds=1)
        )
    with pytest.raises(EvidenceIdentityRejected, match="expired"):
        assert_packet_current(sample, expected=late, now=expiry)


@pytest.mark.parametrize(("field", "value"), [
    ("records", ()),
    ("records", []),
    ("evaluator_version", ""),
    ("binding", "caller-supplied-scope"),
])
def test_mutated_packet_shape_rejected_before_fingerprint_or_freshness(
    field: str, value: Any,
) -> None:
    sample = packet()
    object.__setattr__(sample, field, value)
    with pytest.raises(EvidenceIdentityRejected):
        sample.packet_digest()
    with pytest.raises(EvidenceIdentityRejected):
        assert_packet_current(sample, expected=binding(), now=NOW)


@pytest.mark.parametrize(("field", "value"), [
    ("area", "security"),
    ("evidence_id", "1"),
    ("artifact_digest", "d" * 64),
    ("collected_at", datetime(2026, 10, 31, 20)),
])
def test_mutated_record_shape_rejected_before_fingerprint_or_freshness(
    field: str, value: Any,
) -> None:
    sample = packet()
    object.__setattr__(sample.records[0], field, value)
    with pytest.raises(EvidenceIdentityRejected):
        sample.packet_digest()
    with pytest.raises(EvidenceIdentityRejected):
        assert_packet_current(sample, expected=binding(), now=NOW)


def test_postconstruction_duplicate_and_cross_scope_records_fail_closed() -> None:
    duplicate = packet()
    object.__setattr__(duplicate.records[1], "evidence_id", duplicate.records[0].evidence_id)
    with pytest.raises(EvidenceIdentityRejected, match="duplicate evidence_id"):
        duplicate.packet_digest()

    cross_scope = packet()
    object.__setattr__(cross_scope.records[0].binding, "tenant_id", "other-tenant")
    with pytest.raises(EvidenceIdentityRejected, match="cross-scope"):
        assert_packet_current(cross_scope, expected=binding(), now=NOW)


def test_expected_binding_is_revalidated_not_just_equal() -> None:
    sample = packet()
    expected = binding()
    object.__setattr__(expected, "stage", "shadow")
    with pytest.raises(EvidenceIdentityRejected, match="Stage enum"):
        assert_packet_current(sample, expected=expected, now=NOW)


@pytest.mark.parametrize("level,field", [
    ("packet", "records"),
    ("binding", "tenant_id"),
    ("record", "evidence_id"),
])
def test_deleted_nested_attributes_fail_with_domain_error(level: str, field: str) -> None:
    sample = packet()
    target: object = {
        "packet": sample,
        "binding": sample.binding,
        "record": sample.records[0],
    }[level]
    object.__delattr__(target, field)
    with pytest.raises(EvidenceIdentityRejected, match="missing"):
        sample.packet_digest()
    with pytest.raises(EvidenceIdentityRejected, match="missing"):
        assert_packet_current(sample, expected=binding(), now=NOW)


def test_mutated_empty_packet_never_becomes_approvable_empty_lifecycle() -> None:
    """An emptied packet must fail replay, not satisfy an all-records-verified check."""
    sample = packet()
    object.__setattr__(sample, "records", ())
    with pytest.raises(LifecycleRejected, match="invalid evidence packet"):
        EvidenceLifecycle(sample)


class _HookZone(tzinfo):
    """An untrusted timezone provider with observable callbacks."""

    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        self.calls += 1
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str | None:
        return "hostile-test-zone"


class _HookDateTime(datetime):
    calls = 0

    def utcoffset(self) -> timedelta | None:
        type(self).calls += 1
        return timedelta(0)

    def astimezone(self, tz: tzinfo | None = None) -> datetime:
        type(self).calls += 1
        return super().astimezone(tz)


@pytest.mark.parametrize("field", [
    "window_start", "window_end", "collected_at", "expires_at", "now",
])
@pytest.mark.parametrize("kind", ["custom_zone", "datetime_subclass"])
def test_evidence_rejects_callback_clocks_before_invoking_hooks(
    field: str, kind: str,
) -> None:
    zone = _HookZone()
    _HookDateTime.calls = 0
    hostile = (
        datetime(2026, 10, 31, 19, 30, tzinfo=zone)
        if kind == "custom_zone"
        else _HookDateTime(2026, 10, 31, 19, 30, tzinfo=UTC)
    )
    with pytest.raises(EvidenceIdentityRejected, match="timezone-aware"):
        if field in ("window_start", "window_end"):
            replace(binding(), **{field: hostile})
        elif field in ("collected_at", "expires_at"):
            replace(record(), **{field: hostile})
        else:
            assert_packet_current(packet(), expected=binding(), now=hostile)
    assert zone.calls == 0
    assert _HookDateTime.calls == 0


@pytest.mark.parametrize("surface", ["binding", "record"])
@pytest.mark.parametrize("kind", ["custom_zone", "datetime_subclass"])
def test_evidence_runtime_clock_substitution_fails_before_hooks(
    surface: str, kind: str,
) -> None:
    original = packet()
    zone = _HookZone()
    _HookDateTime.calls = 0
    hostile = (
        datetime(2026, 10, 31, 19, 30, tzinfo=zone)
        if kind == "custom_zone"
        else _HookDateTime(2026, 10, 31, 19, 30, tzinfo=UTC)
    )
    if surface == "binding":
        object.__setattr__(original.binding, "window_end", hostile)
    else:
        object.__setattr__(original.records[0], "collected_at", hostile)
    with pytest.raises(EvidenceIdentityRejected, match="timezone-aware"):
        original.packet_digest()
    assert zone.calls == 0
    assert _HookDateTime.calls == 0


class _PretendDateTime:
    """Non-datetime object whose __class__ getter has observable side effects."""

    def __init__(self) -> None:
        self.calls = 0

    @property
    def __class__(self) -> type[datetime]:
        self.calls += 1
        return datetime


@pytest.mark.parametrize("surface", [
    "window_start", "window_end", "collected_at", "expires_at", "now",
    "mutated_binding", "mutated_record",
])
def test_evidence_forged_class_clock_rejected_before_callback(surface: str) -> None:
    hostile: Any = _PretendDateTime()
    with pytest.raises(EvidenceIdentityRejected, match="timezone-aware"):
        if surface in ("window_start", "window_end"):
            replace(binding(), **{surface: hostile})
        elif surface in ("collected_at", "expires_at"):
            replace(record(), **{surface: hostile})
        elif surface == "now":
            assert_packet_current(packet(), expected=binding(), now=hostile)
        else:
            original = packet()
            if surface == "mutated_binding":
                object.__setattr__(original.binding, "window_end", hostile)
            else:
                object.__setattr__(original.records[0], "collected_at", hostile)
            original.packet_digest()
    assert hostile.calls == 0
