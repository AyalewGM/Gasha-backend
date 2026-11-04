"""Issue #44: synthetic-only, version-pinned list matcher regressions."""
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.risk_lists import (
    MatchedRiskListEntry,
    RiskListEntry,
    RiskListKind,
    RiskListMatch,
    RiskListRejected,
    RiskListSnapshot,
    RiskListSubject,
    SubjectKind,
    match_reference_snapshot,
)

AT = datetime(2026, 10, 31, 12, tzinfo=UTC)
BANK = RiskListSubject(SubjectKind.BENEFICIARY, "a" * 64)
OTHER = RiskListSubject(SubjectKind.ACCOUNT, "b" * 64)


def entry(n: int, kind: RiskListKind, **changes: Any) -> RiskListEntry:
    return RiskListEntry(
        entry_id=UUID(int=n), kind=kind,
        subject=BANK, effective_from=AT - timedelta(hours=2),
        **changes,
    )


def snapshot(*entries: RiskListEntry) -> RiskListSnapshot:
    return RiskListSnapshot(
        tenant_id="synthetic-tenant", list_version="risk-v1", policy_version="policy-v1",
        published_at=AT - timedelta(days=1), entries=tuple(entries),
    )


def lookup(
    value: RiskListSnapshot, *,
    at: datetime = AT,
    subjects: tuple[RiskListSubject, ...] = (BANK,),
) -> RiskListMatch:
    return match_reference_snapshot(
        value, expected_tenant="synthetic-tenant",
        expected_list_version="risk-v1", expected_policy_version="policy-v1",
        event_at=at, subjects=subjects,
    )


@pytest.mark.parametrize("kinds", [
    (RiskListKind.ALLOW,),
    (RiskListKind.WATCH,),
    (RiskListKind.BLOCK,),
    (RiskListKind.ALLOW, RiskListKind.WATCH),
    (RiskListKind.ALLOW, RiskListKind.BLOCK),
    (RiskListKind.WATCH, RiskListKind.BLOCK),
    (RiskListKind.ALLOW, RiskListKind.WATCH, RiskListKind.BLOCK),
])
def test_conflicts_preserve_all_per_entry_provenance(
    kinds: tuple[RiskListKind, ...],
) -> None:
    original = snapshot(*(entry(i + 1, kind) for i, kind in enumerate(kinds)))
    result = lookup(original)
    assert result.matches == tuple(
        MatchedRiskListEntry(UUID(int=i + 1), kind, f"RISK_LIST_{kind.name}_MATCH")
        for i, kind in enumerate(kinds)
    )
    assert result.reason_codes == tuple(f"RISK_LIST_{kind.name}_MATCH" for kind in kinds)
    assert result.matched_entry_ids == tuple(UUID(int=i + 1) for i in range(len(kinds)))
    assert not hasattr(result, "kind")
    assert not result.enforcement_activated
    assert result.snapshot_digest == original.digest()


def test_no_matching_identifiers_never_infers_allow() -> None:
    original = snapshot(entry(1, RiskListKind.BLOCK))
    for subjects in ((), (OTHER,)):
        outcome = lookup(original, subjects=subjects)
        assert outcome.matches == ()
        assert outcome.matched_entry_ids == ()
        assert outcome.reason_codes == ("RISK_LIST_NO_MATCH",)


def test_lookups_do_not_match_other_subject_kinds_with_same_token() -> None:
    other_kind = RiskListSubject(SubjectKind.CUSTOMER, BANK.token)
    assert lookup(snapshot(entry(1, RiskListKind.BLOCK)), subjects=(other_kind,)).matches == ()


def test_effective_boundaries_expiry_and_revocation_are_half_open() -> None:
    start = AT - timedelta(hours=2)
    end = AT + timedelta(hours=1)
    with_window = snapshot(entry(1, RiskListKind.BLOCK, effective_until=end))
    assert lookup(with_window, at=start).matches[0].kind is RiskListKind.BLOCK
    assert lookup(with_window, at=start - timedelta(microseconds=1)).matches == ()
    assert lookup(with_window, at=end - timedelta(microseconds=1)).matches[0].kind is RiskListKind.BLOCK
    assert lookup(with_window, at=end).matches == ()
    revoked = snapshot(entry(2, RiskListKind.BLOCK, revoked_at=AT))
    assert lookup(revoked, at=AT - timedelta(microseconds=1)).matches[0].kind is RiskListKind.BLOCK
    assert lookup(revoked).matches == ()
    assert lookup(snapshot(entry(3, RiskListKind.BLOCK, revoked_at=start))).matches == ()


@pytest.mark.parametrize("field", ["tenant_id", "list_version", "policy_version"])
def test_fail_closed_wrong_scope_or_pinned_version(field: str) -> None:
    original = snapshot(entry(1, RiskListKind.BLOCK))
    changed = replace(original, **{field: "different"})
    with pytest.raises(RiskListRejected, match="scope or version"):
        lookup(changed)


def test_future_published_snapshot_cannot_rewrite_historical_event() -> None:
    future = replace(snapshot(entry(1, RiskListKind.BLOCK)), published_at=AT + timedelta(seconds=1))
    with pytest.raises(RiskListRejected, match="not published"):
        lookup(future)


def test_as_of_snapshot_version_is_replay_deterministic() -> None:
    original = snapshot(entry(1, RiskListKind.ALLOW))
    first = lookup(original)
    newer = replace(
        original, list_version="risk-v2",
        published_at=AT + timedelta(hours=1),
        entries=(entry(1, RiskListKind.ALLOW), entry(2, RiskListKind.BLOCK)),
    )
    assert lookup(original) == first
    assert original.digest() != newer.digest()
    with pytest.raises(RiskListRejected, match="scope or version"):
        lookup(newer)
    with pytest.raises(RiskListRejected, match="not published"):
        match_reference_snapshot(
            newer, expected_tenant="synthetic-tenant", expected_list_version="risk-v2",
            expected_policy_version="policy-v1", event_at=AT, subjects=(BANK,),
        )


def test_order_independent_digest_and_conflict_resolution() -> None:
    original = snapshot(entry(1, RiskListKind.ALLOW), entry(2, RiskListKind.BLOCK))
    permuted = replace(original, entries=tuple(reversed(original.entries)))
    assert original.digest() == permuted.digest()
    assert lookup(original) == lookup(permuted)


def test_snapshot_digest_changes_with_every_material_revision() -> None:
    original = snapshot(entry(1, RiskListKind.ALLOW))
    variants = [
        replace(original, tenant_id="other-tenant"),
        replace(original, policy_version="policy-v2"),
        replace(original, list_version="risk-v2"),
        replace(original, published_at=AT - timedelta(hours=1)),
        replace(original, entries=(replace(original.entries[0], kind=RiskListKind.WATCH),)),
        replace(original, entries=(replace(original.entries[0], revoked_at=AT),)),
    ]
    assert all(v.digest() != original.digest() for v in variants)


def test_dst_repeated_hour_evaluates_utc_instants() -> None:
    new_york = ZoneInfo("America/New_York")
    earlier = datetime(2026, 11, 1, 1, 30, tzinfo=new_york, fold=0)
    later = datetime(2026, 11, 1, 1, 15, tzinfo=new_york, fold=1)
    allowed = RiskListEntry(UUID(int=1), RiskListKind.BLOCK, BANK, earlier, later)
    original = RiskListSnapshot(
        "synthetic-tenant", "risk-v1", "policy-v1",
        earlier - timedelta(days=1), (allowed,),
    )
    assert lookup(original, at=earlier).matches[0].kind is RiskListKind.BLOCK
    assert lookup(original, at=later).matches == ()
    # The reversed fold is a negative interval even if wall time looks ordered.
    with pytest.raises(RiskListRejected, match="interval"):
        replace(allowed, effective_from=later, effective_until=earlier)
    shifted = replace(allowed, effective_from=earlier.astimezone(UTC),
                      effective_until=later.astimezone(timezone(timedelta(hours=-5))))
    assert replace(original, entries=(shifted,)).digest() == original.digest()


@pytest.mark.parametrize(("field", "bad"), [
    ("kind", "block"), ("subject", "raw-id"),
    ("effective_from", datetime(2026, 10, 31)),
    ("effective_until", AT - timedelta(hours=3)),
    ("revoked_at", datetime(2026, 10, 31)),
    ("entry_id", "1"),
])
def test_reject_bad_entry(field: str, bad: Any) -> None:
    with pytest.raises(RiskListRejected):
        replace(entry(1, RiskListKind.ALLOW), **{field: bad})


@pytest.mark.parametrize("bad", [
    "customer@bank.example", "123456", "A" * 64, "f" * 65, "a" * 63, "é" * 64,
])
def test_never_accept_raw_or_noncanonical_subject(bad: str) -> None:
    with pytest.raises(RiskListRejected, match="bank-tokenized"):
        RiskListSubject(SubjectKind.ACCOUNT, bad)


@pytest.mark.parametrize(("field", "bad"), [
    ("tenant_id", ""), ("tenant_id", "raw Customer A"),
    ("list_version", "v1\n"), ("policy_version", "?"),
    ("published_at", datetime(2026, 10, 31)),
    ("entries", []), ("entries", ("not-entry",)),
])
def test_reject_bad_snapshot(field: str, bad: Any) -> None:
    with pytest.raises(RiskListRejected):
        replace(snapshot(), **{field: bad})


def test_reject_duplicate_entry_ids() -> None:
    with pytest.raises(RiskListRejected, match="duplicate"):
        snapshot(entry(1, RiskListKind.ALLOW), entry(1, RiskListKind.BLOCK))


def test_reject_duplicate_logical_entries_even_with_new_ids() -> None:
    with pytest.raises(RiskListRejected, match="duplicate logical"):
        snapshot(entry(1, RiskListKind.ALLOW), entry(2, RiskListKind.ALLOW))
    assert len(lookup(snapshot(entry(1, RiskListKind.ALLOW),
                               entry(2, RiskListKind.WATCH))).matches) == 2
    other = replace(entry(2, RiskListKind.ALLOW), subject=OTHER)
    assert len(lookup(snapshot(entry(1, RiskListKind.ALLOW), other),
                      subjects=(BANK, OTHER)).matches) == 2


def test_revoke_before_effective_start_rejected_with_dst_fold() -> None:
    start = AT - timedelta(hours=2)
    with pytest.raises(RiskListRejected, match="revocation"):
        entry(1, RiskListKind.BLOCK, revoked_at=start - timedelta(microseconds=1))
    equal = entry(2, RiskListKind.BLOCK, revoked_at=start)
    assert not equal.active_at(start)
    assert lookup(snapshot(equal), at=start).matches == ()
    ny = ZoneInfo("America/New_York")
    later = datetime(2026, 11, 1, 1, 15, tzinfo=ny, fold=1)
    earlier = datetime(2026, 11, 1, 1, 30, tzinfo=ny, fold=0)
    with pytest.raises(RiskListRejected, match="revocation"):
        RiskListEntry(UUID(int=3), RiskListKind.WATCH, BANK, later, revoked_at=earlier)
    valid = RiskListEntry(UUID(int=4), RiskListKind.WATCH, BANK, earlier, revoked_at=later)
    assert valid.active_at(earlier)
    assert not valid.active_at(later)


def test_multisubject_conflict_provenance_and_order_stability() -> None:
    original = snapshot(replace(entry(4, RiskListKind.BLOCK), subject=OTHER),
                        entry(2, RiskListKind.ALLOW), entry(3, RiskListKind.WATCH))
    result = lookup(original, subjects=(OTHER, BANK))
    assert result.matches == (
        MatchedRiskListEntry(UUID(int=2), RiskListKind.ALLOW, "RISK_LIST_ALLOW_MATCH"),
        MatchedRiskListEntry(UUID(int=3), RiskListKind.WATCH, "RISK_LIST_WATCH_MATCH"),
        MatchedRiskListEntry(UUID(int=4), RiskListKind.BLOCK, "RISK_LIST_BLOCK_MATCH"),
    )
    assert lookup(replace(original, entries=tuple(reversed(original.entries))),
                  subjects=(BANK, OTHER)) == result


def test_reject_invalid_request_inputs_without_scope_leak() -> None:
    original = snapshot()
    cases: tuple[dict[str, object], ...] = (
        {"event_at": datetime(2026, 10, 31)},
        {"subjects": [BANK]},
        {"subjects": (BANK, BANK)},
        {"subjects": ("raw",)},
        {"expected_tenant": "raw tenant with customer info"},
    )
    for changed in cases:
        inputs: dict[str, Any] = {
            "expected_tenant": "synthetic-tenant", "expected_list_version": "risk-v1",
            "expected_policy_version": "policy-v1", "event_at": AT, "subjects": (BANK,),
        }
        inputs.update(changed)
        with pytest.raises(RiskListRejected):
            match_reference_snapshot(original, **inputs)


def test_immutable_reference_values_and_no_authorizing_fields() -> None:
    original = snapshot(entry(1, RiskListKind.BLOCK))
    outcome = lookup(original)
    with pytest.raises(FrozenInstanceError):
        original.list_version = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        original.entries[0].kind = RiskListKind.ALLOW  # type: ignore[misc]
    assert original.digest() == outcome.snapshot_digest
    assert not hasattr(outcome, "ready")
    assert not hasattr(outcome, "bank_approved")
    assert not hasattr(outcome, "kind")
    assert not hasattr(outcome, "action")
    assert not outcome.enforcement_activated


def test_reference_matcher_has_no_production_consumer() -> None:
    """Guard against accidental production import of untrusted list assertions."""
    from pathlib import Path

    source_root = Path(__file__).resolve().parents[1] / "src" / "gasha"
    unsafe = []
    for path in source_root.rglob("*.py"):
        if path.name == "risk_lists.py":
            continue
        if "gasha.poc.risk_lists" in path.read_text(encoding="utf-8"):
            unsafe.append(str(path.relative_to(source_root)))
    assert unsafe == []


@pytest.mark.parametrize(("target", "field", "corruption"), [
    ("snapshot", "entries", ("not-an-entry",)),
    ("snapshot", "published_at", datetime(2026, 10, 31)),
    ("entry", "kind", "block"),
    ("entry", "effective_from", datetime(2026, 10, 31)),
    ("entry", "revoked_at", AT - timedelta(days=1)),
    ("subject", "kind", "beneficiary"),
    ("subject", "token", "untrusted"),
])
def test_postconstruction_corruption_rejected_before_match_or_digest(
    target: str, field: str, corruption: object,
) -> None:
    # Allocate an isolated subject: the module-level BANK fixture is shared.
    private_subject = RiskListSubject(SubjectKind.BENEFICIARY, "c" * 64)
    original = snapshot(replace(entry(1, RiskListKind.BLOCK), subject=private_subject))
    targets: dict[str, object] = {
        "snapshot": original,
        "entry": original.entries[0],
        "subject": original.entries[0].subject,
    }
    # Simulate deserialized or low-level altered caller assertions. This is
    # not a security boundary, but malformed reference input must fail closed.
    object.__setattr__(targets[target], field, corruption)
    with pytest.raises(RiskListRejected):
        lookup(original)
    with pytest.raises(RiskListRejected):
        original.digest()
    if target == "entry":
        with pytest.raises(RiskListRejected):
            original.entries[0].active_at(AT)


@pytest.mark.parametrize(("target", "field"), [
    ("snapshot", "entries"),
    ("snapshot", "list_version"),
    ("entry", "subject"),
    ("entry", "entry_id"),
    ("subject", "kind"),
])
def test_deleted_reference_attributes_fail_with_domain_rejection(
    target: str, field: str,
) -> None:
    # Allocate an isolated subject: the module-level BANK fixture is shared.
    private_subject = RiskListSubject(SubjectKind.BENEFICIARY, "c" * 64)
    original = snapshot(replace(entry(1, RiskListKind.BLOCK), subject=private_subject))
    targets: dict[str, object] = {
        "snapshot": original,
        "entry": original.entries[0],
        "subject": original.entries[0].subject,
    }
    object.__delattr__(targets[target], field)
    with pytest.raises(RiskListRejected):
        lookup(original)
    with pytest.raises(RiskListRejected):
        original.digest()


def test_invalid_nonmatching_entry_does_not_get_skipped() -> None:
    original = snapshot(
        entry(1, RiskListKind.ALLOW),
        replace(entry(2, RiskListKind.WATCH), subject=OTHER),
    )
    object.__setattr__(original.entries[1], "kind", "watch")
    # All input entries must validate, not just entries matched by subjects.
    with pytest.raises(RiskListRejected):
        lookup(original, subjects=(BANK,))


def test_revalidated_valid_snapshot_preserves_digest_and_match_semantics() -> None:
    original = snapshot(
        entry(3, RiskListKind.WATCH),
        entry(1, RiskListKind.ALLOW),
        replace(entry(2, RiskListKind.BLOCK), subject=OTHER),
    )
    result = lookup(original, subjects=(BANK, OTHER))
    assert result.snapshot_digest == original.digest()
    assert result.matched_entry_ids == (UUID(int=1), UUID(int=2), UUID(int=3))
    assert lookup(replace(original, entries=tuple(reversed(original.entries))),
                  subjects=(OTHER, BANK)) == result



@pytest.mark.parametrize(("field", "corruption"), [
    ("kind", "beneficiary"),  # Equal to a StrEnum value, but not the enum type.
    ("token", "a" * 63),
])
def test_corrupted_request_subject_rejected_before_hash_or_match(
    field: str, corruption: object,
) -> None:
    original = snapshot(entry(1, RiskListKind.BLOCK))
    request_subject = RiskListSubject(SubjectKind.BENEFICIARY, "a" * 64)
    object.__setattr__(request_subject, field, corruption)
    with pytest.raises(RiskListRejected):
        lookup(original, subjects=(request_subject,))


@pytest.mark.parametrize("field", ["kind", "token"])
def test_deleted_request_subject_attribute_raises_domain_rejection(
    field: str,
) -> None:
    original = snapshot(entry(1, RiskListKind.BLOCK))
    request_subject = RiskListSubject(SubjectKind.BENEFICIARY, "a" * 64)
    object.__delattr__(request_subject, field)
    with pytest.raises(RiskListRejected, match="missing list subject attribute"):
        lookup(original, subjects=(request_subject,))


def test_nonmatching_request_subject_must_also_validate_before_hashing() -> None:
    original = snapshot(entry(1, RiskListKind.ALLOW))
    unrelated = RiskListSubject(SubjectKind.CUSTOMER, "c" * 64)
    object.__setattr__(unrelated, "kind", "customer")
    with pytest.raises(RiskListRejected):
        lookup(original, subjects=(BANK, unrelated))


def test_valid_request_subject_copies_preserve_match_only_result() -> None:
    original = snapshot(entry(1, RiskListKind.BLOCK))
    independent = RiskListSubject(SubjectKind.BENEFICIARY, "a" * 64)
    report = lookup(original, subjects=(independent,))
    assert report.matched_entry_ids == (UUID(int=1),)
    assert report.snapshot_digest == original.digest()
    assert not report.enforcement_activated
    with pytest.raises(RiskListRejected, match="duplicate subject"):
        lookup(original, subjects=(BANK, independent))
