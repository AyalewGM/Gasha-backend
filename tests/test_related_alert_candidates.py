"""#45 FR-32: synthetic candidate grouping; no Bank execution or case merge."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from random import Random
from uuid import UUID

import pytest

from gasha.cases.related_alerts import (
    DEFAULT_POLICY,
    RelatedAlertEvidence,
    RelatedAlertPolicy,
    RelatedAlertRejected,
    project_related_alert_candidates,
)

AT = datetime(2026, 11, 5, 0, 0, tzinfo=UTC)
LINK = "a" * 64
OTHER_LINK = "b" * 64
CONTEXT = "c" * 64
TENANT = "tenant-a"


def alert(
    number: int, *,
    link: str | None = LINK,
    tenant: str = TENANT,
    observed_at: datetime = AT,
    context: str = CONTEXT,
    scenarios: tuple[str, ...] = ("APP-01",),
    availability: str = "available",
) -> RelatedAlertEvidence:
    return RelatedAlertEvidence(
        tenant_id=tenant, event_id=UUID(int=number),
        context_ref=context, link_ref=link, observed_at=observed_at,
        scenario_ids=scenarios, linkage_availability=availability,
    )


def project(
    *rows: RelatedAlertEvidence, at: datetime = AT,
    policy: RelatedAlertPolicy = DEFAULT_POLICY, **kwargs: int,
) -> dict[str, object]:
    return project_related_alert_candidates(
        tenant_id=TENANT, evidence=rows, as_of=at, policy=policy, **kwargs,
    )


def test_candidate_preserves_members_and_non_authoritative_flags() -> None:
    result = project(
        alert(2, observed_at=AT - timedelta(minutes=1), scenarios=("ATO-02",)),
        alert(1, observed_at=AT - timedelta(minutes=2)),
        alert(3, link=OTHER_LINK),
    )
    assert result["alert_count"] == 3
    assert result["candidate_group_count"] == 1
    assert result["candidate_linked_alert_count"] == 2
    assert result["unlinked_singleton_count"] == 1
    rows = result["candidates"]
    assert isinstance(rows, list) and len(rows) == 1
    group = rows[0]
    assert group["source_event_ids"] == [str(UUID(int=1)), str(UUID(int=2))]
    assert group["scenario_ids"] == ["APP-01", "ATO-02"]
    assert group["source_event_count"] == 2
    assert [m["context_ref"] for m in group["member_evidence"]] == [CONTEXT, CONTEXT]
    assert group["case_merge_performed"] is False
    assert result["bank_correlation_approved"] is False
    assert result["bank_source_provenance_verified"] is False
    assert result["bank_ranking_approved"] is False
    assert result["enforcement_activated"] is False
    assert LINK not in str(result)


def test_empty_singletons_and_unavailable_links_are_traceable() -> None:
    assert project()["candidates"] == []
    result = project(alert(1), alert(2, link=OTHER_LINK))
    assert result["candidates"] == []
    assert result["unlinked_singleton_count"] == 2
    no_link = project(
        alert(1, link=None, availability="missing"),
        alert(2, link=None, availability="unauthorized"),
    )
    assert [s["linkage_availability"] for s in no_link["singletons"]] == [
        "missing", "unauthorized",
    ]
    assert all(s["reason_code"] == "LINKAGE_UNAVAILABLE" for s in no_link["singletons"])


def test_100_seeded_input_permutations_and_equivalent_timezone_clock() -> None:
    scenarios = ("ATO-02", "ATO-06", "MM-01", "MM-02",
                 "MM-05", "APP-01", "APP-02", "APP-05")
    rows = tuple(
        alert(i + 1, observed_at=AT - timedelta(minutes=8 - i),
              scenarios=(scenario,), link=LINK if i < 4 else OTHER_LINK)
        for i, scenario in enumerate(scenarios)
    )
    expected = project(*rows)
    rng = Random(45032)
    for _ in range(120):
        shuffled = list(rows)
        rng.shuffle(shuffled)
        assert project(*shuffled) == expected
    eastern = timezone(timedelta(hours=-5))
    equivalent = tuple(replace(row, observed_at=row.observed_at.astimezone(eastern))
                       for row in rows)
    assert project(*equivalent, at=AT.astimezone(eastern)) == expected
    assert sorted({s for group in expected["candidates"] for s in group["scenario_ids"]}) == sorted(scenarios)


def test_change_to_evidence_or_policy_lineage_changes_identity() -> None:
    original = project(alert(1), alert(2))["candidates"][0]["candidate_ref"]
    changed = project(alert(1, context="d" * 64), alert(2))["candidates"][0]["candidate_ref"]
    new_policy = replace(DEFAULT_POLICY, version="v2")
    versioned = project(alert(1), alert(2), policy=new_policy)["candidates"][0]["candidate_ref"]
    assert original != changed and original != versioned


@pytest.mark.parametrize("bad_tenant", ["", " tenant-a", "tenant-a\n", "\x00", "tenant/a"])
def test_invalid_tenant_scope(bad_tenant: str) -> None:
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(tenant_id=bad_tenant, evidence=(), as_of=AT)


@pytest.mark.parametrize("bad", [
    replace(alert(1), tenant_id="tenant-b"),
    replace(alert(1), event_id=UUID(int=0)),
    replace(alert(1), context_ref="bad"),
    replace(alert(1), link_ref="not-a-digest"),
    replace(alert(1), scenario_ids=()),
    replace(alert(1), scenario_ids=("APP-01", "APP-01")),
    replace(alert(1), scenario_ids=("ATO-02", "APP-01")),
    replace(alert(1), scenario_ids=("UNAPPROVED-99",)),
    replace(alert(1), observed_at=AT + timedelta(seconds=1)),
    replace(alert(1), observed_at=AT.replace(tzinfo=None)),
    replace(alert(1), link_ref=None),
    replace(alert(1), link_ref=LINK, linkage_availability="missing"),
    replace(alert(1), link_ref=None, linkage_availability="unknown"),
])
def test_invalid_finding_rejected_before_projection(bad: RelatedAlertEvidence) -> None:
    with pytest.raises(RelatedAlertRejected):
        project(alert(2), bad)


def test_duplicate_source_and_conflicting_replay_rejected() -> None:
    with pytest.raises(RelatedAlertRejected, match="duplicate"):
        project(alert(1), alert(1))
    with pytest.raises(RelatedAlertRejected, match="duplicate"):
        project(alert(1), alert(1, link=OTHER_LINK))


@pytest.mark.parametrize("bad_clock", [None, AT.replace(tzinfo=None), "2026-11-05", 42])
def test_invalid_clock(bad_clock: object) -> None:
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=(alert(1),),
            as_of=bad_clock,  # type: ignore[arg-type]
        )


def test_window_boundary_partitions_and_preserves_singletons() -> None:
    inside = AT - timedelta(minutes=15)
    result = project(alert(1, observed_at=inside), alert(2, observed_at=AT))
    assert result["candidate_linked_alert_count"] == 2
    exclusive = replace(DEFAULT_POLICY, boundary="exclusive")
    separate = project(alert(1, observed_at=inside), alert(2, observed_at=AT),
                       policy=exclusive)
    assert separate["candidate_group_count"] == 0
    assert separate["unlinked_singleton_count"] == 2
    outside = project(alert(1, observed_at=inside - timedelta(microseconds=1)),
                      alert(2, observed_at=AT))
    assert outside["unlinked_singleton_count"] == 2
    assert project(alert(1, observed_at=AT))["alert_count"] == 1
    with pytest.raises(RelatedAlertRejected):
        project(alert(1, observed_at=AT + timedelta(microseconds=1)))


@pytest.mark.parametrize(("bound", "value"), [
    ("max_alerts", 0), ("max_alerts", 501), ("max_alerts", True),
    ("max_group_size", 1), ("max_group_size", 51), ("max_group_size", False),
])
def test_limits(bound: str, value: object) -> None:
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=(), as_of=AT,
            **{bound: value},  # type: ignore[arg-type]
        )


def test_oversize_group_and_batch_rejected_atomically() -> None:
    with pytest.raises(RelatedAlertRejected, match="group bound"):
        project(*(alert(i) for i in range(1, 4)), max_group_size=2)
    with pytest.raises(RelatedAlertRejected, match="bounded"):
        project(*(alert(i) for i in range(1, 4)), max_alerts=2)


@pytest.mark.parametrize("policy", [
    replace(DEFAULT_POLICY, policy_id="bad/id"),
    replace(DEFAULT_POLICY, version=""),
    replace(DEFAULT_POLICY, window_seconds=0),
    replace(DEFAULT_POLICY, window_seconds=True),
    replace(DEFAULT_POLICY, boundary="surprise"),
    replace(DEFAULT_POLICY, max_group_size=51),
    replace(DEFAULT_POLICY, unavailable_behavior="infer"),
    replace(DEFAULT_POLICY, linkage_class="remote_coaching"),
])
def test_invalid_policy_rejected(policy: RelatedAlertPolicy) -> None:
    with pytest.raises(RelatedAlertRejected):
        project(alert(1), policy=policy)


def test_mutated_frozen_records_rejected() -> None:
    row = alert(1)
    object.__setattr__(row, "tenant_id", "tenant-b")
    with pytest.raises(RelatedAlertRejected):
        project(row)
    row = alert(1)
    object.__setattr__(row, "scenario_ids", ["APP-01"])
    with pytest.raises(RelatedAlertRejected):
        project(row)


class MutatingZone(tzinfo):
    def __init__(self, action: str, replacement: object, throws: bool = False) -> None:
        self.row: RelatedAlertEvidence | None = None
        self.action = action
        self.replacement = replacement
        self.throws = throws

    def utcoffset(self, dt: datetime | None) -> timedelta:
        if self.row is not None:
            object.__setattr__(self.row, self.action, self.replacement)
        if self.throws:
            raise RuntimeError("faulty source clock")
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)


@pytest.mark.parametrize(("field", "replacement"), [
    ("tenant_id", "tenant-b"),
    ("scenario_ids", ("UNAPPROVED-99",)),
    ("link_ref", "f" * 64),
    ("context_ref", "e" * 64),
    ("event_id", UUID(int=22)),
])
@pytest.mark.parametrize("throws", [False, True])
def test_tzinfo_callback_mutation_rejected_on_both_paths(
    field: str, replacement: object, throws: bool,
) -> None:
    zone = MutatingZone(field, replacement, throws)
    unsafe = alert(2, observed_at=datetime(2026, 11, 5, tzinfo=zone))
    zone.row = unsafe
    with pytest.raises(RelatedAlertRejected):
        project(alert(1), unsafe)


def test_later_clock_cannot_mutate_earlier_snapshot() -> None:
    zone = MutatingZone("tenant_id", "tenant-b")
    first = alert(1)
    later = alert(2, observed_at=datetime(2026, 11, 5, tzinfo=zone))
    zone.row = first
    with pytest.raises(RelatedAlertRejected):
        project(first, later)


def test_full_reconciliation_and_golden_coverage_per_uc() -> None:
    uc_rows = (
        (("ATO-02", "ATO-06"), LINK, 1),
        (("MM-01", "MM-02", "MM-05"), OTHER_LINK, 10),
        (("APP-01", "APP-02", "APP-05"), "e" * 64, 20),
    )
    rows: list[RelatedAlertEvidence] = []
    for scenarios, link, base in uc_rows:
        rows.extend(alert(base + i, scenarios=(scenario,), link=link)
                    for i, scenario in enumerate(scenarios))
        rows.append(alert(base + 8, scenarios=(scenarios[0],), link=None,
                          availability="missing"))
    result = project(*rows)
    assert result["candidate_group_count"] == 3
    assert result["unlinked_singleton_count"] == 3
    assert result["raw_finding_count"] == (
        result["grouped_member_count"] + result["unlinked_singleton_count"]
        + result["quarantined_count"]
    )
    all_ids = [
        member["source_event_id"] for group in result["candidates"]
        for member in group["member_evidence"]
    ] + [single["source_event_id"] for single in result["singletons"]]
    assert len(all_ids) == len(set(all_ids)) == len(rows)
    assert result["reviewable_case_count"] == 6


def test_dst_fold_and_mixed_offsets_normalize_equivalent_instants() -> None:
    from zoneinfo import ZoneInfo

    eastern = ZoneInfo("America/New_York")
    first_fold = datetime(2026, 11, 1, 1, 30, tzinfo=eastern, fold=0)
    second_fold = datetime(2026, 11, 1, 1, 30, tzinfo=eastern, fold=1)
    projection = project(alert(1, observed_at=first_fold),
                         alert(2, observed_at=second_fold))
    assert projection["candidate_group_count"] == 0
    assert projection["unlinked_singleton_count"] == 2
    a = alert(1, observed_at=first_fold)
    b = alert(2, observed_at=first_fold.astimezone(UTC))
    assert project(a, b) == project(
        replace(a, observed_at=a.observed_at.astimezone(UTC)), b,
    )


def test_non_tuple_batch_and_non_evidence_records_rejected() -> None:
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=[alert(1)], as_of=AT,  # type: ignore[arg-type]
        )
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=(alert(1), "wrong"),  # type: ignore[arg-type]
            as_of=AT,
        )
