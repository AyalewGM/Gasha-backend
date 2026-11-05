"""#45 / FR-32: synthetic candidate links, not a Bank case-consolidation action."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations
from uuid import UUID

import pytest

from gasha.cases.related_alerts import (
    RelatedAlertEvidence,
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
    link: str = LINK,
    tenant: str = TENANT,
    observed_at: datetime = AT,
    context: str = CONTEXT,
    scenarios: tuple[str, ...] = ("APP-01",),
) -> RelatedAlertEvidence:
    return RelatedAlertEvidence(
        tenant_id=tenant, event_id=UUID(int=number),
        context_ref=context, link_ref=link, observed_at=observed_at,
        scenario_ids=scenarios,
    )


def project(*rows: RelatedAlertEvidence, at: datetime = AT, **kwargs: int) -> dict[str, object]:
    return project_related_alert_candidates(
        tenant_id=TENANT, evidence=rows, as_of=at, **kwargs,
    )


def test_candidate_is_read_only_complete_and_keeps_distinct_event_identities() -> None:
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
    assert group["case_merge_performed"] is False
    assert result["bank_correlation_approved"] is False
    assert result["bank_source_provenance_verified"] is False
    assert result["enforcement_activated"] is False
    assert LINK not in str(result)
    assert CONTEXT not in str(result)


def test_unrelated_or_single_alerts_are_not_automatically_consolidated() -> None:
    empty = project()
    assert empty["candidates"] == [] and empty["alert_count"] == 0
    only = project(alert(1), alert(2, link=OTHER_LINK))
    assert only["candidates"] == []
    assert only["unlinked_singleton_count"] == 2


def test_stable_identity_under_permutation_and_equivalent_timezone_clock() -> None:
    rows = (
        alert(1, observed_at=AT - timedelta(minutes=3)),
        alert(2, observed_at=AT - timedelta(minutes=2), scenarios=("ATO-02",)),
        alert(3, link=OTHER_LINK, observed_at=AT - timedelta(minutes=1)),
        alert(4, link=OTHER_LINK, observed_at=AT),
    )
    expected = project(*rows)
    for ordering in permutations(rows):
        assert project(*ordering) == expected
    eastern = timezone(timedelta(hours=-5))
    equivalent = tuple(replace(row, observed_at=row.observed_at.astimezone(eastern))
                       for row in rows)
    assert project(*equivalent, at=AT.astimezone(eastern)) == expected


def test_change_to_evidence_lineage_changes_candidate_identity() -> None:
    original = project(alert(1), alert(2))["candidates"]
    altered = project(alert(1, context="d" * 64), alert(2))["candidates"]
    assert original != altered
    assert original[0]["candidate_ref"] != altered[0]["candidate_ref"]


@pytest.mark.parametrize("bad_tenant", ["", " tenant-a", "tenant-a\n", "\x00", "tenant/a"])
def test_invalid_tenant_scope_is_rejected(bad_tenant: str) -> None:
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
])
def test_bad_evidence_fails_closed_before_any_projection(bad: RelatedAlertEvidence) -> None:
    with pytest.raises(RelatedAlertRejected):
        project(alert(2), bad)


def test_duplicate_identity_is_rejected_even_if_source_or_link_disagrees() -> None:
    with pytest.raises(RelatedAlertRejected, match="duplicate"):
        project(alert(1), alert(1))
    with pytest.raises(RelatedAlertRejected, match="duplicate"):
        project(alert(1), alert(1, link=OTHER_LINK, context="d" * 64))


@pytest.mark.parametrize("bad_clock", [None, AT.replace(tzinfo=None), "2026-11-05", 42])
def test_invalid_as_of_clock_is_rejected(bad_clock: object) -> None:
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=(alert(1),), as_of=bad_clock,  # type: ignore[arg-type]
        )


def test_exact_boundary_inclusive_but_future_disallowed() -> None:
    assert project(alert(1, observed_at=AT))["alert_count"] == 1
    with pytest.raises(RelatedAlertRejected):
        project(alert(1, observed_at=AT + timedelta(microseconds=1)))


@pytest.mark.parametrize(("bound", "value"), [
    ("max_alerts", 0), ("max_alerts", 501), ("max_alerts", True),
    ("max_group_size", 1), ("max_group_size", 51), ("max_group_size", False),
])
def test_limits_fail_closed(bound: str, value: object) -> None:
    options = {bound: value}
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=(), as_of=AT,
            **options,  # type: ignore[arg-type]
        )


def test_oversize_candidate_and_batch_are_not_partially_returned() -> None:
    with pytest.raises(RelatedAlertRejected, match="group bound"):
        project(*(alert(i) for i in range(1, 4)), max_group_size=2)
    with pytest.raises(RelatedAlertRejected, match="bounded"):
        project(*(alert(i) for i in range(1, 4)), max_alerts=2)


def test_mutated_frozen_evidence_is_rejected_when_consumed() -> None:
    row = alert(1)
    object.__setattr__(row, "tenant_id", "tenant-b")
    with pytest.raises(RelatedAlertRejected):
        project(row)
    row = alert(1)
    object.__setattr__(row, "scenario_ids", ["APP-01"])
    with pytest.raises(RelatedAlertRejected):
        project(row)


def test_non_tuple_batch_and_non_evidence_records_are_rejected() -> None:
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=[alert(1)], as_of=AT,  # type: ignore[arg-type]
        )
    with pytest.raises(RelatedAlertRejected):
        project_related_alert_candidates(
            tenant_id=TENANT, evidence=(alert(1), "wrong"),  # type: ignore[arg-type]
            as_of=AT,
        )
