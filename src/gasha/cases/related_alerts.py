"""Issue #45 / FR-32: inert, tenant-scoped, related-finding candidate projection.

All links, contexts and policies are source assertions, NOT Bank-verified authority.
No protected API, case merge, durable write, fraud label or enforcement is provided.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from json import dumps
from re import fullmatch
from typing import cast
from uuid import UUID

_SCENARIOS = frozenset({
    "ATO-02", "ATO-06", "MM-01", "MM-02", "MM-05",
    "APP-01", "APP-02", "APP-05",
})
_SCOPE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}"
_DIGEST_PATTERN = r"[0-9a-f]{64}"
_LINK_CLASSES = frozenset({"journey", "beneficiary_network", "device_session"})
_UNAVAILABLE = frozenset({"missing", "ambiguous", "unauthorized"})


class RelatedAlertRejected(ValueError):
    """Malformed or contradictory input; never return a partial projection."""


@dataclass(frozen=True, slots=True)
class RelatedAlertPolicy:
    """Source-supplied policy shape, not proof of server or Bank authorization."""

    policy_id: str = "synthetic-related-alerts"
    version: str = "v1"
    linkage_class: str = "journey"
    window_seconds: int = 900
    boundary: str = "inclusive"
    max_group_size: int = 50
    unavailable_behavior: str = "singleton"


DEFAULT_POLICY = RelatedAlertPolicy()


@dataclass(frozen=True, slots=True)
class RelatedAlertEvidence:
    """One finding, one canonical scenario, no raw customer identity or free text."""

    tenant_id: str
    event_id: UUID
    context_ref: str
    link_ref: str | None
    observed_at: datetime
    scenario_ids: tuple[str, ...]
    linkage_availability: str = "available"


@dataclass(frozen=True, slots=True)
class _Finding:
    """Detached primitive-only snapshot. No source record/tzinfo references."""

    event_id: str
    context_ref: str
    link_ref: str | None
    observed_at: datetime
    scenario_id: str
    availability: str


def _instant(value: datetime) -> datetime:
    """Read custom tzinfo only once, never re-enter it during UTC conversion."""
    if type(value) is not datetime:
        raise RelatedAlertRejected("aware observation and projection clocks required")
    try:
        # Snapshot the local civil clock *before* an untrusted tzinfo callback.
        civil = (
            value.year, value.month, value.day, value.hour,
            value.minute, value.second, value.microsecond,
        )
        offset = value.utcoffset()
        if type(offset) is not timedelta or not -timedelta(days=1) < offset < timedelta(days=1):
            raise ValueError("invalid or absent time offset")
        return datetime(*civil, tzinfo=UTC) - offset
    except Exception as exc:
        raise RelatedAlertRejected("invalid observation or projection clock") from exc


def _policy_snapshot(policy: RelatedAlertPolicy) -> tuple[dict[str, object], str]:
    if type(policy) is not RelatedAlertPolicy:
        raise RelatedAlertRejected("invalid grouping policy type")
    values = (
        policy.policy_id, policy.version, policy.linkage_class,
        policy.window_seconds, policy.boundary, policy.max_group_size,
        policy.unavailable_behavior,
    )
    if (
        type(values[0]) is not str or fullmatch(_SCOPE_PATTERN, values[0]) is None
        or type(values[1]) is not str or fullmatch(_SCOPE_PATTERN, values[1]) is None
        or type(values[2]) is not str or values[2] not in _LINK_CLASSES
        or type(values[3]) is not int or not 1 <= values[3] <= 604800
        or type(values[4]) is not str or values[4] not in {"inclusive", "exclusive"}
        or type(values[5]) is not int or not 2 <= values[5] <= 50
        or values[6] != "singleton" or type(values[6]) is not str
    ):
        raise RelatedAlertRejected("invalid bounded grouping policy")
    fields = {
        "policy_id": values[0], "version": values[1],
        "linkage_class": values[2], "window_seconds": values[3],
        "boundary": values[4], "max_group_size": values[5],
        "unavailable_behavior": values[6],
    }
    digest = sha256(dumps(
        {"domain": "gasha-related-alert-policy-v1", **fields},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return fields, digest


_FIELDS = (
    "tenant_id", "event_id", "context_ref", "link_ref",
    "observed_at", "scenario_ids", "linkage_availability",
)


def _unchanged(row: RelatedAlertEvidence, captured: tuple[object, ...]) -> bool:
    return all(getattr(row, name) is original for name, original in zip(_FIELDS, captured))


def _snapshot(
    row: RelatedAlertEvidence, *, tenant_id: str, at: datetime,
) -> tuple[_Finding, tuple[object, ...]]:
    if type(row) is not RelatedAlertEvidence:
        raise RelatedAlertRejected("invalid finding record")
    captured: tuple[object, ...] = (
        row.tenant_id, row.event_id, row.context_ref, row.link_ref,
        row.observed_at, row.scenario_ids, row.linkage_availability,
    )
    tenant, event, context, link, observed, scenarios, availability = captured
    if (
        type(tenant) is not str or tenant != tenant_id
        or type(event) is not UUID or event.int == 0
        or type(context) is not str or fullmatch(_DIGEST_PATTERN, context) is None
        or type(observed) is not datetime
        or type(scenarios) is not tuple or len(scenarios) != 1
        or type(scenarios[0]) is not str or scenarios[0] not in _SCENARIOS
        or type(availability) is not str
        or (
            availability == "available"
            and (type(link) is not str or fullmatch(_DIGEST_PATTERN, link) is None)
        )
        or (
            availability != "available"
            and (availability not in _UNAVAILABLE or link is not None)
        )
    ):
        raise RelatedAlertRejected("invalid, ambiguous or wrong-tenant finding")
    # All identity, scope and scenario values were detached before calling tzinfo.
    normalized = _instant(cast(datetime, observed))
    if not _unchanged(row, captured):
        raise RelatedAlertRejected("finding changed during clock normalization")
    if normalized > at:
        raise RelatedAlertRejected("future observation is not eligible")
    return _Finding(
        event_id=str(event), context_ref=cast(str, context),
        link_ref=cast(str | None, link), observed_at=normalized,
        scenario_id=cast(tuple[str, ...], scenarios)[0],
        availability=cast(str, availability),
    ), captured


def _member(row: _Finding) -> dict[str, str]:
    return {
        "source_event_id": row.event_id,
        "context_ref": row.context_ref,
        "observed_at": row.observed_at.isoformat(),
        "scenario_id": row.scenario_id,
    }


def _digest(value: object) -> str:
    return sha256(dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def project_related_alert_candidates(
    *,
    tenant_id: str,
    evidence: tuple[RelatedAlertEvidence, ...],
    as_of: datetime,
    max_alerts: int = 500,
    max_group_size: int = 50,
    policy: RelatedAlertPolicy = DEFAULT_POLICY,
) -> dict[str, object]:
    """Pure, order-independent, candidate-only grouping for synthetic review.

    Window partitions use earliest observation as anchor, sorted by UTC time
    then event UUID. The exact cutoff is controlled by policy.boundary.
    Missing/ambiguous/unauthorized links remain visible singletons.
    """
    if (
        type(tenant_id) is not str
        or fullmatch(_SCOPE_PATTERN, tenant_id) is None
        or type(evidence) is not tuple
        or type(max_alerts) is not int or not 1 <= max_alerts <= 500
        or type(max_group_size) is not int or not 2 <= max_group_size <= 50
        or len(evidence) > max_alerts
    ):
        raise RelatedAlertRejected("invalid bounded tenant candidate request")
    policy_fields, policy_digest = _policy_snapshot(policy)
    # No policy source reference is consulted after untrusted clock callbacks.
    at = _instant(as_of)
    by_link: dict[str, list[_Finding]] = defaultdict(list)
    unlinked: list[_Finding] = []
    originals: list[tuple[RelatedAlertEvidence, tuple[object, ...]]] = []
    seen_events: set[str] = set()
    for row in evidence:
        finding, captured = _snapshot(row, tenant_id=tenant_id, at=at)
        originals.append((row, captured))
        if finding.event_id in seen_events:
            raise RelatedAlertRejected("duplicate source-event identity")
        seen_events.add(finding.event_id)
        if finding.link_ref is None:
            unlinked.append(finding)
        else:
            by_link[finding.link_ref].append(finding)
    # A callback belonging to a later row may have mutated an earlier row.
    # Never use the source objects to build output, and reject such a race.
    if any(not _unchanged(row, captured) for row, captured in originals):
        raise RelatedAlertRejected("finding changed during source snapshot")
    # Custom tzinfo can also mutate the policy: never consume that new policy.
    if _policy_snapshot(policy)[0] != policy_fields:
        raise RelatedAlertRejected("grouping policy changed during snapshot")

    groups: list[dict[str, object]] = []
    singletons: list[dict[str, str]] = []
    linked_count = 0
    effective_limit = min(max_group_size, cast(int, policy_fields["max_group_size"]))
    window = timedelta(seconds=cast(int, policy_fields["window_seconds"]))
    inclusive = policy_fields["boundary"] == "inclusive"

    def emit_singleton(finding: _Finding) -> None:
        singletons.append({
            **_member(finding),
            "linkage_availability": finding.availability,
            "reason_code": (
                "LINKAGE_UNAVAILABLE" if finding.link_ref is None
                else "NO_OTHER_FINDING_WITHIN_WINDOW"
            ),
        })

    for finding in unlinked:
        emit_singleton(finding)
    for link, arrivals in sorted(by_link.items()):
        members = sorted(arrivals, key=lambda r: (r.observed_at, r.event_id))
        index = 0
        while index < len(members):
            anchor = members[index].observed_at
            end = index + 1
            while end < len(members):
                delta = members[end].observed_at - anchor
                if not (delta <= window if inclusive else delta < window):
                    break
                end += 1
            cohort = members[index:end]
            if len(cohort) > effective_limit:
                raise RelatedAlertRejected("related-alert candidate exceeds group bound")
            if len(cohort) == 1:
                emit_singleton(cohort[0])
            else:
                linked_count += len(cohort)
                attached = [_member(r) for r in cohort]
                groups.append({
                    "candidate_ref": _digest({
                        "domain": "gasha-related-alert-candidate-v2",
                        "tenant_id": tenant_id,
                        "policy_digest": policy_digest,
                        "link_ref": link,
                        "members": attached,
                    }),
                    "source_event_ids": [r.event_id for r in cohort],
                    "source_event_count": len(cohort),
                    "scenario_ids": sorted({r.scenario_id for r in cohort}),
                    "member_evidence": attached,
                    "first_observed_at": cohort[0].observed_at.isoformat(),
                    "last_observed_at": cohort[-1].observed_at.isoformat(),
                    "reason_code": "SHARED_ASSERTED_LINK_WITHIN_POLICY_WINDOW",
                    "linkage_availability": "source_asserted_not_verified",
                    "policy_version": policy_fields["version"],
                    "policy_digest": policy_digest,
                    "case_merge_performed": False,
                })
            index = end
    singletons.sort(key=lambda r: (r["observed_at"], r["source_event_id"]))
    groups.sort(key=lambda group: (
        -cast(int, group["source_event_count"]),
        str(group["first_observed_at"]), str(group["candidate_ref"]),
    ))
    if linked_count + len(singletons) != len(evidence):
        raise RelatedAlertRejected("finding reconciliation invariant failed")
    return {
        "source": "unverified_source_asserted_links_only",
        "tenant_id": tenant_id,
        "as_of": at.isoformat(),
        "policy_id": policy_fields["policy_id"],
        "policy_version": policy_fields["version"],
        "policy_digest": policy_digest,
        "linkage_class": policy_fields["linkage_class"],
        "window_seconds": policy_fields["window_seconds"],
        "window_boundary": policy_fields["boundary"],
        "alert_count": len(evidence),
        "raw_finding_count": len(evidence),
        "candidate_group_count": len(groups),
        "candidate_linked_alert_count": linked_count,
        "grouped_member_count": linked_count,
        "unlinked_singleton_count": len(singletons),
        "quarantined_count": 0,
        "reviewable_case_count": len(groups) + len(singletons),
        "candidates": groups,
        "singletons": singletons,
        "bank_correlation_approved": False,
        "bank_source_provenance_verified": False,
        "bank_ranking_approved": False,
        "case_merge_performed": False,
        "enforcement_activated": False,
        "limitations": (
            "Linkage digests and policy are source assertions, not Bank authorization.",
            "Grouping changes neither immutable findings nor fraud or execution state.",
            "No Bank provenance, ranking, labels, KPI, case merge or payment authority.",
        ),
    }
