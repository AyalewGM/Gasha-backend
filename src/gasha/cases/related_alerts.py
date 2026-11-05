"""Issue #45 / FR-32: inert, deterministic related-alert *candidate* projection.

A correlation digest supplied by a source is not verified Bank provenance or
proof that alerts belong to the same case. No case merge, durable write, scoring,
approval, analyst action, payment instruction or API endpoint is implemented.
An authorized, independently reviewed source adapter is required before use
with bank records. Deliberately separate from the protected ranked queue.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
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


class RelatedAlertRejected(ValueError):
    """Invalid, ambiguous or out-of-scope candidate evidence; no output."""


@dataclass(frozen=True, slots=True)
class RelatedAlertEvidence:
    """Opaque source assertion, NOT a trusted evaluation or correlation proof.

    link_ref must be a domain-separated digest of a source-controlled linkage
    attribute. This module never computes links from customer/account PII.
    """

    tenant_id: str
    event_id: UUID
    context_ref: str
    link_ref: str
    observed_at: datetime
    scenario_ids: tuple[str, ...]


def _instant(value: datetime) -> datetime:
    if type(value) is not datetime or value.utcoffset() is None:
        raise RelatedAlertRejected("aware observation and projection clocks required")
    return value.astimezone(UTC)


def _validated(
    row: RelatedAlertEvidence, *, tenant_id: str, at: datetime,
) -> tuple[datetime, RelatedAlertEvidence]:
    # Revalidate fields at consumption time: frozen-slotted records can still be
    # mutated through low-level Python primitives by a faulty in-process source.
    if (
        type(row) is not RelatedAlertEvidence
        or type(row.tenant_id) is not str
        or row.tenant_id != tenant_id
        or type(row.event_id) is not UUID
        or row.event_id.int == 0
        or type(row.context_ref) is not str
        or fullmatch(_DIGEST_PATTERN, row.context_ref) is None
        or type(row.link_ref) is not str
        or fullmatch(_DIGEST_PATTERN, row.link_ref) is None
        or type(row.scenario_ids) is not tuple
        or not row.scenario_ids
        or any(type(s) is not str or s not in _SCENARIOS for s in row.scenario_ids)
        or row.scenario_ids != tuple(sorted(set(row.scenario_ids)))
    ):
        raise RelatedAlertRejected("invalid or wrong-tenant alert evidence")
    observed = _instant(row.observed_at)
    if observed > at:
        raise RelatedAlertRejected("future observation is not eligible for linkage")
    return observed, row


def project_related_alert_candidates(
    *,
    tenant_id: str,
    evidence: tuple[RelatedAlertEvidence, ...],
    as_of: datetime,
    max_alerts: int = 500,
    max_group_size: int = 50,
) -> dict[str, object]:
    """Project possible links without merging underlying alert/case identities.

    Only two or more distinct source events with exactly the same asserted
    opaque linkage digest form a candidate. Every input is validated before
    any aggregate is exposed. Sort and digest members canonically so order
    and equivalent timezone representations do not change the result.
    A missing/ambiguous link cannot authorize consolidation.
    """
    if (
        type(tenant_id) is not str
        or fullmatch(_SCOPE_PATTERN, tenant_id) is None
        or type(evidence) is not tuple
        or type(max_alerts) is not int
        or not 1 <= max_alerts <= 500
        or type(max_group_size) is not int
        or not 2 <= max_group_size <= 50
        or len(evidence) > max_alerts
    ):
        raise RelatedAlertRejected("invalid bounded tenant candidate request")
    at = _instant(as_of)
    by_link: dict[str, list[tuple[datetime, RelatedAlertEvidence]]] = defaultdict(list)
    seen_events: set[UUID] = set()
    for row in evidence:
        observed, checked = _validated(row, tenant_id=tenant_id, at=at)
        if checked.event_id in seen_events:
            # Even identical duplicates must not inflate a grouping count.
            # Conflicting duplicates must not choose an arbitrary first copy.
            raise RelatedAlertRejected("duplicate source-event identity")
        seen_events.add(checked.event_id)
        by_link[checked.link_ref].append((observed, checked))

    groups: list[dict[str, object]] = []
    singleton_count = 0
    linked_count = 0
    for link_ref, members in by_link.items():
        if len(members) > max_group_size:
            raise RelatedAlertRejected("related-alert candidate exceeds group bound")
        if len(members) == 1:
            singleton_count += 1
            continue
        members.sort(key=lambda pair: (pair[0], pair[1].event_id.hex))
        linked_count += len(members)
        scenarios = sorted({
            scenario for _, alert in members for scenario in alert.scenario_ids
        })
        source_ids = [str(alert.event_id) for _, alert in members]
        # Include source context + observed time + scenarios in the identity:
        # changing a linked event's underlying asserted evidence changes the
        # candidate rather than silently reusing a stale grouping reference.
        candidate_preimage = {
            "domain": "gasha-related-alert-candidate-v1",
            "tenant": tenant_id,
            "link_ref": link_ref,
            "members": [
                {
                    "event_id": str(alert.event_id),
                    "context_ref": alert.context_ref,
                    "observed_at": observed.isoformat(),
                    "scenario_ids": list(alert.scenario_ids),
                }
                for observed, alert in members
            ],
        }
        candidate_ref = sha256(dumps(
            candidate_preimage, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        groups.append({
            "candidate_ref": candidate_ref,
            "source_event_ids": source_ids,
            "source_event_count": len(source_ids),
            "scenario_ids": scenarios,
            "first_observed_at": members[0][0].isoformat(),
            "last_observed_at": members[-1][0].isoformat(),
            "case_merge_performed": False,
        })
    # Stable canonical output regardless of record or group arrival order.
    groups.sort(key=lambda group: (
        -cast(int, group["source_event_count"]),
        str(group["first_observed_at"]), str(group["candidate_ref"]),
    ))
    return {
        "source": "unverified_source_asserted_links_only",
        "tenant_id": tenant_id,
        "as_of": at.isoformat(),
        "alert_count": len(evidence),
        "candidate_group_count": len(groups),
        "candidate_linked_alert_count": linked_count,
        "unlinked_singleton_count": singleton_count,
        "candidates": groups,
        "bank_correlation_approved": False,
        "bank_source_provenance_verified": False,
        "enforcement_activated": False,
        "limitations": (
            "Correlation digest is a source assertion, not a Bank-approved relationship.",
            "Candidate groups do not consolidate cases or alter original evaluations.",
            "Missing links, linkage correctness and customer identity are not inferred.",
        ),
    }
