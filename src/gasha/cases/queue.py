"""Issue #45: defensive, read-only projection for a server-ranked analyst queue.

Only an explicitly installed, tenant-authorized reader may supply a snapshot.
Rank order is an external policy assertion, NOT a risk model, approved Bank
priority, proof of scenario detection, or permission to mutate a case/payment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.cases.timeline import CaseEvent, CaseOperation, validate_case_history

_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SCENARIOS = frozenset({
    "ATO-02", "ATO-06", "MM-01", "MM-02", "MM-05",
    "APP-01", "APP-02", "APP-05",
})
_ACTIVE = frozenset({CaseOperation.CREATE, CaseOperation.TRIAGE, CaseOperation.ASSIGN})


def valid_scenario_ids(scenario_ids: tuple[str, ...]) -> bool:
    """Validate concrete, deterministic, source-declared scenario vocabulary."""
    return (
        type(scenario_ids) is tuple
        and bool(scenario_ids)
        and all(type(scenario) is str and scenario in _SCENARIOS
                for scenario in scenario_ids)
        and scenario_ids == tuple(sorted(set(scenario_ids)))
    )


class CaseQueueRejected(ValueError):
    """Queue is not a complete, tenant-safe, canonical read projection."""


@dataclass(frozen=True, slots=True)
class RankedCase:
    """One already-ranked, single-source, multi-scenario *open* case.

    No request is permitted to supply these fields. The installed reader owns
    mapping one durable case and its immutable scenario evidence to this item.
    """
    rank: int
    case_id: UUID
    source_event_id: UUID
    source_context_ref: str
    scenario_ids: tuple[str, ...]
    history: tuple[CaseEvent, ...]


@dataclass(frozen=True, slots=True)
class CaseQueueSnapshot:
    """Server-side read result; policy_version is a label, not approval."""
    tenant_id: str
    ranking_policy_version: str
    generated_at: datetime
    items: tuple[RankedCase, ...]


def project_case_queue(
    snapshot: CaseQueueSnapshot, *, tenant_id: str, limit: int, at: datetime,
) -> dict[str, object]:
    """Check the whole result before exposing any case; reject on one bad row.

    Does NOT verify the installed reader's authority, ranking math, source
    records or scenario evidence. Those need separate Bank-approved adapters.
    """
    if (
        type(snapshot) is not CaseQueueSnapshot
        or type(tenant_id) is not str
        or not tenant_id
        or type(limit) is not int
        or not 1 <= limit <= 100
        or type(at) is not datetime
        or type(at.tzinfo) not in (timezone, ZoneInfo)
        or at.utcoffset() is None
    ):
        raise CaseQueueRejected("typed tenant-scoped queue request required")
    if (
        type(snapshot.tenant_id) is not str
        or snapshot.tenant_id != tenant_id
        or type(snapshot.ranking_policy_version) is not str
        or _VERSION.fullmatch(snapshot.ranking_policy_version) is None
        or type(snapshot.generated_at) is not datetime
        # A reader-owned timezone callback must not execute before validation.
        or type(snapshot.generated_at.tzinfo) not in (timezone, ZoneInfo)
        or snapshot.generated_at.utcoffset() is None
        or snapshot.generated_at.astimezone(UTC) > at.astimezone(UTC)
        or type(snapshot.items) is not tuple
        or len(snapshot.items) > limit
    ):
        raise CaseQueueRejected("invalid queue snapshot scope or version")
    seen_cases: set[UUID] = set()
    seen_sources: set[UUID] = set()
    rows: list[dict[str, object]] = []
    for position, item in enumerate(snapshot.items, 1):
        if (
            type(item) is not RankedCase
            or type(item.rank) is not int
            or item.rank != position
            or type(item.case_id) is not UUID
            or type(item.source_event_id) is not UUID
            or type(item.source_context_ref) is not str
            or _DIGEST.fullmatch(item.source_context_ref) is None
            or not valid_scenario_ids(item.scenario_ids)
            or type(item.history) is not tuple
            or not item.history
            or item.case_id in seen_cases
            or item.source_event_id in seen_sources
        ):
            raise CaseQueueRejected("invalid or duplicate ranked case")
        try:
            validate_case_history(item.history, tenant_id=tenant_id, case_id=item.case_id)
        except Exception as exc:
            raise CaseQueueRejected("invalid case chronology in queue") from exc
        initial, latest = item.history[0], item.history[-1]
        if (
            initial.source_event_id != item.source_event_id
            or initial.source_context_ref != item.source_context_ref
            or latest.operation not in _ACTIVE
            or latest.recorded_at.astimezone(UTC) >
                snapshot.generated_at.astimezone(UTC)
        ):
            raise CaseQueueRejected("closed, future or mismatched case in queue")
        seen_cases.add(item.case_id)
        seen_sources.add(item.source_event_id)
        rows.append({
            "rank": position,
            "case_id": str(item.case_id),
            "source_event_id": str(item.source_event_id),
            "source_context_ref": item.source_context_ref,
            "scenario_ids": list(item.scenario_ids),
            "status": latest.operation.value,
            "revision": latest.revision,
            "created_at": initial.recorded_at.astimezone(UTC).isoformat(),
            "updated_at": latest.recorded_at.astimezone(UTC).isoformat(),
            "assignee_ref": latest.assignee_ref,
            "bank_execution": "unknown",
        })
    return {
        "tenant_scope": "authenticated_reader",
        "ranking_policy_version": snapshot.ranking_policy_version,
        "generated_at": snapshot.generated_at.astimezone(UTC).isoformat(),
        "items": rows,
        "bank_ranking_approved": False,
        "enforcement_activated": False,
    }
