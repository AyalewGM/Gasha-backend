"""Opt-in #45 PostgreSQL history binding for the protected analyst queue.

A Bank-authorized ranking/scenario evidence provider must independently supply
ranked immutable case references. This reader does not calculate fraud risk,
assert source provenance, install credentials, or authorize Bank actions.
Missing/corrupt/closed cases fail the entire queue, never return partial rows.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.cases.postgres_history_reader import (
    ExplicitPostgresCaseHistoryReader,
    authorized_case_read,
)
from gasha.cases.queue import (
    CaseQueueRejected,
    CaseQueueSnapshot,
    RankedCase,
    project_case_queue,
    valid_scenario_ids,
)
from gasha.postgres import Connection
from gasha.security.access import TrustedPrincipal

_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


@dataclass(frozen=True, slots=True)
class RankedCaseReference:
    """A ranking provider's claim, NOT independently attested Bank evidence."""

    case_id: UUID
    source_event_id: UUID
    source_context_ref: str
    scenario_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RankedCaseSelection:
    """Bounded output from a separately installed ranking/evidence authority."""

    tenant_id: str
    ranking_policy_version: str
    items: tuple[RankedCaseReference, ...]


class TrustedRankingSource(Protocol):
    """Installation must bind rank, case, policy and scenarios to trusted data."""

    def select(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        limit: int, at: datetime,
    ) -> RankedCaseSelection: ...


class ExplicitPostgresCaseQueueReader:
    """Read-through durable history verifier, deliberately unwired by default.

    A deployer must provide a fresh least-privilege DB connection and a trusted
    ranking source. This code validates consistency, not ranking authority.
    """

    def __init__(
        self, *, connections: Callable[[], AbstractContextManager[Connection]],
        ranking: TrustedRankingSource,
    ) -> None:
        self._history_reader = ExplicitPostgresCaseHistoryReader(connections=connections)
        self._ranking = ranking

    def read(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        limit: int, at: datetime,
    ) -> CaseQueueSnapshot:
        if (
            type(tenant_id) is not str or not tenant_id
            or tenant_id != tenant_id.strip()
            or type(limit) is not int or not 1 <= limit <= 100
            or type(at) is not datetime
            or type(at.tzinfo) not in (timezone, ZoneInfo)
            or at.utcoffset() is None
        ):
            raise CaseQueueRejected("typed tenant-scoped queue request required")
        accepted = authorized_case_read(
            principal=principal, tenant_id=tenant_id, at=at,
        )

        # Never let a ranking adapter mutate the principal later used for SQL.
        selection = self._ranking.select(
            principal=replace(accepted), tenant_id=tenant_id, limit=limit, at=at,
        )
        if (
            type(selection) is not RankedCaseSelection
            or type(selection.tenant_id) is not str
            or selection.tenant_id != tenant_id
            or type(selection.ranking_policy_version) is not str
            or _VERSION.fullmatch(selection.ranking_policy_version) is None
            or type(selection.items) is not tuple
            or len(selection.items) > limit
        ):
            raise CaseQueueRejected("invalid tenant-scoped rank selection")
        seen_cases: set[UUID] = set()
        seen_sources: set[UUID] = set()
        for item in selection.items:
            if (
                type(item) is not RankedCaseReference
                or type(item.case_id) is not UUID
                or type(item.source_event_id) is not UUID
                or type(item.source_context_ref) is not str
                or re.fullmatch(r"[0-9a-f]{64}", item.source_context_ref) is None
                or not valid_scenario_ids(item.scenario_ids)
                or item.case_id in seen_cases
                or item.source_event_id in seen_sources
            ):
                raise CaseQueueRejected("invalid or duplicate ranked reference")
            seen_cases.add(item.case_id)
            seen_sources.add(item.source_event_id)

        # Each ranked history reuses #130's exact authorization and immutable
        # row/JSON verification, on its own request-scoped read transaction.
        # These are sequential reads, NOT an atomic point-in-time snapshot:
        # a concurrent case change may invalidate the whole result; the
        # Bank installation must implement approved snapshot semantics first.
        ranked: list[RankedCase] = []
        for position, item in enumerate(selection.items, 1):
            history = self._history_reader.history(
                principal=accepted, tenant_id=tenant_id,
                case_id=item.case_id, at=at,
            )
            if not history:
                raise CaseQueueRejected("ranked case unavailable")
            ranked.append(RankedCase(
                rank=position, case_id=item.case_id,
                source_event_id=item.source_event_id,
                source_context_ref=item.source_context_ref,
                scenario_ids=item.scenario_ids, history=history,
            ))
        snapshot = CaseQueueSnapshot(
            tenant_id=tenant_id,
            ranking_policy_version=selection.ranking_policy_version,
            generated_at=at, items=tuple(ranked),
        )
        # Recheck *all* chronology, source identities, scenario vocabulary and
        # active status before the protected route can expose even one item.
        project_case_queue(snapshot, tenant_id=tenant_id, limit=limit, at=at)
        return snapshot
