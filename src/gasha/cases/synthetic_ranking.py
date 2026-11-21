"""Versioned synthetic priority computation for the protected case queue."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID
from zoneinfo import ZoneInfo

from gasha.cases.evaluation_alerts import (
    AlertPolicy,
    alert_evidence,
    alert_group_ref,
    persisted_evaluation_context_matches,
)
from gasha.cases.postgres_history_reader import authorized_case_read
from gasha.cases.postgres_queue_reader import RankedCaseReference, RankedCaseSelection
from gasha.cases.queue import CaseQueueRejected
from gasha.orchestration import ShadowEvaluationRecord
from gasha.postgres import Connection
from gasha.security.access import TrustedPrincipal

_POLICY_VERSION = "synthetic-alert-priority-v1"
_MAX_ALERTS = 10_000


@dataclass(frozen=True, slots=True)
class _RankedEvidence:
    case_id: UUID
    event_id: UUID
    source_event_id: UUID
    context_ref: str
    group_ref: str
    scenarios: tuple[str, ...]
    opened_at: datetime
    priority: int
    score: float

    def sort_key(self, at: datetime) -> tuple[int, float, datetime, UUID]:
        # Escalate a tier per day of waiting, capped at the highest severity.
        opened_utc = self.opened_at.astimezone(UTC)
        wait_days = (at.astimezone(UTC) - opened_utc) // timedelta(days=1)
        effective_priority = min(3, self.priority + wait_days)
        return (-effective_priority, -self.score, opened_utc, self.case_id)


class SyntheticPostgresRankingSource:
    """Compute queue positions from tenant-bound alert evidence in one SQL snapshot.

    The existing protected queue reader independently rechecks case histories.
    This source is installed explicitly in the lab and has a bounded cohort so
    it can revalidate every contributing alert before returning any ranking.
    """

    def __init__(
        self, *, connections: Callable[[], AbstractContextManager[Connection]],
        tenant_id: str, alert_policies: tuple[AlertPolicy, ...],
    ) -> None:
        self._connections = connections
        self._tenant_id = tenant_id
        self._policies = {policy.version: policy for policy in alert_policies}
        if not self._policies or len(self._policies) != len(alert_policies):
            raise ValueError("ranking needs unique historical alert policies")

    def select(
        self, *, principal: TrustedPrincipal, tenant_id: str, limit: int, at: datetime,
    ) -> RankedCaseSelection:
        authorized_case_read(principal=principal, tenant_id=tenant_id, at=at)
        if tenant_id != self._tenant_id or type(limit) is not int or not 1 <= limit <= 100:
            raise CaseQueueRejected("ranking request outside configured scope")
        at = at.astimezone(UTC)
        with self._connections() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT a.*, evaluation.record_json, initial.source_event_id,
                       initial.source_context_ref, initial.occurred_at AS opened_at,
                       latest.occurred_at AS last_transition_at
                FROM evaluation_alerts a
                JOIN shadow_evaluations evaluation USING (tenant_id, event_id)
                JOIN analyst_case_events initial
                  ON initial.tenant_id = a.tenant_id AND initial.case_id = a.case_id
                 AND initial.revision = 1
                JOIN LATERAL (
                    SELECT occurred_at, event_json->>'operation' AS operation
                    FROM analyst_case_events c
                    WHERE c.tenant_id = a.tenant_id AND c.case_id = a.case_id
                    ORDER BY revision DESC LIMIT 1
                ) latest ON latest.operation IN ('create', 'triage', 'assign')
                WHERE a.tenant_id = %s
                LIMIT %s
                """,
                (tenant_id, _MAX_ALERTS + 1),
            )
            rows = cursor.fetchall()
        if len(rows) > _MAX_ALERTS:
            raise CaseQueueRejected("synthetic ranking cohort exceeds capacity")

        primary: dict[UUID, _RankedEvidence] = {}
        strongest: dict[UUID, _RankedEvidence] = {}
        case_groups: dict[UUID, str] = {}
        for row in rows:
            item = self._verify(row, at=at)
            if case_groups.setdefault(item.case_id, item.group_ref) != item.group_ref:
                raise CaseQueueRejected("case contains unrelated alert evidence")
            if item.event_id == item.source_event_id:
                primary[item.case_id] = item
            previous = strongest.get(item.case_id)
            if previous is None or item.sort_key(at) < previous.sort_key(at):
                strongest[item.case_id] = item
        if primary.keys() != strongest.keys():
            raise CaseQueueRejected("case has no primary alert")
        order = sorted(strongest, key=lambda case_id: strongest[case_id].sort_key(at))[:limit]
        return RankedCaseSelection(tenant_id, _POLICY_VERSION, tuple(
            RankedCaseReference(case_id, primary[case_id].event_id, primary[case_id].context_ref,
                                primary[case_id].scenarios)
            for case_id in order
        ))

    def _verify(self, row: Mapping[str, object], *, at: datetime) -> _RankedEvidence:
        case_id, event_id, source_event_id = row["case_id"], row["event_id"], row["source_event_id"]
        opened_at, generated_at = row["opened_at"], row["generated_at"]
        last_transition_at = row["last_transition_at"]
        if (
            row["tenant_id"] != self._tenant_id
            or type(case_id) is not UUID
            or type(event_id) is not UUID
            or type(source_event_id) is not UUID
            or type(opened_at) is not datetime
            or type(generated_at) is not datetime
            or type(last_transition_at) is not datetime
            or any(
                type(clock.tzinfo) not in (timezone, ZoneInfo) or clock.utcoffset() is None
                for clock in (opened_at, generated_at, last_transition_at)
            )
            or not opened_at.astimezone(UTC) <= generated_at.astimezone(UTC) <= at
            or not opened_at.astimezone(UTC) <= last_transition_at.astimezone(UTC) <= at
        ):
            raise CaseQueueRejected("invalid or future-dated alert evidence")
        policy = self._policies.get(str(row["policy_version"]))
        if policy is None:
            raise CaseQueueRejected("alert policy version unavailable")
        raw_record_json = str(row["record_json"])
        record = ShadowEvaluationRecord.model_validate_json(raw_record_json)
        evidence = alert_evidence(self._tenant_id, record, policy)
        if evidence is None:
            raise CaseQueueRejected("persisted evaluation does not qualify for an alert")
        priority, scenarios = evidence
        context_ref = row["context_ref"]
        if type(context_ref) is not str or not persisted_evaluation_context_matches(
            record, raw_record_json=raw_record_json, stored_context_ref=context_ref,
        ):
            raise CaseQueueRejected("alert and persisted evaluation disagree")
        group_ref = alert_group_ref(record, policy.version)
        decision = record.evaluation.decision
        if (
            record.event.event_id != event_id
            or row["group_ref"] != group_ref
            or row["decision_action"] != decision.action.value
            or row["risk_score"] != decision.risk_score
            or row["priority_seed"] != priority
            or row["scenario_ids"] != list(scenarios)
            or (event_id == source_event_id and (
                row["source_context_ref"] != context_ref
                or opened_at.astimezone(UTC) != generated_at.astimezone(UTC)
            ))
        ):
            raise CaseQueueRejected("alert and persisted evaluation disagree")
        return _RankedEvidence(
            case_id, event_id, source_event_id, context_ref, group_ref, scenarios, opened_at,
            priority, decision.risk_score,
        )
