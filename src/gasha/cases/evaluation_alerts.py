"""Opt-in synthetic evaluation-to-case composition. No bank execution authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from gasha.cases.postgres_timeline import PostgresCaseTimelineService, lock_case_history
from gasha.cases.queue import valid_scenario_ids
from gasha.cases.timeline import (
    CaseCommand,
    CaseOperation,
    CaseReason,
    CaseSourceUnavailable,
    VerifiedEvaluation,
)
from gasha.domain.models import DecisionAction, OperatingMode
from gasha.orchestration import ShadowEvaluationRecord
from gasha.postgres import Connection
from gasha.security.access import Capability, TrustedPrincipal, authorize, tenant_audit_ref


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, ZoneInfo):
        raise ValueError("alert generation requires a timezone-aware clock")
    return value.astimezone(UTC)


_OPEN = {CaseOperation.CREATE, CaseOperation.TRIAGE, CaseOperation.ASSIGN}
_PRIORITY_V1 = {DecisionAction.REVIEW: 1, DecisionAction.HOLD: 2, DecisionAction.BLOCK: 3}


def _digest(value: object) -> str:
    return sha256(dumps(value, separators=(",", ":"), sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AlertPolicy:
    """Tenant-scoped deployment configuration, with versioned evidence mapping."""

    version: str
    minimum_score: float
    scenario_by_reason: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.version.strip() or not 0 <= self.minimum_score <= 1:
            raise ValueError("invalid alert policy")
        for reason, scenario in self.scenario_by_reason:
            if not reason.strip() or not valid_scenario_ids((scenario,)):
                raise ValueError("invalid alert scenario mapping")


@dataclass(frozen=True, slots=True)
class _EvaluationSource:
    reference: VerifiedEvaluation

    def resolve(self, tenant_id: str, event_id: UUID) -> VerifiedEvaluation:
        if (tenant_id, event_id) != (self.reference.tenant_id, self.reference.event_id):
            raise CaseSourceUnavailable("evaluation source is outside the case scope")
        return self.reference


@dataclass(frozen=True, slots=True)
class PostgresEvaluationAlertWriter:
    """Append an alert and, when needed, create its case on the evaluation transaction."""

    tenant_id: str
    policy: AlertPolicy
    principal: TrustedPrincipal

    def append(
        self, connection: Connection, record: ShadowEvaluationRecord, *, at: datetime,
    ) -> None:
        if getattr(connection, "autocommit", None) is not False:
            raise ValueError("alert creation requires autocommit=False")
        event = record.event
        decision = record.evaluation.decision
        transaction = event.canonical_transaction
        identity = (self.tenant_id, event.event_id)
        if (
            (event.tenant_id, event.event_id) != identity
            or (decision.tenant_id, decision.event_id) != identity
            or (transaction.tenant_id, transaction.event_id) != identity
            or event.operating_mode is not OperatingMode.SHADOW
            or record.evaluation.operating_mode is not OperatingMode.SHADOW
            or record.evaluation.effective_action is not DecisionAction.NO_ACTION_SHADOW
        ):
            raise ValueError("alert writer requires a tenant-bound shadow evaluation")

        priority = _PRIORITY_V1.get(decision.action)
        scenarios = tuple(sorted({
            scenario for reason, scenario in self.policy.scenario_by_reason
            if reason in decision.reason_codes
        }))
        if priority is None or decision.risk_score < self.policy.minimum_score or not scenarios:
            return
        authorize(self.principal, tenant_id=self.tenant_id, capability=Capability.CASE_CREATE)
        at = _utc(at)
        if at >= _utc(self.principal.expires_at):
            raise ValueError("alert writer requires a current service credential")

        bucket = _utc(transaction.occurred_at).replace(minute=0, second=0, microsecond=0)
        grouping = [
            "gasha-alert-group-v1", self.tenant_id, self.policy.version, bucket.isoformat(),
            transaction.sender_customer_id, transaction.beneficiary_type.value,
            transaction.destination_institution_id, transaction.beneficiary_id,
            transaction.device_id,
        ]
        # Incomplete entity identifiers must never coalesce unrelated alerts.
        if not all((transaction.sender_customer_id, transaction.beneficiary_id, transaction.device_id)):
            grouping.append(str(event.event_id))
        group_ref = _digest(grouping)
        context_ref = _digest(["gasha-shadow-evaluation-v1", record.model_dump(mode="json")])

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (group_ref,),
            )
            cursor.execute(
                """
                SELECT DISTINCT a.case_id
                FROM evaluation_alerts a
                JOIN LATERAL (
                    SELECT event_json->>'operation' AS operation
                    FROM analyst_case_events c
                    WHERE c.tenant_id = a.tenant_id AND c.case_id = a.case_id
                    ORDER BY revision DESC LIMIT 1
                ) latest ON latest.operation IN ('create', 'triage', 'assign')
                WHERE a.tenant_id = %s AND a.group_ref = %s
                LIMIT 2
                """,
                (self.tenant_id, group_ref),
            )
            matches = cursor.fetchall()
            if len(matches) > 1:
                raise ValueError("multiple open cases for alert group")
            case_id = None
            if matches:
                candidate = UUID(str(matches[0]["case_id"]))
                history = lock_case_history(cursor, self.tenant_id, candidate)
                if history and history[-1].operation in _OPEN:
                    case_id = candidate
        if case_id is None:
            case_id = uuid4()
            PostgresCaseTimelineService(connection).append_in_transaction(
                CaseCommand(
                    tenant_id=self.tenant_id,
                    case_id=case_id,
                    source_event_id=event.event_id,
                    operation=CaseOperation.CREATE,
                    expected_revision=0,
                    idempotency_key=event.event_id.hex,
                    reason_code=CaseReason.SOURCE_EVALUATION,
                ),
                principal=self.principal,
                source=_EvaluationSource(VerifiedEvaluation(self.tenant_id, event.event_id, context_ref)),
                at=at,
            )
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO evaluation_alerts (
                    tenant_id, event_id, case_id, group_ref, context_ref, policy_version,
                    decision_action, risk_score, priority_seed, scenario_ids, generated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                """,
                (
                    self.tenant_id, event.event_id, case_id, group_ref, context_ref,
                    self.policy.version, decision.action.value, decision.risk_score, priority,
                    dumps(scenarios), at,
                ),
            )
            cursor.execute(
                """
                INSERT INTO security_audit_events (
                    occurred_at, action, result, actor_ref, tenant_ref,
                    reason, attempt_ref, event_ref, context_ref
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    at, "alert.generate", "allowed", self.principal.audit_actor,
                    tenant_audit_ref(self.tenant_id), "alert_committed", uuid4().hex,
                    _digest(["gasha-alert-v1", self.tenant_id, str(event.event_id)]), context_ref,
                ),
            )
