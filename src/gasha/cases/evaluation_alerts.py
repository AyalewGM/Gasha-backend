"""Opt-in synthetic evaluation-to-case composition. No bank execution authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from math import isfinite
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from pydantic_core import TzInfo

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
from gasha.orchestration import ShadowEvaluationRecord, canonical_evaluation_context_payload
from gasha.postgres import Connection
from gasha.security.access import Capability, TrustedPrincipal, authorize, tenant_audit_ref


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, ZoneInfo, TzInfo):
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
    policy_id: str = "gasha-synthetic-alert-policy"

    def __post_init__(self) -> None:
        if (
            type(self.policy_id) is not str or not self.policy_id.strip()
            or type(self.version) is not str or not self.version.strip()
            or type(self.minimum_score) not in (int, float)
            or not isfinite(self.minimum_score)
            or not 0 <= self.minimum_score <= 1
            or type(self.scenario_by_reason) is not tuple
        ):
            raise ValueError("invalid alert policy")
        for item in self.scenario_by_reason:
            if type(item) is not tuple or len(item) != 2:
                raise ValueError("invalid alert scenario mapping")
            reason, scenario = item
            if (
                type(reason) is not str or not reason.strip()
                or type(scenario) is not str
                or not valid_scenario_ids((scenario,))
            ):
                raise ValueError("invalid alert scenario mapping")


ALERT_POLICY_DIGEST_SCHEMA = "gasha-alert-policy-content-v1"


def alert_policy_content(policy: AlertPolicy) -> dict[str, object]:
    """Complete versioned alert decision policy, not just a selected alert.

    This content is compared to a separate server-provisioned, tenant-scoped
    installation record. A supplied policy version/label is never proof of
    installation. Changes to any code-defined eligibility, grouping, priority,
    or evidence rule require a new digest-schema version.
    """
    return {
        "digest_schema": ALERT_POLICY_DIGEST_SCHEMA,
        "policy_id": policy.policy_id,
        "version": policy.version,
        "minimum_score": float(policy.minimum_score),
        "scenario_by_reason": [list(item) for item in sorted(policy.scenario_by_reason)],
        "eligible_action_priority": [
            [action.value, seed] for action, seed in
            sorted(_PRIORITY_V1.items(), key=lambda item: item[0].value)
        ],
        "eligible_mode": OperatingMode.SHADOW.value,
        "effective_action": DecisionAction.NO_ACTION_SHADOW.value,
        "grouping_schema": "gasha-alert-group-v1",
        "grouping_inputs": [
            "tenant_id", "policy_version", "occurred_at_utc_hour",
            "sender_customer_id", "beneficiary_type",
            "destination_institution_id", "beneficiary_id", "device_id",
        ],
        "missing_grouping_input_behavior": "append_event_id",
        "scenario_match_rule": "matching_reason_code_deduped_and_sorted",
        "score_qualification_rule": "risk_score_gte_minimum",
        "context_schema": "gasha-shadow-evaluation-v1",
        "qualification_schema": "gasha-alert-qualification-v1",
    }


def alert_policy_digest(policy: AlertPolicy) -> str:
    """Domain-separated digest of the complete canonical alert policy."""
    return _digest(["gasha-alert-policy-installation", alert_policy_content(policy)])


def evaluation_context_ref(record: ShadowEvaluationRecord) -> str:
    return _digest(["gasha-shadow-evaluation-v1", canonical_evaluation_context_payload(record)])


def alert_group_ref(record: ShadowEvaluationRecord, policy_version: str) -> str:
    event = record.event
    transaction = event.canonical_transaction
    bucket = _utc(transaction.occurred_at).replace(minute=0, second=0, microsecond=0)
    grouping = [
        "gasha-alert-group-v1", event.tenant_id, policy_version, bucket.isoformat(),
        transaction.sender_customer_id, transaction.beneficiary_type.value,
        transaction.destination_institution_id, transaction.beneficiary_id,
        transaction.device_id,
    ]
    # Incomplete entity identifiers must never coalesce unrelated alerts.
    if not all((transaction.sender_customer_id, transaction.beneficiary_id, transaction.device_id)):
        grouping.append(str(event.event_id))
    return _digest(grouping)


def alert_evidence(
    tenant_id: str, record: ShadowEvaluationRecord, policy: AlertPolicy,
) -> tuple[int, tuple[str, ...]] | None:
    event = record.event
    decision = record.evaluation.decision
    transaction = event.canonical_transaction
    identity = (tenant_id, event.event_id)
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
        scenario for reason, scenario in policy.scenario_by_reason
        if reason in decision.reason_codes
    }))
    if priority is None or decision.risk_score < policy.minimum_score or not scenarios:
        return None
    return priority, scenarios


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

    def require_current_principal(self) -> datetime:
        """Check tenant-bound create authority even on an idempotent retry."""
        authorize(self.principal, tenant_id=self.tenant_id, capability=Capability.CASE_CREATE)
        expiry = _utc(self.principal.expires_at)
        if datetime.now(UTC) >= expiry:
            raise ValueError("alert writer requires a current service credential")
        return expiry

    def append(
        self, connection: Connection, record: ShadowEvaluationRecord,
    ) -> None:
        if getattr(connection, "autocommit", None) is not False:
            raise ValueError("alert creation requires autocommit=False")
        evidence = alert_evidence(self.tenant_id, record, self.policy)
        if evidence is None:
            return
        priority, scenarios = evidence
        event = record.event
        decision = record.evaluation.decision
        expiry = self.require_current_principal()

        group_ref = alert_group_ref(record, self.policy.version)
        context_ref = evaluation_context_ref(record)

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (group_ref,),
            )
            cursor.execute(
                """
                SELECT DISTINCT a.case_id
                FROM evaluation_alerts a
                JOIN analyst_case_events initial
                  ON initial.tenant_id = a.tenant_id AND initial.case_id = a.case_id
                 AND initial.revision = 1 AND initial.source_event_id = a.event_id
                 AND initial.source_context_ref = a.context_ref
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
        # Group and case locks may have blocked past the credential's expiry.
        at = datetime.now(UTC)
        if at >= expiry:
            raise ValueError("alert writer requires a current service credential")
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
