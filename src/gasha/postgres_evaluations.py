from __future__ import annotations

import json
from typing import cast
from uuid import UUID

from gasha.cases.evaluation_alerts import (
    ALERT_POLICY_DIGEST_SCHEMA,
    PostgresEvaluationAlertWriter,
    alert_policy_content,
    alert_policy_digest,
)
from gasha.decision.audit import DecisionAuditRecord
from gasha.ingestion.lease import EvaluationLease, LeaseLostError, current_evaluation_lease
from gasha.orchestration import ShadowEvaluationRecord, canonical_evaluation_context_payload
from gasha.postgres import Connection, Cursor
from gasha.tenant_scope import require_tenant


class PostgresShadowEvaluationRepository:
    """PostgreSQL adapter for persisted shadow/enforcing evaluations.

    First write wins on ``(tenant_id, event_id)`` — a resubmitted
    evaluation returns the originally persisted record, matching the
    in-memory contract.
    """

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None
    ) -> None:
        self._tenant_ids = tenant_ids
        self._connection = connection

    def get(
        self, tenant_id: str, event_id: UUID
    ) -> ShadowEvaluationRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT record_json
                FROM shadow_evaluations
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ShadowEvaluationRecord.model_validate_json(
            str(row["record_json"])
        )

    def save(self, record: ShadowEvaluationRecord) -> ShadowEvaluationRecord:
        require_tenant(record.event.tenant_id, self._tenant_ids)
        with self._connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO shadow_evaluations (
                    tenant_id, event_id, record_json, persisted_at
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    record.event.tenant_id,
                    str(record.event.event_id),
                    record.model_dump_json(),
                    record.persisted_at,
                ),
            )
        self._connection.commit()

        persisted = self.get(record.event.tenant_id, record.event.event_id)
        if persisted is None:
            raise RuntimeError(
                "shadow evaluation save completed without a record"
            )
        return persisted


def _require_live_lease(cursor: Cursor, lease: EvaluationLease) -> None:
    cursor.execute(
        """SELECT lease_token FROM pending_evaluations
        WHERE tenant_id = %s AND event_id = %s
          AND lease_token = %s AND leased_until > clock_timestamp()""",
        (lease.tenant_id, str(lease.event_id), lease.token),
    )
    if cursor.fetchone() is None:
        raise LeaseLostError("evaluation claim expired")


def _immutable_replay_identity(record: ShadowEvaluationRecord) -> dict[str, object]:
    """Semantic decision input/output identity; exclude only write-time clocks.

    The event's canonical transaction, adapter/schema *versions*, intelligence,
    reasons and policy provenance remain immutable. Receipt/normalization time,
    decision clock, evaluation latency and persistence time can differ on an
    otherwise identical retry and are not fraud-decision inputs.
    """
    value = canonical_evaluation_context_payload(record)
    value.pop("persisted_at", None)
    event = value["event"]
    if isinstance(event, dict):
        event.pop("received_at", None)
        adapter = event.get("adapter")
        if isinstance(adapter, dict):
            adapter.pop("normalized_at", None)
    evaluation = value["evaluation"]
    if isinstance(evaluation, dict):
        evaluation.pop("evaluated_at", None)
        evaluation.pop("evaluation_latency_ms", None)
        decision = evaluation.get("decision")
        if isinstance(decision, dict):
            decision.pop("decided_at", None)
    return value


def _verify_alert_policy_provenance(
    cursor: Cursor,
    record: ShadowEvaluationRecord,
    *,
    alerts: PostgresEvaluationAlertWriter,
    inserted: bool,
) -> None:
    """Bind EVERY event to separately installed, immutable policy content.

    The runtime cannot create/repair the installation record. It must match
    the full code-defined eligibility, mapping, priority and grouping policy,
    not just the fields which happened to qualify this evaluation. Both
    policy installation and per-event provenance are read in the same READ
    COMMITTED transaction as the decision/alert/case writes. The immutable
    installation and provenance rows need no row lock: PostgreSQL requires
    UPDATE privileges for both SELECT FOR SHARE and SELECT FOR UPDATE, while
    the separate provisioning/runtime trust boundary grants only SELECT on
    policy installations and SELECT/INSERT on provenance. The canonical
    evaluation, decision audit, and alert rows remain row-locked on replay.
    """
    policy = alerts.policy
    tenant = record.event.tenant_id
    event_id = str(record.event.event_id)
    cursor.execute(
        """SELECT digest_schema, content_digest, content_json, installation_ref
           FROM tenant_alert_policy_installations
           WHERE tenant_id = %s AND policy_id = %s AND policy_version = %s
           """,
        (tenant, policy.policy_id, policy.version),
    )
    installed = cursor.fetchone()
    if (
        installed is None
        or installed["digest_schema"] != ALERT_POLICY_DIGEST_SCHEMA
        or installed["content_json"] != alert_policy_content(policy)
        or installed["content_digest"] != alert_policy_digest(policy)
    ):
        raise ValueError("conflicting evaluation replay: untrusted alert policy installation")

    # The source of installation_ref is the separately provisioned, immutable DB
    # record, never a caller-provided policy label or evaluation claim.
    expected = (
        policy.policy_id, policy.version, ALERT_POLICY_DIGEST_SCHEMA,
        alert_policy_digest(policy), installed["installation_ref"],
    )
    if inserted:
        cursor.execute(
            """INSERT INTO evaluation_alert_policy_provenance (
                 tenant_id, event_id, policy_id, policy_version, digest_schema,
                 content_digest, installation_ref
               ) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (tenant, event_id, *expected),
        )
    cursor.execute(
        """SELECT policy_id, policy_version, digest_schema,
                  content_digest, installation_ref
           FROM evaluation_alert_policy_provenance
           WHERE tenant_id = %s AND event_id = %s""",
        (tenant, event_id),
    )
    saved = cursor.fetchone()
    if saved is None or (
        saved["policy_id"], saved["policy_version"], saved["digest_schema"],
        saved["content_digest"], saved["installation_ref"],
    ) != expected:
        # In particular, pre-migration non-alerting events have no source
        # provenance. Never fabricate it from their old policy_version.
        raise ValueError("conflicting evaluation replay: alert policy provenance changed")


def _verify_canonical_replay(
    cursor: Cursor,
    record: ShadowEvaluationRecord,
    audit: DecisionAuditRecord,
    *,
    alerts: PostgresEvaluationAlertWriter,
    inserted: bool,
) -> None:
    """Lock canonical evidence and refuse incompatible tenant/event retries.

    The INSERT .. ON CONFLICT wait and subsequent FOR UPDATE reads occur in
    one READ COMMITTED transaction; the loser sees the committed winner.
    No alert/case/audit success is written on an incompatible retry.
    """
    tenant, event_id = record.event.tenant_id, record.event.event_id
    cursor.execute(
        """SELECT decision_json, signal_policy_versions_json, evidence_json
           FROM fraud_decision_audit
           WHERE tenant_id = %s AND event_id = %s FOR UPDATE""",
        (tenant, str(event_id)),
    )
    saved_audit = cursor.fetchone()
    cursor.execute(
        """SELECT record_json FROM shadow_evaluations
           WHERE tenant_id = %s AND event_id = %s FOR UPDATE""",
        (tenant, str(event_id)),
    )
    saved_evaluation = cursor.fetchone()
    if saved_audit is None or saved_evaluation is None:
        raise ValueError("conflicting evaluation replay: incomplete canonical evidence")

    from gasha.cases.evaluation_alerts import (
        alert_evidence,
        alert_group_ref,
        persisted_evaluation_context_matches,
    )
    from gasha.domain.models import FraudDecision

    canonical = ShadowEvaluationRecord.model_validate_json(str(saved_evaluation["record_json"]))
    canonical_decision = FraudDecision.model_validate_json(str(saved_audit["decision_json"]))
    current_decision = audit.decision.model_dump(mode="json")
    current_decision.pop("decided_at", None)
    original_decision = canonical_decision.model_dump(mode="json")
    original_decision.pop("decided_at", None)

    if (
        canonical.evaluation.decision != canonical_decision
        or _immutable_replay_identity(canonical) != _immutable_replay_identity(record)
        or original_decision != current_decision
        or json.loads(str(saved_audit["signal_policy_versions_json"]))
            != list(audit.signal_policy_versions)
        or json.loads(str(saved_audit["evidence_json"]))
            != [item.model_dump(mode="json") for item in audit.evidence]
    ):
        raise ValueError("conflicting evaluation replay: immutable identity changed")

    # Alert policy is a separate versioned input not carried in the shadow
    # evaluation JSON. A duplicate cannot silently switch mapping/threshold
    # or inherit an earlier alert generated by a different installed policy.
    if not inserted:
        cursor.execute(
            """SELECT policy_version, decision_action, risk_score, priority_seed,
                      scenario_ids, group_ref, context_ref
               FROM evaluation_alerts
               WHERE tenant_id = %s AND event_id = %s FOR UPDATE""",
            (tenant, str(event_id)),
        )
        saved_alert = cursor.fetchone()
        qualified = alert_evidence(alerts.tenant_id, canonical, alerts.policy)
        if saved_alert is None:
            if qualified is not None:
                raise ValueError("conflicting evaluation replay: expected alert is absent")
        elif (
            qualified is None
            or saved_alert["policy_version"] != alerts.policy.version
            or saved_alert["decision_action"] != canonical_decision.action.value
            or saved_alert["risk_score"] != canonical_decision.risk_score
            or saved_alert["priority_seed"] != qualified[0]
            or saved_alert["scenario_ids"] != list(qualified[1])
            or saved_alert["group_ref"] != alert_group_ref(canonical, alerts.policy.version)
            or not persisted_evaluation_context_matches(
                canonical,
                raw_record_json=str(saved_evaluation["record_json"]),
                stored_context_ref=cast(str, saved_alert["context_ref"]),
            )
        ):
            raise ValueError("conflicting evaluation replay: alert policy/evidence changed")


class PostgresEvaluationPersistence:
    """Atomic persistence boundary for one evaluation's two artifacts.

    The decision audit (``fraud_decision_audit``) and the shadow
    evaluation record (``shadow_evaluations``) are written in a single
    transaction: either both commit or neither does, so a retry after a
    mid-save failure can never observe half-persisted evidence. Both
    inserts are first-write-wins on ``(tenant_id, event_id)``, keeping
    the originally persisted pair intact on replay.
    """

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None,
        require_lease: bool = False,
        alerts: PostgresEvaluationAlertWriter | None = None,
    ) -> None:
        self._alerts = alerts
        self._require_lease = require_lease
        self._tenant_ids = tenant_ids
        self._connection = connection

    def save(
        self,
        record: ShadowEvaluationRecord,
        audit: DecisionAuditRecord,
    ) -> ShadowEvaluationRecord:
        decision = audit.decision
        require_tenant(record.event.tenant_id, self._tenant_ids)
        require_tenant(decision.tenant_id, self._tenant_ids)
        if (decision.tenant_id, decision.event_id) != (record.event.tenant_id, record.event.event_id):
            raise ValueError("audit and evaluation identity mismatch")
        if self._alerts is not None and (
            getattr(self._connection, "autocommit", None) is not False
            or decision != record.evaluation.decision
            or record.event.tenant_id != self._alerts.tenant_id
        ):
            raise ValueError("alert persistence requires a matching tenant-bound transaction")
        if self._alerts is not None:
            self._alerts.require_current_principal()
        try:
            with self._connection.cursor() as cursor:
                if self._alerts is not None:
                    cursor.execute("SHOW transaction_isolation", ())
                    if cursor.fetchone() != {"transaction_isolation": "read committed"}:
                        raise ValueError("alert grouping requires read committed isolation")
                lease = current_evaluation_lease.get()
                if self._require_lease:
                    if lease is None or (lease.tenant_id, lease.event_id) != (
                        record.event.tenant_id, record.event.event_id
                    ):
                        raise LeaseLostError("missing or mismatched evaluation claim")
                    cursor.execute(
                        """SELECT lease_token FROM pending_evaluations
                        WHERE tenant_id = %s AND event_id = %s
                          AND lease_token = %s
                        FOR UPDATE""",
                        (lease.tenant_id, str(lease.event_id), lease.token),
                    )
                    if cursor.fetchone() is None:
                        raise LeaseLostError("evaluation claim superseded")
                    # Check database time after acquiring the lock: a lock wait
                    # may itself have outlived the lease window.
                    _require_live_lease(cursor, lease)
                cursor.execute(
                    """
                    INSERT INTO fraud_decision_audit (
                        tenant_id, event_id, decision_json,
                        signal_policy_versions_json, evidence_json,
                        decided_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, event_id) DO NOTHING
                    """,
                    (
                        decision.tenant_id,
                        str(decision.event_id),
                        decision.model_dump_json(),
                        json.dumps(audit.signal_policy_versions),
                        json.dumps(
                            [
                                item.model_dump(mode="json")
                                for item in audit.evidence
                            ]
                        ),
                        decision.decided_at,
                    ),
                )
                audit_inserted = cursor.rowcount == 1
                cursor.execute(
                    """
                    INSERT INTO shadow_evaluations (
                        tenant_id, event_id, record_json, persisted_at
                    )
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (tenant_id, event_id) DO NOTHING
                    """,
                    (
                        record.event.tenant_id,
                        str(record.event.event_id),
                        record.model_dump_json(),
                        record.persisted_at,
                    ),
                )
                inserted = cursor.rowcount == 1
            if self._alerts is not None:
                if inserted != audit_inserted:
                    raise ValueError("alert persistence found incomplete decision evidence")
                with self._connection.cursor() as cursor:
                    _verify_alert_policy_provenance(
                        cursor, record, alerts=self._alerts, inserted=inserted,
                    )
                    _verify_canonical_replay(
                        cursor, record, audit, alerts=self._alerts, inserted=inserted,
                    )
                # Key-lock waits must not allow an expired credential to
                # retrieve the previously persisted decision on replay.
                self._alerts.require_current_principal()
            if self._alerts is not None and inserted:
                self._alerts.append(self._connection, record)
                if self._require_lease and lease is not None:
                    with self._connection.cursor() as cursor:
                        _require_live_lease(cursor, lease)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

        persisted = PostgresShadowEvaluationRepository(
            self._connection
        ).get(record.event.tenant_id, record.event.event_id)
        if persisted is None:
            raise RuntimeError(
                "atomic evaluation save completed without a record"
            )
        return persisted

