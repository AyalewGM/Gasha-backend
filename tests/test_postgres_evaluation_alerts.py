"""Synthetic reference ingestion and PostgreSQL alert/case acceptance for #148."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from json import dumps
from time import monotonic, sleep
from uuid import uuid4

import pytest
import test_postgres_case_writer_bridge as bridge
from test_postgres_case_writer_bridge import (
    CAPABILITIES,
    DSN,
    MIGRATIONS,
    connect,
    principal,
)
from test_postgres_evaluations import POLICY, envelope, inbound_for

from gasha.cases.evaluation_alerts import (
    ALERT_POLICY_DIGEST_SCHEMA,
    AlertPolicy,
    PostgresEvaluationAlertWriter,
    alert_policy_content,
    alert_policy_digest,
)
from gasha.cases.metrics import SyntheticAlertClock, summarize_synthetic_case_metrics
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import (
    AuthorizedAssignee,
    CaseCommand,
    CaseDisposition,
    CaseOperation,
    CaseReason,
    VerifiedEvaluation,
)
from gasha.domain.models import DecisionAction, IntelligenceSnapshot
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionService
from gasha.orchestration import ShadowOrchestrator
from gasha.postgres_evaluations import PostgresEvaluationPersistence
from gasha.security.access import AuthorizationRejected, Capability

pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
schema = bridge.schema
ALERT_POLICY = AlertPolicy("synthetic-alerts-v1", 0.7, (("HIGH_DEVICE_SESSION_RISK", "ATO-02"),))


def install_policy(installation, policy: AlertPolicy, tenant: str = "tenant-a") -> None:
    """Synthetic privileged test provisioning; never an application request path."""
    installation_ref = sha256(dumps(
        ["synthetic-test-install", tenant, policy.policy_id, policy.version],
        separators=(",", ":"), sort_keys=True,
    ).encode()).hexdigest()
    with connect(installation) as connection:
        connection.execute(
            """INSERT INTO tenant_alert_policy_installations (
                 tenant_id, policy_id, policy_version, digest_schema, content_digest,
                 content_json, installation_ref, installed_at
               ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
               ON CONFLICT (tenant_id, policy_id, policy_version) DO NOTHING""",
            (
                tenant, policy.policy_id, policy.version, ALERT_POLICY_DIGEST_SCHEMA,
                alert_policy_digest(policy), dumps(alert_policy_content(policy)),
                installation_ref, datetime.now(UTC),
            ),
        )


@pytest.fixture
def installation(schema):
    with connect(schema) as connection:
        for migration in (
            "001_create_fraud_decision_audit.sql",
            "003_create_shadow_evaluations.sql",
            "017_evaluation_alerts.sql",
            "018_alert_policy_provenance.sql",
        ):
            connection.execute((MIGRATIONS / migration).read_text())
    for tenant in ("tenant-a", "tenant-b"):
        install_policy(schema, ALERT_POLICY, tenant)
    return schema


def event(tenant="tenant-a", score=0.91):
    sample = envelope(tenant)
    inbound = inbound_for(sample)
    inbound.payload = {
        **inbound.payload,
        "device_id": "synthetic-device",
        "intelligence": IntelligenceSnapshot(device_session_risk=score).model_dump(),
    }
    normalized = IngestionService({inbound.source_system: ReferenceJsonAdapter()}).ingest(inbound)
    assert normalized.envelope is not None
    return normalized.envelope


def evaluate(installation, sample, *, writer=None, policy=POLICY):
    if writer is None:
        writer = PostgresEvaluationAlertWriter(
            sample.tenant_id, ALERT_POLICY, principal(tenant=sample.tenant_id),
        )
    with connect(installation) as connection:
        persistence = PostgresEvaluationPersistence(connection, alerts=writer)
        return ShadowOrchestrator(
            {sample.tenant_id: policy}, persistence=persistence,
        ).evaluate(sample)


def test_ingestion_alert_case_disposition_feedback_and_kpis(installation):
    sample = event()
    result = evaluate(installation, sample)
    assert result.decision.action is DecisionAction.HOLD
    assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
    assert result.decision.risk_score == 0.91

    with connect(installation) as connection:
        alert = connection.execute("SELECT * FROM evaluation_alerts").fetchone()
        assert alert["scenario_ids"] == ["ATO-02"]
        assert alert["priority_seed"] == 2
        assert alert["risk_score"] == 0.91
        assert alert["policy_version"] == ALERT_POLICY.version
        case_id = alert["case_id"]

        class Source:
            def resolve(self, tenant_id, event_id):
                assert (tenant_id, event_id) == (alert["tenant_id"], alert["event_id"])
                return VerifiedEvaluation(tenant_id, event_id, alert["context_ref"])

        timeline = PostgresCaseTimelineService(connection)
        analyst = replace(
            principal(caps=CAPABILITIES | {Capability.CASE_READ}), subject="synthetic-investigator",
        )
        for revision, (operation, reason, fields) in enumerate((
            (CaseOperation.TRIAGE, CaseReason.ANALYST_TRIAGE, {}),
            (CaseOperation.ASSIGN, CaseReason.INVESTIGATION_ASSIGNED,
             {"assignee": AuthorizedAssignee(sample.tenant_id, analyst.audit_actor)}),
            (CaseOperation.DISPOSE, CaseReason.FRAUD_EVIDENCE,
             {"disposition": CaseDisposition.FRAUD}),
            (CaseOperation.RECONCILE, CaseReason.FEEDBACK_RECONCILED, {}),
        ), start=1):
            timeline.apply(
                CaseCommand(
                    sample.tenant_id, case_id, sample.event_id, operation, revision,
                    uuid4().hex, reason, **fields,
                ),
                principal=analyst, source=Source(), at=datetime.now(UTC),
            )
        now = datetime.now(UTC)
        history = timeline.history(
            principal=analyst, tenant_id=sample.tenant_id, case_id=case_id, at=now,
        )
        assert history[0].source_context_ref == alert["context_ref"]
        assert history[-1].operation is CaseOperation.RECONCILE
        metrics = summarize_synthetic_case_metrics(
            tenant_id=sample.tenant_id, histories=(history,), as_of=now,
            alert_clocks=(SyntheticAlertClock(
                sample.tenant_id, case_id, sample.event_id,
                sample.canonical_transaction.occurred_at, alert["generated_at"],
            ),),
        )
        assert metrics["counts"]["confirmed_fraud"] == metrics["counts"]["reconciled"] == 1
        assert metrics["counts"]["open_investigations"] == 0
        assert metrics["investigation_turnaround"]["count"] == 1
        assert metrics["alert_latency"]["count"] == 1
        assert metrics["enforcement_activated"] is False


def test_concurrent_groups_deduplicate_and_isolate_tenants(installation):
    first, second, foreign = event(), event(), event("tenant-b")
    with ThreadPoolExecutor(max_workers=4) as workers:
        futures = [
            workers.submit(evaluate, installation, item) for item in (first, second, first, foreign)
        ]
        for future in futures:
            future.result(timeout=15)
    with connect(installation) as connection:
        alerts = connection.execute("SELECT * FROM evaluation_alerts").fetchall()
        assert len(alerts) == 3
        assert len({row["case_id"] for row in alerts if row["tenant_id"] == "tenant-a"}) == 1
        assert len({row["case_id"] for row in alerts}) == 2
        assert len({row["context_ref"] for row in alerts}) == 3
        assert connection.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] == 2


@pytest.mark.parametrize("score", [0.1, 0.6])
def test_allow_and_monitor_do_not_open_alerts(installation, score):
    evaluate(installation, event(score=score))
    with connect(installation) as connection:
        assert connection.execute("SELECT * FROM evaluation_alerts").fetchall() == []
        assert connection.execute("SELECT * FROM analyst_case_events").fetchall() == []
        assert len(connection.execute("SELECT * FROM shadow_evaluations").fetchall()) == 1


def test_wrong_service_tenant_cannot_create_or_attach(installation):
    writer = PostgresEvaluationAlertWriter("tenant-a", ALERT_POLICY, principal(tenant="tenant-b"))
    with pytest.raises(AuthorizationRejected):
        evaluate(installation, event(), writer=writer)
    with connect(installation) as connection:
        assert connection.execute("SELECT * FROM shadow_evaluations").fetchall() == []
        assert connection.execute("SELECT * FROM evaluation_alerts").fetchall() == []



@pytest.mark.parametrize("denial", ["wrong_tenant", "missing_capability", "expired"])
def test_exact_retry_cannot_bypass_writer_authorization(installation, denial):
    sample = event()
    evaluate(installation, sample)
    candidate = principal()
    if denial == "wrong_tenant":
        candidate = principal(tenant="tenant-b")
    elif denial == "missing_capability":
        candidate = principal(caps=CAPABILITIES - {Capability.CASE_CREATE})
    elif denial == "expired":
        candidate = replace(candidate, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    writer = PostgresEvaluationAlertWriter("tenant-a", ALERT_POLICY, candidate)
    tables = ("fraud_decision_audit", "shadow_evaluations", "evaluation_alerts",
              "analyst_case_events", "security_audit_events")
    with connect(installation) as connection:
        before = {table: connection.execute(
            f"SELECT count(*) AS n FROM {table}"
        ).fetchone()["n"] for table in tables}
    failure = ValueError if denial == "expired" else AuthorizationRejected
    with pytest.raises(failure):
        evaluate(installation, sample, writer=writer)
    with connect(installation) as connection:
        for table in tables:
            assert connection.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == before[table]


@pytest.mark.parametrize("existing_case", [False, True])
def test_alert_audit_failure_rolls_back_evaluation_alert_and_any_new_case(
    installation, existing_case,
):
    if existing_case:
        evaluate(installation, event())
    with connect(installation) as connection:
        connection.execute(
            "ALTER TABLE security_audit_events ADD CHECK (action <> 'alert.generate') NOT VALID"
        )
    from psycopg.errors import CheckViolation

    sample = event()
    with pytest.raises(CheckViolation):
        evaluate(installation, sample)
    with connect(installation) as connection:
        for table in (
            "shadow_evaluations", "fraud_decision_audit", "evaluation_alerts", "analyst_case_events",
        ):
            assert len(connection.execute(f"SELECT * FROM {table}").fetchall()) == int(existing_case)
        connection.execute(
            "ALTER TABLE security_audit_events DROP CONSTRAINT security_audit_events_action_check"
        )
    evaluate(installation, sample)
    with connect(installation) as connection:
        assert len(connection.execute("SELECT * FROM evaluation_alerts").fetchall()) == 1 + existing_case
        assert len(connection.execute("SELECT * FROM analyst_case_events").fetchall()) == 1


def test_grouping_rejects_transaction_snapshot_isolation(installation):
    from psycopg import IsolationLevel

    sample = event()
    with connect(installation) as connection:
        connection.isolation_level = IsolationLevel.REPEATABLE_READ
        persistence = PostgresEvaluationPersistence(
            connection, alerts=PostgresEvaluationAlertWriter("tenant-a", ALERT_POLICY, principal()),
        )
        with pytest.raises(ValueError, match="read committed"):
            ShadowOrchestrator({"tenant-a": POLICY}, persistence=persistence).evaluate(sample)
        assert connection.execute("SELECT * FROM shadow_evaluations").fetchall() == []


def test_expired_credential_cannot_attach_after_waiting_for_group_lock(installation):
    evaluate(installation, event())
    sample = event()
    with ThreadPoolExecutor(max_workers=1) as workers, connect(installation) as locker:
        row = locker.execute("SELECT group_ref FROM evaluation_alerts").fetchone()
        locker.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (row["group_ref"],))
        expiry = datetime.now(UTC) + timedelta(seconds=1)
        writer = PostgresEvaluationAlertWriter(
            "tenant-a", ALERT_POLICY, replace(principal(), expires_at=expiry),
        )
        future = workers.submit(evaluate, installation, sample, writer=writer)
        try:
            deadline = monotonic() + 3
            while not locker.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted)"
                " AS waiting"
            ).fetchone()["waiting"]:
                if monotonic() > deadline:
                    pytest.fail("alert worker did not wait on the held group lock")
                sleep(0.01)
            sleep(max(0, (expiry - datetime.now(UTC)).total_seconds()) + 0.02)
        finally:
            locker.rollback()
        with pytest.raises(ValueError, match="current service credential"):
            future.result(timeout=4)
    with connect(installation) as connection:
        assert connection.execute("SELECT count(*) AS n FROM evaluation_alerts").fetchone()["n"] == 1
        assert connection.execute("SELECT count(*) AS n FROM shadow_evaluations").fetchone()["n"] == 1


def test_exact_evaluation_retry_returns_original_without_revising_history(installation):
    sample = event(score=0.91)
    original = evaluate(installation, sample)
    # Receipt/normalization timestamps and re-decision clocks may differ;
    # immutable transaction, intelligence, mode and policy cannot.
    sample.received_at = datetime.now(UTC)
    sample.adapter.normalized_at = datetime.now(UTC)
    assert evaluate(installation, sample) == original
    with connect(installation) as connection:
        for table in ("fraud_decision_audit", "shadow_evaluations", "evaluation_alerts",
                      "analyst_case_events"):
            assert connection.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 1
        assert connection.execute("SELECT risk_score FROM evaluation_alerts").fetchone()["risk_score"] == 0.91


@pytest.mark.parametrize("difference", [
    "risk", "reason", "transaction_time", "transaction_reference", "transaction_amount",
    "adapter_version", "intelligence_evidence", "mode", "policy_version",
    "configuration_version", "rule_version", "signal_policy_versions",
    "alert_policy_version", "alert_policy_mapping",
])
def test_conflicting_replay_never_inherits_alert_or_changes_case(installation, difference):
    original = event(score=0.91)
    initial = evaluate(installation, original)
    with connect(installation) as connection:
        before = {
            table: connection.execute(f"SELECT * FROM {table}").fetchall()
            for table in ("fraud_decision_audit", "shadow_evaluations",
                          "evaluation_alerts", "analyst_case_events", "security_audit_events")
        }
    incoming = original.model_copy(deep=True)
    decision_policy = POLICY
    writer = None
    if difference == "risk":
        incoming.intelligence = IntelligenceSnapshot(device_session_risk=0.1)
    elif difference == "reason":
        incoming.evidence_reason_codes = ("CHANGED_REASON",)
    elif difference == "transaction_time":
        incoming.canonical_transaction.occurred_at += timedelta(seconds=1)
    elif difference == "transaction_reference":
        incoming.canonical_transaction.correlation_id = "changed-reference"
    elif difference == "transaction_amount":
        incoming.canonical_transaction.amount += 1
    elif difference == "adapter_version":
        incoming.adapter.adapter_version = "changed-adapter"
    elif difference == "intelligence_evidence":
        incoming.intelligence = IntelligenceSnapshot(device_session_risk=0.87)
    elif difference == "mode":
        from gasha.domain.models import OperatingMode
        incoming.operating_mode = OperatingMode.ENFORCING
    elif difference == "signal_policy_versions":
        incoming.signal_policy_versions = ("different-signal-policy",)
    elif difference in {"policy_version", "configuration_version", "rule_version"}:
        decision_policy = POLICY.model_copy(update={difference: "changed-version"})
    elif difference == "alert_policy_version":
        writer = PostgresEvaluationAlertWriter(
            incoming.tenant_id,
            AlertPolicy("different-alert-policy", 0.7,
                        (("HIGH_DEVICE_SESSION_RISK", "ATO-02"),)),
            principal(tenant=incoming.tenant_id),
        )
    elif difference == "alert_policy_mapping":
        writer = PostgresEvaluationAlertWriter(
            incoming.tenant_id,
            AlertPolicy(ALERT_POLICY.version, 0.7,
                        (("HIGH_DEVICE_SESSION_RISK", "ATO-06"),)),
            principal(tenant=incoming.tenant_id),
        )

    with pytest.raises(ValueError, match="conflicting evaluation replay"):
        evaluate(installation, incoming, writer=writer, policy=decision_policy)
    with connect(installation) as connection:
        for table, rows in before.items():
            assert connection.execute(f"SELECT * FROM {table}").fetchall() == rows
    assert initial.decision.action is DecisionAction.HOLD


def test_concurrent_conflicting_replays_choose_one_canonical_winner(installation):
    original = event(score=0.91)
    incompatible = original.model_copy(deep=True)
    incompatible.intelligence = IntelligenceSnapshot(device_session_risk=0.1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(evaluate, installation, sample)
                   for sample in (original, incompatible)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=15))
            except ValueError as error:
                assert "conflicting evaluation replay" in str(error)
                outcomes.append(error)
    assert sum(not isinstance(result, Exception) for result in outcomes) == 1
    with connect(installation) as connection:
        assert connection.execute("SELECT count(*) AS n FROM shadow_evaluations").fetchone()["n"] == 1
        assert connection.execute("SELECT count(*) AS n FROM fraud_decision_audit").fetchone()["n"] == 1
        assert connection.execute("SELECT count(*) AS n FROM evaluation_alerts").fetchone()["n"] in (0, 1)
        assert connection.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] in (0, 1)



def test_allow_monitor_policy_provenance_is_durable_and_v2_replay_fails(installation):
    for score in (0.1, 0.6):
        sample = event(score=score)
        original = evaluate(installation, sample)
        with connect(installation) as connection:
            provenance = connection.execute(
                """SELECT * FROM evaluation_alert_policy_provenance
                   WHERE tenant_id = %s AND event_id = %s""",
                (sample.tenant_id, sample.event_id),
            ).fetchone()
            assert provenance["policy_id"] == ALERT_POLICY.policy_id
            assert provenance["policy_version"] == ALERT_POLICY.version
            assert provenance["digest_schema"] == ALERT_POLICY_DIGEST_SCHEMA
            assert provenance["content_digest"] == alert_policy_digest(ALERT_POLICY)
            assert connection.execute(
                "SELECT count(*) AS n FROM evaluation_alerts"
            ).fetchone()["n"] == 0
        new_policy = AlertPolicy(
            "synthetic-alerts-v2", 0.95, ALERT_POLICY.scenario_by_reason,
        )
        install_policy(installation, new_policy)
        writer = PostgresEvaluationAlertWriter(
            sample.tenant_id, new_policy, principal(tenant=sample.tenant_id),
        )
        with pytest.raises(ValueError, match="conflicting evaluation replay"):
            evaluate(installation, sample, writer=writer)
        assert evaluate(installation, sample) == original
    with connect(installation) as connection:
        assert connection.execute(
            "SELECT count(*) AS n FROM evaluation_alert_policy_provenance"
        ).fetchone()["n"] == 2


def test_same_version_changed_mapping_denied_without_qualified_alert(installation):
    sample = event(score=0.1)
    evaluate(installation, sample)
    altered = AlertPolicy(
        ALERT_POLICY.version, ALERT_POLICY.minimum_score,
        ALERT_POLICY.scenario_by_reason + (("UNUSED_REASON", "ATO-06"),),
    )
    with pytest.raises(ValueError, match="untrusted alert policy installation"):
        evaluate(
            installation, sample,
            writer=PostgresEvaluationAlertWriter(
                sample.tenant_id, altered, principal(tenant=sample.tenant_id),
            ),
        )
    with connect(installation) as connection:
        assert connection.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 0


def test_changed_unused_policy_content_cannot_inherit_existing_alert(installation):
    sample = event()
    evaluate(installation, sample)
    altered = AlertPolicy(
        ALERT_POLICY.version, ALERT_POLICY.minimum_score,
        ALERT_POLICY.scenario_by_reason + (("UNUSED_REASON", "APP-01"),),
    )
    with pytest.raises(ValueError, match="untrusted alert policy installation"):
        evaluate(
            installation, sample,
            writer=PostgresEvaluationAlertWriter(
                sample.tenant_id, altered, principal(tenant=sample.tenant_id),
            ),
        )
    with connect(installation) as connection:
        assert connection.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 1


@pytest.mark.parametrize("tamper", ["missing", "null", "unknown_schema", "wrong_digest"])
def test_legacy_or_corrupt_provenance_replay_fails_closed(installation, tamper):
    sample = event(score=0.1)
    evaluate(installation, sample)
    with connect(installation) as connection:
        # Only the isolated test schema allows disabling the immutability
        # trigger to simulate corrupted or pre-migration rows.
        connection.execute(
            "ALTER TABLE evaluation_alert_policy_provenance DISABLE TRIGGER USER"
        )
        if tamper == "missing":
            connection.execute("DELETE FROM evaluation_alert_policy_provenance")
        elif tamper == "null":
            connection.execute(
                "ALTER TABLE evaluation_alert_policy_provenance "
                "ALTER COLUMN content_digest DROP NOT NULL"
            )
            connection.execute(
                "UPDATE evaluation_alert_policy_provenance SET content_digest = NULL"
            )
        elif tamper == "unknown_schema":
            connection.execute(
                "UPDATE evaluation_alert_policy_provenance "
                "SET digest_schema = 'obsolete-alert-digest-v0'"
            )
        else:
            connection.execute(
                "UPDATE evaluation_alert_policy_provenance "
                "SET content_digest = %s", ("0" * 64,),
            )
        connection.execute(
            "ALTER TABLE evaluation_alert_policy_provenance ENABLE TRIGGER USER"
        )
    with pytest.raises(ValueError, match="alert policy provenance changed"):
        evaluate(installation, sample)
    with connect(installation) as connection:
        assert connection.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 0
        assert connection.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 1


def test_same_event_id_in_distinct_tenants_has_distinct_provenance(installation):
    first = event()
    second = event(tenant="tenant-b")
    second.event_id = first.event_id
    second.canonical_transaction.event_id = first.event_id
    evaluate(installation, first)
    evaluate(installation, second)
    with connect(installation) as connection:
        provenance = connection.execute(
            "SELECT tenant_id, installation_ref FROM evaluation_alert_policy_provenance "
            "WHERE event_id = %s ORDER BY tenant_id", (first.event_id,),
        ).fetchall()
        assert len(provenance) == 2
        assert [row["tenant_id"] for row in provenance] == ["tenant-a", "tenant-b"]
        assert provenance[0]["installation_ref"] != provenance[1]["installation_ref"]


def test_concurrent_two_installed_alert_policies_choose_one_winner(installation):
    original = event(score=0.1)
    alternative = AlertPolicy(
        "synthetic-alerts-v2", 0.9, ALERT_POLICY.scenario_by_reason,
    )
    install_policy(installation, alternative)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(evaluate, installation, original),
            pool.submit(
                evaluate, installation, original,
                writer=PostgresEvaluationAlertWriter(
                    original.tenant_id, alternative, principal(),
                ),
            ),
        ]
        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=15))
            except ValueError as exc:
                assert "conflicting evaluation replay" in str(exc)
                results.append(exc)
    assert sum(not isinstance(item, Exception) for item in results) == 1
    with connect(installation) as connection:
        assert connection.execute(
            "SELECT count(*) AS n FROM evaluation_alert_policy_provenance"
        ).fetchone()["n"] == 1
        assert connection.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 1


def test_concurrent_exact_retry_and_changed_installed_policy_never_mutate_original(
    installation,
):
    sample = event(score=0.6)
    original = evaluate(installation, sample)
    alternative = AlertPolicy(
        "synthetic-alerts-v2", 0.9, ALERT_POLICY.scenario_by_reason,
    )
    install_policy(installation, alternative)
    writer = PostgresEvaluationAlertWriter(
        sample.tenant_id, alternative, principal(tenant=sample.tenant_id),
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        exact = pool.submit(evaluate, installation, sample)
        altered = pool.submit(evaluate, installation, sample, writer=writer)
        assert exact.result(timeout=15) == original
        with pytest.raises(ValueError, match="conflicting evaluation replay"):
            altered.result(timeout=15)
    with connect(installation) as connection:
        assert connection.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 1
        assert connection.execute(
            "SELECT count(*) AS n FROM evaluation_alert_policy_provenance"
        ).fetchone()["n"] == 1
        assert connection.execute(
            "SELECT count(*) AS n FROM security_audit_events"
        ).fetchone()["n"] == 0


def test_installed_policy_separate_runtime_login_denied_mutations(installation):
    """#148 synthetic DB role negative: installations need a distinct owner.

    The PostgreSQL service user in this fixture provisions the role and grants.
    This does NOT certify a Bank deployment, Bank identity, or tenant-level RLS.
    """
    import psycopg
    from psycopg import sql

    name = "gasha_alert_runtime_" + uuid4().hex[:14]
    password = uuid4().hex + uuid4().hex
    ident = sql.Identifier(name)
    namespace = sql.Identifier(installation)
    installed_table = sql.SQL("{}.tenant_alert_policy_installations").format(namespace)
    provenance_table = sql.SQL("{}.evaluation_alert_policy_provenance").format(namespace)
    with psycopg.connect(DSN, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT"
            ).format(ident, sql.Literal(password))
        )
        try:
            owner.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(namespace, ident)
            )
            owner.execute(
                sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(installed_table, ident)
            )
            owner.execute(
                sql.SQL("GRANT SELECT, INSERT ON TABLE {} TO {}").format(
                    provenance_table, ident,
                )
            )
            # Connect as a distinct LOGIN. SET ROLE from the superuser is
            # insufficient to exercise privilege-escalation denial.
            with psycopg.connect(
                DSN, user=name, password=password, autocommit=True,
            ) as runtime:
                runtime.execute(
                    sql.SQL("SET search_path TO {}").format(namespace)
                )
                assert runtime.execute("SELECT current_user").fetchone()[0] == name
                assert runtime.execute(
                    "SELECT count(*) FROM tenant_alert_policy_installations "
                    "WHERE tenant_id = 'tenant-a'"
                ).fetchone()[0] == 1
                assert runtime.execute(
                    "SELECT has_table_privilege(current_user, "
                    "'evaluation_alert_policy_provenance', 'INSERT')"
                ).fetchone()[0] is True
                forbidden = (
                    ("INSERT INTO tenant_alert_policy_installations (tenant_id) "
                     "VALUES ('tenant-a')"),
                    "UPDATE tenant_alert_policy_installations SET policy_version = 'forged'",
                    "DELETE FROM tenant_alert_policy_installations",
                    "TRUNCATE tenant_alert_policy_installations",
                    ("UPDATE evaluation_alert_policy_provenance "
                     "SET policy_version = 'forged'"),
                    "DELETE FROM evaluation_alert_policy_provenance",
                    ("ALTER TABLE tenant_alert_policy_installations "
                     "DISABLE TRIGGER tenant_alert_policy_installations_immutable"),
                    ("CREATE OR REPLACE FUNCTION reject_alert_policy_provenance_mutation() "
                     "RETURNS trigger LANGUAGE plpgsql AS $ "
                     "BEGIN RETURN NULL; END; $"),
                )
                for statement in forbidden:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        runtime.execute(statement)
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    runtime.execute("SET ROLE gasha_test")
            assert owner.execute(
                sql.SQL("SELECT count(*) FROM {} WHERE tenant_id = 'tenant-a'").format(
                    installed_table,
                )
            ).fetchone()[0] == 1
            assert owner.execute(
                sql.SQL(
                    "SELECT tgenabled FROM pg_trigger "
                    "WHERE tgrelid = {}::regclass AND "
                    "tgname = 'tenant_alert_policy_installations_immutable'"
                ).format(sql.Literal(f"{installation}.tenant_alert_policy_installations"))
            ).fetchone()[0] == "O"
        finally:
            owner.execute(
                sql.SQL("REVOKE ALL ON TABLE {} FROM {}").format(
                    provenance_table, ident,
                )
            )
            owner.execute(
                sql.SQL("REVOKE ALL ON TABLE {} FROM {}").format(
                    installed_table, ident,
                )
            )
            owner.execute(
                sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(
                    namespace, ident,
                )
            )
            owner.execute(sql.SQL("DROP ROLE {}").format(ident))
