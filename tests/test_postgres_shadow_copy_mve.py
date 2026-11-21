"""#146/#148/#45: synthetic copy -> internal feature -> durable shadow analyst MVE.

This is an opt-in PostgreSQL integration test, not an installed bank feed,
NetGuardians interface, authenticated source issuer, or bank failover test.
No payment action is dispatched; the synthetic incumbent is never modified.
"""
from __future__ import annotations

from datetime import timedelta
from json import dumps, loads
from uuid import uuid4

import pytest
import test_postgres_evaluation_alerts as alerts
import test_postgres_synthetic_fraud_workflow as workflow
from fastapi.testclient import TestClient
from test_kafka_ingestion import FakeRecord, make_consumer
from test_postgres_case_writer_bridge import (
    ASSIGNEE,
    CAPABILITIES,
    AssigneeDirectory,
    IngressAudit,
    principal,
)
from test_postgres_evaluations import POLICY, envelope, inbound_for

from gasha.api.main import app
from gasha.cases.evaluation_alerts import (
    PostgresEvaluationAlertWriter,
    evaluation_context_ref,
)
from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader
from gasha.cases.postgres_writer_bridge import ExplicitPostgresCaseTransitionWriter
from gasha.cases.synthetic_ranking import SyntheticPostgresRankingSource
from gasha.cases.timeline import VerifiedEvaluation
from gasha.domain.models import DecisionAction, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.service import IngestionOutcome, IngestionService
from gasha.ingestion.shadow_copy import SHADOW_COPY_SCHEMA, SyntheticShadowCopyAdapter
from gasha.ingestion.worker import IngestionWorker
from gasha.intelligence.feature_assessment_v1 import assess_synthetic_shadow_features
from gasha.intelligence.feature_set_v1 import ObservedTransfer
from gasha.intelligence.internal_graph import InternalGraphPolicy
from gasha.orchestration import ShadowOrchestrator
from gasha.postgres_evaluations import (
    PostgresEvaluationPersistence,
    PostgresShadowEvaluationRepository,
)
from gasha.security.access import Capability, CredentialRejected

schema = alerts.schema
installation = workflow.installation
TENANT = "tenant-a"


def _synthetic_copy(tenant: str = TENANT) -> InboundBankEvent:
    original = envelope(tenant)
    fields = dict(inbound_for(original).payload)
    fields["device_id"] = "synthetic-device"
    return InboundBankEvent(
        tenant_id=tenant,
        source_system="synthetic-shadow-copy",
        schema_version=SHADOW_COPY_SCHEMA,
        payload=fields,
        # This is only a synthetic receipt-time input, NOT a Bank-trusted clock.
        received_at=original.canonical_transaction.occurred_at + timedelta(seconds=1),
    )


def _computed_graph_event(copy: InboundBankEvent):
    ingestion = IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()})
    receipt = ingestion.ingest(copy)
    assert receipt.outcome is IngestionOutcome.ACCEPTED
    assert ingestion.ingest(copy).outcome is IngestionOutcome.DUPLICATE
    assert receipt.envelope is not None
    return _computed_graph_from_normalized(receipt.envelope)


def _computed_graph_assessment(normalized: FraudEventEnvelope):
    assert normalized.operating_mode is OperatingMode.SHADOW
    assert normalized.intelligence.transaction_risk == 0.0
    occurred = normalized.canonical_transaction.occurred_at
    receipt_as_of = normalized.received_at
    assert receipt_as_of is not None and occurred <= receipt_as_of
    tx = normalized.canonical_transaction
    history = tuple(
        ObservedTransfer(
            normalized.tenant_id, f"prior-{n}", f"prior-account-{n}",
            tx.beneficiary_id, None,
            occurred - timedelta(minutes=n), occurred - timedelta(minutes=n),
        ) for n in range(1, 6)
    )
    late_observation = ObservedTransfer(
        normalized.tenant_id, "late-after-receipt", "late-sender",
        tx.beneficiary_id, None, occurred - timedelta(minutes=10),
        receipt_as_of + timedelta(seconds=1),
    )
    # The production-shaped assessment contract replaces the test's prior
    # direct model_copy risk injection. The *persisted* feature lineage still
    # requires a separate reviewed atomic storage/projection change under #145.
    assessment = assess_synthetic_shadow_features(
        normalized, history + (late_observation,),
        policy=InternalGraphPolicy(policy_version="synthetic-graph-v1"),
    )
    assert assessment.feature_set.beneficiary_unique_senders_1h == 5
    assert assessment.late_observations == 1
    assert assessment.decision_as_of == receipt_as_of
    assert len(assessment.computation_fingerprint) == 64
    return assessment


def _computed_graph_from_normalized(normalized: FraudEventEnvelope) -> FraudEventEnvelope:
    return _computed_graph_assessment(normalized).assessed_envelope


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_copy_to_durable_deduped_alert_authenticated_case_and_feedback(
    installation, monkeypatch,
) -> None:
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    first = _computed_graph_event(_synthetic_copy())
    second = _computed_graph_event(_synthetic_copy())
    for item in (first, second):
        result = alerts.evaluate(
            installation, item,
            writer=PostgresEvaluationAlertWriter(
                TENANT, workflow.ALERT_POLICY,
                principal(caps=frozenset({Capability.CASE_CREATE})),
            ),
        )
        assert result.decision.action is DecisionAction.HOLD
        assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
        assert workflow.FAN_IN in result.decision.reason_codes

    with workflow.connect(installation) as db:
        rows = db.execute(
            "SELECT tenant_id, event_id, case_id, context_ref FROM evaluation_alerts"
        ).fetchall()
        assert len(rows) == 2
        assert len({row["case_id"] for row in rows}) == 1
        assert len({row["context_ref"] for row in rows}) == 2
        assert db.execute("SELECT count(*) AS n FROM shadow_evaluations").fetchone()["n"] == 2
        assert db.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events WHERE action='alert.generate'"
        ).fetchone()["n"] == 2

    capabilities = CAPABILITIES | {Capability.CASE_READ}

    class Identity:
        def verify(self, bearer):
            if bearer == "analyst":
                return principal(caps=capabilities)
            if bearer == "other-tenant":
                return principal(tenant="tenant-b", caps=capabilities)
            raise CredentialRejected("synthetic identity rejected")

    class Evaluations:
        def resolve(self, *, principal, tenant_id, event_id, at):
            assert tenant_id in principal.tenant_ids
            with workflow.connect(installation) as db:
                record = PostgresShadowEvaluationRepository(
                    db, tenant_ids=(tenant_id,),
                ).get(tenant_id, event_id)
            assert record is not None and record.persisted_at <= at
            return VerifiedEvaluation(tenant_id, event_id, evaluation_context_ref(record))

    def connections():
        return workflow.connect(installation)

    monkeypatch.setattr(app.state, "identity_verifier", Identity())
    monkeypatch.setattr(app.state, "security_audit", IngressAudit())
    monkeypatch.setattr(app.state, "case_queue_reader", ExplicitPostgresCaseQueueReader(
        connections=connections,
        ranking=SyntheticPostgresRankingSource(
            connections=connections, tenant_id=TENANT,
            alert_policies=(workflow.ALERT_POLICY,),
        ),
    ))
    monkeypatch.setattr(app.state, "case_history_reader", ExplicitPostgresCaseHistoryReader(
        connections=connections,
    ))
    monkeypatch.setattr(app.state, "case_transition_writer", ExplicitPostgresCaseTransitionWriter(
        connections=connections, evaluations=Evaluations(),
        assignees=AssigneeDirectory(),
    ))

    base = f"/v1/tenants/{TENANT}/cases"
    auth = {"Authorization": "Bearer analyst"}
    foreign = {"Authorization": "Bearer other-tenant"}
    with TestClient(app) as http:
        assert http.get(f"{base}/queue").status_code == 401
        assert http.get(f"{base}/queue", headers=foreign).status_code == 404
        queued = http.get(f"{base}/queue", headers=auth)
        assert queued.status_code == 200, queued.text
        [item] = queued.json()["items"]
        assert item["scenario_ids"] == ["MM-02"]
        case = f"{base}/{item['case_id']}"
        assert http.get(f"{case}/history", headers=foreign).status_code == 404
        first_history = http.get(f"{case}/history", headers=auth)
        assert first_history.status_code == 200, first_history.text
        assert [e["operation"] for e in first_history.json()["events"]] == ["create"]
        assert first_history.json()["events"][0]["source_context_ref"] in {
            row["context_ref"] for row in rows
        }

        operations = (
            ("triage", "analyst_triage", {}),
            ("assign", "investigation_assigned", {"assignee_selector": str(ASSIGNEE)}),
            ("dispose", "legitimate_evidence", {"disposition": "confirmed_legitimate"}),
            ("correct", "corrected_finding", {"disposition": "confirmed_fraud"}),
            ("reconcile", "feedback_reconciled", {}),
        )
        for revision, (operation, reason, fields) in enumerate(operations, start=1):
            payload = {
                "source_event_id": item["source_event_id"],
                "expected_revision": revision,
                "idempotency_key": uuid4().hex,
                "reason_code": reason,
                **fields,
            }
            url = f"{case}/transitions/{operation}"
            if revision == 1:
                assert http.post(url, headers=foreign, json=payload).status_code == 404
            reply = http.post(url, headers=auth, json=payload)
            assert reply.status_code == 200, reply.text
            assert reply.json()["revision"] == revision + 1
            assert reply.json()["bank_execution"] == "unknown"
            assert reply.json()["enforcement_activated"] is False
            assert http.post(url, headers=auth, json=payload).json() == reply.json()
        final = http.get(f"{case}/history", headers=auth)
        assert final.status_code == 200
        assert [e["operation"] for e in final.json()["events"]] == [
            "create", "triage", "assign", "dispose", "correct", "reconcile",
        ]
        assert http.get(f"{base}/queue", headers=auth).json()["items"] == []

    with workflow.connect(installation) as db:
        assert db.execute("SELECT count(*) AS n FROM analyst_case_events").fetchone()["n"] == 6



@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_json_wire_worker_to_durable_shadow_alert_case_with_replay_and_scope(
    installation,
) -> None:
    """A complete synthetic wire-to-PostgreSQL path, not a Bank/broker test.

    The copy arrives through JSON/Pydantic, not a direct-object adapter.
    Features are computed within Gasha before the durable alert is committed.
    Neither the wire payload nor the worker selects an enforcing mode.
    """
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    copies = (_synthetic_copy(), _synthetic_copy())
    wire = [dumps(copy.model_dump(mode="json")).encode() for copy in copies]
    consumer, batch, dead_letters = make_consumer([
        FakeRecord(wire[0], 20),
        FakeRecord(wire[1], 21),
        FakeRecord(wire[0], 22),  # at-least-once transport replay
    ])
    ingestion = IngestionService(
        {"synthetic-shadow-copy": SyntheticShadowCopyAdapter()},
        dead_letters=dead_letters,
    )
    evaluated: list[str] = []

    def evaluate_normalized(
        normalized: FraudEventEnvelope, _policy=None,
    ) -> None:
        assert batch.commits == 0  # no ack before durable evaluation
        assessed = _computed_graph_from_normalized(normalized)
        result = alerts.evaluate(
            installation, assessed,
            writer=PostgresEvaluationAlertWriter(
                TENANT, workflow.ALERT_POLICY,
                principal(caps=frozenset({Capability.CASE_CREATE})),
            ),
        )
        assert result.decision.action is DecisionAction.HOLD
        assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
        evaluated.append(str(normalized.event_id))

    worker = IngestionWorker(
        consumer, ingestion, evaluate=evaluate_normalized,
        dead_letters=dead_letters, tenant_ids=(TENANT,),
    )
    assert worker.run_once(max_events=3) == 3
    assert batch.commits == 1
    assert len(set(evaluated)) == 2
    assert dead_letters.records == ()

    with workflow.connect(installation) as db:
        rows = db.execute(
            "SELECT tenant_id, event_id, case_id, context_ref "
            "FROM evaluation_alerts"
        ).fetchall()
        assert len(rows) == 2
        assert {row["tenant_id"] for row in rows} == {TENANT}
        assert len({row["case_id"] for row in rows}) == 1
        assert len({row["context_ref"] for row in rows}) == 2
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 2

    # A worker configured for tenant A never evaluates or acks tenant B,
    # even if an unauthenticated synthetic transport supplies that identifier.
    foreign = dumps(_synthetic_copy("tenant-b").model_dump(mode="json")).encode()
    other_consumer, other_batch, other_dead_letters = make_consumer([
        FakeRecord(foreign, 23),
    ])
    other_worker = IngestionWorker(
        other_consumer, ingestion, evaluate=evaluate_normalized,
        dead_letters=other_dead_letters, tenant_ids=(TENANT,),
    )
    with pytest.raises(PermissionError, match="tenant outside authorized"):
        other_worker.run_once(max_events=1)
    assert other_batch.commits == 0
    assert len(evaluated) == 2
    with workflow.connect(installation) as db:
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 2


def test_synthetic_incumbent_continues_when_separate_gasha_copy_consumer_fails() -> None:
    """Architectural simulation only: no installed bank transport/load timing claim."""
    source = _synthetic_copy()
    bank_accepted: list[str] = []
    incumbent_observed: list[str] = []
    copy_outbox: list[InboundBankEvent] = []

    # This simulated independent primary path intentionally has no Gasha calls.
    # It places a *copy* in a separate inbox after completing bank processing.
    bank_accepted.append(str(source.payload["event_id"]))
    incumbent_observed.append(str(source.payload["event_id"]))
    copy_outbox.append(source)
    original_primary = (tuple(bank_accepted), tuple(incumbent_observed))

    class FailedShadowAdapter:
        adapter_type = "synthetic-failed-shadow"
        adapter_version = "1.0"
        supported_schema_versions = frozenset({SHADOW_COPY_SCHEMA})

        def __init__(self, failure: type[Exception]):
            self.failure = failure

        def adapt(self, event: InboundBankEvent):
            raise self.failure("synthetic Gasha consumer down")

    for failure in (RuntimeError, TimeoutError):
        isolated = IngestionService({
            "synthetic-shadow-copy": FailedShadowAdapter(failure),
        })
        rejected = isolated.ingest(copy_outbox[0])
        assert rejected.outcome is IngestionOutcome.REJECTED
        assert rejected.envelope is None
        # This checks the architecture of the synthetic separate-copy harness,
        # not any physical Bank broker/timeout/HA property.
        assert (tuple(bank_accepted), tuple(incumbent_observed)) == original_primary
        assert len(copy_outbox) == 1

    # Recovery replays the exact immutable copy through the actual adapter;
    # Bank/NetGuardians receive no callback, hold or status update.
    ingestion = IngestionService({"synthetic-shadow-copy": SyntheticShadowCopyAdapter()})
    assert ingestion.ingest(copy_outbox[0]).outcome is IngestionOutcome.ACCEPTED
    assert ingestion.ingest(copy_outbox[0]).outcome is IngestionOutcome.DUPLICATE
    assert (tuple(bank_accepted), tuple(incumbent_observed)) == original_primary


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_synthetic_copy_audit_failure_cannot_leave_partial_alert_case(installation) -> None:
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    sample = _computed_graph_event(_synthetic_copy())
    with workflow.connect(installation) as db:
        db.execute(
            "ALTER TABLE security_audit_events ADD CONSTRAINT shadow_copy_audit_guard "
            "CHECK (action <> 'alert.generate') NOT VALID"
        )
    from psycopg.errors import CheckViolation

    with pytest.raises(CheckViolation):
        alerts.evaluate(
            installation, sample,
            writer=PostgresEvaluationAlertWriter(
                TENANT, workflow.ALERT_POLICY,
                principal(caps=frozenset({Capability.CASE_CREATE})),
            ),
        )
    with workflow.connect(installation) as db:
        for table in (
            "shadow_evaluations", "fraud_decision_audit", "evaluation_alerts",
            "analyst_case_events", "evaluation_alert_policy_provenance",
        ):
            assert db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 0
        db.execute("ALTER TABLE security_audit_events DROP CONSTRAINT shadow_copy_audit_guard")
    result = alerts.evaluate(
        installation, sample,
        writer=PostgresEvaluationAlertWriter(
            TENANT, workflow.ALERT_POLICY,
            principal(caps=frozenset({Capability.CASE_CREATE})),
        ),
    )
    assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
    with workflow.connect(installation) as db:
        assert db.execute("SELECT count(*) AS n FROM evaluation_alerts").fetchone()["n"] == 1


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_receipt_feature_evidence_is_atomic_with_shadow_alert_and_case(installation) -> None:
    """Persist opaque lineage with the same transaction as alert, case and audit.

    Deliberately synthetic-only: existing protected history still exposes its
    immutable source_context_ref, not a new unapproved analyst field.
    """
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    receipt = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    }).ingest(_synthetic_copy())
    assert receipt.envelope is not None
    assessment = _computed_graph_assessment(receipt.envelope)
    writer = PostgresEvaluationAlertWriter(
        TENANT, workflow.ALERT_POLICY,
        principal(caps=frozenset({Capability.CASE_CREATE})),
    )
    with workflow.connect(installation) as db:
        orchestrator = ShadowOrchestrator(
            {TENANT: POLICY},
            persistence=PostgresEvaluationPersistence(db, alerts=writer),
        )
        result = orchestrator.evaluate(
            assessment.assessed_envelope, feature_assessment=assessment,
        )
        assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
        persisted = PostgresShadowEvaluationRepository(
            db, tenant_ids=(TENANT,),
        ).get(TENANT, assessment.event_id)
        assert persisted is not None and persisted.feature_evidence is not None
        evidence = persisted.feature_evidence
        assert evidence.source_fingerprint == assessment.source_fingerprint
        assert evidence.computation_fingerprint == assessment.computation_fingerprint
        assert evidence.late_observations == 1
        assert evidence.canonical_transaction_fingerprint
        assert evidence.lineage_ref
        alert = db.execute(
            "SELECT case_id, context_ref FROM evaluation_alerts "
            "WHERE tenant_id = %s AND event_id = %s",
            (TENANT, assessment.event_id),
        ).fetchone()
        assert alert is not None
        assert alert["context_ref"] == evaluation_context_ref(persisted)
        source = db.execute(
            "SELECT source_context_ref FROM analyst_case_events "
            "WHERE tenant_id = %s AND case_id = %s",
            (TENANT, alert["case_id"]),
        ).fetchone()
        assert source is not None
        assert source["source_context_ref"] == alert["context_ref"]
        # Exact duplicate causes neither a new case nor another audit.
        assert orchestrator.evaluate(
            assessment.assessed_envelope, feature_assessment=assessment,
        ).effective_action is DecisionAction.NO_ACTION_SHADOW
        for table, expected in (
            ("shadow_evaluations", 1), ("fraud_decision_audit", 1),
            ("evaluation_alerts", 1), ("analyst_case_events", 1),
        ):
            assert db.execute(
                f"SELECT count(*) AS n FROM {table}",
            ).fetchone()["n"] == expected
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action = 'alert.generate'",
        ).fetchone()["n"] == 1

    # A mutated stored digest cannot masquerade as a valid feature lineage.
    from gasha.orchestration import ShadowEvaluationRecord
    with workflow.connect(installation) as db:
        original = db.execute(
            "SELECT record_json FROM shadow_evaluations "
            "WHERE tenant_id = %s AND event_id = %s",
            (TENANT, assessment.event_id),
        ).fetchone()["record_json"]
        tampered = dict(original) if isinstance(original, dict) else loads(original)
        tampered["feature_evidence"]["source_fingerprint"] = "0" * 64
        with pytest.raises(ValueError, match="digest mismatch"):
            ShadowEvaluationRecord.model_validate(tampered)


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_feature_evidence_alert_audit_failure_rolls_back_all(installation) -> None:
    """A failed terminal alert audit cannot leave lineage, alert or case."""
    from psycopg.errors import CheckViolation

    alerts.install_policy(installation, workflow.ALERT_POLICY)
    receipt = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    }).ingest(_synthetic_copy())
    assert receipt.envelope is not None
    assessment = _computed_graph_assessment(receipt.envelope)
    writer = PostgresEvaluationAlertWriter(
        TENANT, workflow.ALERT_POLICY,
        principal(caps=frozenset({Capability.CASE_CREATE})),
    )
    with workflow.connect(installation) as db:
        db.execute(
            "ALTER TABLE security_audit_events ADD CONSTRAINT "
            "feature_evidence_audit_guard "
            "CHECK (action <> 'alert.generate') NOT VALID"
        )
    with pytest.raises(CheckViolation), workflow.connect(installation) as db:
        orchestrator = ShadowOrchestrator(
            {TENANT: POLICY},
            persistence=PostgresEvaluationPersistence(db, alerts=writer),
        )
        orchestrator.evaluate(
            assessment.assessed_envelope, feature_assessment=assessment,
        )
    with workflow.connect(installation) as db:
        for table in (
            "shadow_evaluations", "fraud_decision_audit",
            "evaluation_alerts", "analyst_case_events",
            "evaluation_alert_policy_provenance",
        ):
            assert db.execute(
                f"SELECT count(*) AS n FROM {table}",
            ).fetchone()["n"] == 0
        db.execute(
            "ALTER TABLE security_audit_events "
            "DROP CONSTRAINT feature_evidence_audit_guard"
        )
    with workflow.connect(installation) as db:
        result = ShadowOrchestrator(
            {TENANT: POLICY},
            persistence=PostgresEvaluationPersistence(db, alerts=writer),
        ).evaluate(assessment.assessed_envelope, feature_assessment=assessment)
        assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations",
        ).fetchone()["n"] == 1


@pytest.mark.parametrize("outage", [RuntimeError, TimeoutError])
def test_synthetic_incumbent_completes_while_shadow_copy_consumer_is_stalled(
    outage: type[Exception],
) -> None:
    """#47 fixture-level isolation: a blocked Gasha copy cannot hold the primary path.

    This deliberately models independently running Bank and NetGuardians loops.
    It does not represent an installed Bank connector, network timeout guarantee,
    production broker topology or representative latency measurement.
    """
    from threading import Event, Thread

    shadow_entered = Event()
    release_shadow = Event()
    first = _synthetic_copy()
    outcomes: list[IngestionOutcome] = []
    accepted_by_bank: list[str] = []
    observed_by_incumbent: list[str] = []
    copy_outbox: list[InboundBankEvent] = []

    class StalledShadowAdapter:
        adapter_type = "synthetic-stalled-shadow"
        adapter_version = "1.0"
        supported_schema_versions = frozenset({SHADOW_COPY_SCHEMA})

        def adapt(self, event: InboundBankEvent) -> FraudEventEnvelope:
            shadow_entered.set()
            # Safety bound is test-only. The primary synthetic loops do not
            # call this adapter or wait for this event.
            if not release_shadow.wait(timeout=5):
                raise TimeoutError("synthetic shadow fixture deadline exceeded")
            raise outage("synthetic shadow consumer unavailable")

    failed_shadow = IngestionService({
        "synthetic-shadow-copy": StalledShadowAdapter(),
    })

    def consume_shadow() -> None:
        outcomes.append(failed_shadow.ingest(first).outcome)

    consumer = Thread(target=consume_shadow, daemon=True)
    consumer.start()
    try:
        assert shadow_entered.wait(timeout=2)
        assert consumer.is_alive()
        # Simulate three Bank transaction completions and corresponding
        # incumbent observations while Gasha is still stuck processing a copy.
        # No Gasha result/callback/decision participates in this primary path.
        for event in (first, _synthetic_copy(), _synthetic_copy()):
            identifier = str(event.payload["event_id"])
            accepted_by_bank.append(identifier)
            observed_by_incumbent.append(identifier)
            copy_outbox.append(event)
        assert len(set(accepted_by_bank)) == 3
        assert accepted_by_bank == observed_by_incumbent
        assert not outcomes
        assert consumer.is_alive()
    finally:
        release_shadow.set()
        consumer.join(timeout=2)

    assert not consumer.is_alive()
    assert outcomes == [IngestionOutcome.REJECTED]
    assert len(copy_outbox) == 3
    # Recovery consumes the same copies through the real synthetic normalizer.
    # Replays do not retroactively change Bank or incumbent results.
    recovered = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    })
    for event in copy_outbox:
        accepted = recovered.ingest(event)
        assert accepted.outcome is IngestionOutcome.ACCEPTED
        assert accepted.envelope is not None
        assert accepted.envelope.operating_mode is OperatingMode.SHADOW
        assert recovered.ingest(event).outcome is IngestionOutcome.DUPLICATE
    assert accepted_by_bank == observed_by_incumbent
