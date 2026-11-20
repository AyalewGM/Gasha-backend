"""#146/#148/#45: synthetic copy -> internal feature -> durable shadow analyst MVE.

This is an opt-in PostgreSQL integration test, not an installed bank feed,
NetGuardians interface, authenticated source issuer, or bank failover test.
No payment action is dispatched; the synthetic incumbent is never modified.
"""
from __future__ import annotations

from datetime import timedelta
from json import dumps
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
from test_postgres_evaluations import envelope, inbound_for

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
from gasha.intelligence.feature_set_v1 import ObservedTransfer, compute_feature_set
from gasha.intelligence.internal_graph import (
    InternalGraphDetector,
    InternalGraphPolicy,
    InternalGraphSignals,
)
from gasha.intelligence.provenance import IntelligenceScope, IntelligenceSource, SignalProvenance
from gasha.postgres_evaluations import PostgresShadowEvaluationRepository
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


def _computed_graph_from_normalized(normalized: FraudEventEnvelope) -> FraudEventEnvelope:
    assert normalized.operating_mode is OperatingMode.SHADOW
    assert normalized.intelligence.transaction_risk == 0.0
    occurred = normalized.canonical_transaction.occurred_at
    receipt_as_of = normalized.received_at
    assert occurred <= receipt_as_of
    tx = normalized.canonical_transaction
    target = ObservedTransfer(
        normalized.tenant_id, str(tx.event_id), tx.sender_account_id,
        tx.beneficiary_id, tx.device_id, occurred, receipt_as_of,
    )
    history = tuple(
        ObservedTransfer(
            normalized.tenant_id, f"prior-{n}", f"prior-account-{n}",
            tx.beneficiary_id, None,
            occurred - timedelta(minutes=n), occurred - timedelta(minutes=n),
        ) for n in range(1, 6)
    )
    # A past transaction observed after the receipt cutoff cannot contribute.
    late_observation = ObservedTransfer(
        normalized.tenant_id, "late-after-receipt", "late-sender",
        tx.beneficiary_id, None, occurred - timedelta(minutes=10),
        receipt_as_of + timedelta(seconds=1),
    )
    features = compute_feature_set(
        target, history + (late_observation,), decision_as_of=receipt_as_of,
    )
    assert features.decision_as_of == receipt_as_of
    assert features.beneficiary_unique_senders_1h == 5
    # Risk is derived on the Gasha side from synthetic observed history;
    # the inbound copy never supplies it or chooses the decision policy.
    assessed = InternalGraphDetector(
        InternalGraphPolicy(policy_version="synthetic-graph-v1")
    ).assess(InternalGraphSignals(
        unique_senders_to_beneficiary_1h=features.beneficiary_unique_senders_1h,
        provenance=SignalProvenance(
            source=IntelligenceSource.TENANT_NETWORK,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=occurred,
            source_version=features.version,
        ),
    ))
    return normalized.model_copy(update={
        "intelligence": assessed.intelligence,
        "evidence_reason_codes": assessed.reason_codes,
        "signal_policy_versions": (assessed.signal_policy_version,),
    })


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
