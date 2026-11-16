"""Issue #45 synthetic integration across computed graph inputs and protected case HTTP."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import test_postgres_evaluation_alerts as alert_tests
from fastapi.testclient import TestClient
from test_postgres_case_writer_bridge import (
    ASSIGNEE,
    CAPABILITIES,
    DSN,
    AssigneeDirectory,
    IngressAudit,
    connect,
    principal,
)
from test_postgres_evaluations import envelope, inbound_for

from gasha.api.main import app
from gasha.cases.evaluation_alerts import (
    AlertPolicy,
    PostgresEvaluationAlertWriter,
    evaluation_context_ref,
)
from gasha.cases.metrics import SyntheticAlertClock, summarize_synthetic_case_metrics
from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader
from gasha.cases.postgres_writer_bridge import ExplicitPostgresCaseTransitionWriter
from gasha.cases.synthetic_ranking import SyntheticPostgresRankingSource
from gasha.cases.timeline import VerifiedEvaluation
from gasha.domain.models import DecisionAction
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionService
from gasha.intelligence.feature_set_v1 import ObservedTransfer, compute_feature_set
from gasha.intelligence.internal_graph import (
    InternalGraphDetector,
    InternalGraphPolicy,
    InternalGraphSignals,
)
from gasha.intelligence.provenance import IntelligenceScope, IntelligenceSource, SignalProvenance
from gasha.postgres_evaluations import PostgresShadowEvaluationRepository
from gasha.security.access import Capability, CredentialRejected

pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
schema = alert_tests.schema
installation = alert_tests.installation
TENANT = "tenant-a"
FAN_IN = "INTERNAL_GRAPH_BENEFICIARY_FAN_IN"
ALERT_POLICY = AlertPolicy("synthetic-graph-alerts-v1", 0.7, ((FAN_IN, "MM-02"),))


def computed_fan_in():
    transaction = envelope()
    occurred = transaction.canonical_transaction.occurred_at
    target = ObservedTransfer(
        TENANT, str(transaction.event_id), "target-account", "shared-beneficiary", "target-device",
        occurred, occurred,
    )
    prior = tuple(ObservedTransfer(
        TENANT, f"prior-{index}", f"prior-account-{index}", "shared-beneficiary", None,
        occurred - timedelta(minutes=index), occurred - timedelta(minutes=index),
    ) for index in range(1, 6))
    features = compute_feature_set(target, prior, decision_as_of=occurred)
    assert features.beneficiary_unique_senders_1h == 5
    graph = InternalGraphDetector(InternalGraphPolicy(policy_version="synthetic-graph-v1")).assess(
        InternalGraphSignals(
            unique_senders_to_beneficiary_1h=features.beneficiary_unique_senders_1h,
            provenance=SignalProvenance(
                source=IntelligenceSource.TENANT_NETWORK, scope=IntelligenceScope.TENANT_OBSERVED,
                observed_at=occurred, source_version=features.version,
            ),
        ),
    )
    inbound = inbound_for(transaction)
    inbound.payload = {
        **inbound.payload,
        "beneficiary_id": target.beneficiary_ref,
        "sender_account_id": target.account_ref,
        "device_id": target.device_ref,
        "intelligence": graph.intelligence.model_dump(),
        "evidence_reason_codes": graph.reason_codes,
        "signal_policy_versions": (graph.signal_policy_version,),
    }
    result = IngestionService({inbound.source_system: ReferenceJsonAdapter()}).ingest(inbound)
    assert result.envelope is not None
    return result.envelope


def test_computed_graph_detection_to_authenticated_investigation_and_kpis(
    installation, monkeypatch,
):
    sample = computed_fan_in()
    decision = alert_tests.evaluate(
        installation, sample, writer=PostgresEvaluationAlertWriter(
            TENANT, ALERT_POLICY, principal(caps=frozenset({Capability.CASE_CREATE})),
        ),
    )
    assert decision.decision.action is DecisionAction.HOLD
    assert decision.decision.risk_score == 0.86
    assert FAN_IN in decision.decision.reason_codes
    assert decision.effective_action is DecisionAction.NO_ACTION_SHADOW

    def connections():
        return connect(installation)

    analyst_capabilities = (CAPABILITIES - {Capability.CASE_CREATE}) | {Capability.CASE_READ}

    class LabIdentity:
        def verify(self, bearer):
            if bearer == "synthetic-investigator":
                return principal(caps=analyst_capabilities)
            if bearer == "synthetic-other-tenant":
                return principal(tenant="tenant-b", caps=analyst_capabilities)
            raise CredentialRejected("synthetic session rejected")

    class LabEvaluationDirectory:
        def resolve(self, *, principal, tenant_id, event_id, at):
            assert tenant_id == TENANT and tenant_id in principal.tenant_ids
            with connections() as connection:
                record = PostgresShadowEvaluationRepository(
                    connection, tenant_ids=(TENANT,),
                ).get(tenant_id, event_id)
            assert record is not None and record.persisted_at <= at
            return VerifiedEvaluation(tenant_id, event_id, evaluation_context_ref(record))

    history_reader = ExplicitPostgresCaseHistoryReader(connections=connections)
    monkeypatch.setattr(app.state, "identity_verifier", LabIdentity())
    monkeypatch.setattr(app.state, "security_audit", IngressAudit())
    monkeypatch.setattr(app.state, "case_history_reader", history_reader)
    monkeypatch.setattr(app.state, "case_queue_reader", ExplicitPostgresCaseQueueReader(
        connections=connections, ranking=SyntheticPostgresRankingSource(
            connections=connections, tenant_id=TENANT, alert_policies=(ALERT_POLICY,),
        ),
    ))
    monkeypatch.setattr(app.state, "case_transition_writer", ExplicitPostgresCaseTransitionWriter(
        connections=connections, evaluations=LabEvaluationDirectory(),
        assignees=AssigneeDirectory(),
    ))

    base_url = f"/v1/tenants/{TENANT}/cases"
    auth = {"Authorization": "Bearer synthetic-investigator"}
    foreign_auth = {"Authorization": "Bearer synthetic-other-tenant"}
    with TestClient(app) as http:
        response = http.get(f"{base_url}/queue", headers=auth)
        assert response.status_code == 200, response.text
        [queued] = response.json()["items"]
        assert queued["source_event_id"] == str(sample.event_id)
        assert queued["scenario_ids"] == ["MM-02"]
        assert queued["rank"] == queued["revision"] == 1
        case_url = f"{base_url}/{queued['case_id']}"

        operations = (
            ("triage", "analyst_triage", {}),
            ("assign", "investigation_assigned", {"assignee_selector": str(ASSIGNEE)}),
            ("dispose", "legitimate_evidence", {"disposition": "confirmed_legitimate"}),
            ("correct", "corrected_finding", {"disposition": "confirmed_fraud"}),
            ("reconcile", "feedback_reconciled", {}),
        )
        for revision, (operation, reason, fields) in enumerate(operations, 1):
            payload = {
                "source_event_id": queued["source_event_id"],
                "expected_revision": revision,
                "idempotency_key": uuid4().hex,
                "reason_code": reason,
                **fields,
            }
            url = f"{case_url}/transitions/{operation}"
            if revision == 1:
                assert http.post(url, headers=foreign_auth, json=payload).status_code == 404
            result = http.post(url, headers=auth, json=payload)
            assert result.status_code == 200, result.text
            assert result.json()["revision"] == revision + 1
            assert result.json()["bank_execution"] == "unknown"
            assert result.json()["enforcement_activated"] is False
        assert http.post(url, headers=auth, json=payload).json() == result.json()
        assert http.get(f"{base_url}/queue", headers=auth).json()["items"] == []

        inspected = http.get(f"{case_url}/history", headers=auth)
        assert inspected.status_code == 200, inspected.text
        assert [row["operation"] for row in inspected.json()["events"]] == [
            "create", "triage", "assign", "dispose", "correct", "reconcile",
        ]
        assert http.get(f"{case_url}/history", headers=foreign_auth).status_code == 404

    with connections() as connection:
        persisted = connection.execute("SELECT * FROM evaluation_alerts").fetchone()
    at = datetime.now(UTC)
    history = history_reader.history(
        principal=principal(caps=analyst_capabilities), tenant_id=TENANT,
        case_id=persisted["case_id"], at=at,
    )
    kpis = summarize_synthetic_case_metrics(
        tenant_id=TENANT, histories=(history,), as_of=at,
        alert_clocks=(SyntheticAlertClock(
            TENANT, persisted["case_id"], sample.event_id,
            sample.canonical_transaction.occurred_at, persisted["generated_at"],
        ),),
    )
    assert kpis["counts"]["confirmed_fraud"] == kpis["counts"]["reconciled"] == 1
    assert kpis["counts"]["confirmed_legitimate"] == kpis["counts"]["open_investigations"] == 0
    assert kpis["alert_latency"]["eligible_count"] == kpis["alert_latency"]["count"] == 1
    assert kpis["investigation_turnaround"]["count"] == 1
    assert kpis["bank_operational_kpi_authorized"] is False
