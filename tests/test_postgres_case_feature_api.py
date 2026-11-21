"""#42/#45 actual PostgreSQL protected synthetic feature endpoint / audit regressions.

No browser session, Bank identity/attestation, source-data access, or payment
enforcement is installed. All fixtures are disposable, invented, and tenant scoped.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import test_postgres_case_feature_view as features
import test_postgres_evaluation_alerts as alerts
import test_postgres_synthetic_fraud_workflow as workflow
from fastapi.testclient import TestClient
from test_postgres_case_writer_bridge import principal

from gasha.api.main import app
from gasha.cases.postgres_feature_view import ExplicitPostgresCaseFeatureReader
from gasha.security.access import Capability, CredentialRejected
from gasha.security.postgres_audit import PostgresSecurityAuditSink

pytestmark = pytest.mark.skipif(
    not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set",
)
schema = alerts.schema
installation = workflow.installation
TENANT = "tenant-a"


class SyntheticVerifier:
    def __init__(self) -> None:
        self.revoked = False

    def verify(self, bearer: str):
        if bearer == "outage":
            raise RuntimeError("synthetic identity unavailable")
        if bearer == "valid" and not self.revoked:
            return principal(caps=frozenset({Capability.CASE_READ}))
        if bearer == "no-read":
            return principal(caps=frozenset({Capability.CASE_TRIAGE}))
        if bearer == "wrong-tenant":
            return principal(tenant="tenant-b", caps=frozenset({Capability.CASE_READ}))
        if bearer == "expired":
            return principal(caps=frozenset({Capability.CASE_READ})).__class__(
                subject="synthetic-analyst", issuer="synthetic-test",
                credential_ref="expired-synthetic", tenant_ids=frozenset({TENANT}),
                capabilities=frozenset({Capability.CASE_READ}),
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            )
        raise CredentialRejected("synthetic credential revoked")


def path(case_id: UUID, tenant: str = TENANT) -> str:
    return f"/v1/tenants/{tenant}/cases/{case_id}/feature-evidence"


def auth(token: str = "valid") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def audit_rows(schema_name: str):
    with workflow.connect(schema_name) as conn:
        return conn.execute(
            "SELECT action, result, reason, actor_ref, tenant_ref, "
            "attempt_ref, event_ref, context_ref "
            "FROM security_audit_events ORDER BY id"
        ).fetchall()


def test_protected_case_feature_read_and_denial_have_committed_redacted_audit(
    installation, monkeypatch,
):
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    case_id, event_id, context_ref = features._source(installation, feature=True)
    factory_calls = [0]

    def connections():
        factory_calls[0] += 1
        return workflow.connect(installation)

    reader = ExplicitPostgresCaseFeatureReader(connections=connections)
    verifier = SyntheticVerifier()
    monkeypatch.setattr(app.state, "identity_verifier", verifier)
    monkeypatch.setattr(app.state, "case_feature_reader", reader)
    with workflow.connect(installation) as audit_connection:
        monkeypatch.setattr(
            app.state, "security_audit", PostgresSecurityAuditSink(audit_connection),
        )
        with TestClient(app) as client:
            good = client.get(path(case_id), headers=auth())
            assert good.status_code == 200, good.text
            payload = good.json()
            assert payload["feature_evidence"]["scope"] == "case_creation_source_only"
            assert payload["feature_evidence"]["source_assurance"] == "synthetic_unattested"
            assert payload["feature_evidence"]["context_ref"] == context_ref
            assert payload["feature_evidence"]["eligible_observations"] == 5
            assert payload["bank_source_attested"] is False
            assert payload["enforcement_activated"] is False
            assert str(event_id) not in good.text
            assert "synthetic-analyst" not in good.text
            assert factory_calls[0] == 1

            tests = (
                (path(case_id), {}, 401),
                (path(case_id), auth("revoked"), 401),
                (path(case_id), auth("expired"), 401),
                (path(case_id), auth("outage"), 503),
                (path(case_id), auth("no-read"), 403),
                (path(case_id), auth("wrong-tenant"), 404),
                (path(case_id, tenant="tenant-b"), auth(), 404),
            )
            for target, headers, expected_status in tests:
                result = client.get(
                    target, headers={
                        **headers, "X-Tenant-Id": "tenant-b", "X-Role": "admin",
                    },
                )
                assert result.status_code == expected_status, result.text
                assert "feature_evidence" not in result.text
            assert factory_calls[0] == 1  # no data access on rejected credentials/role

            verifier.revoked = True
            assert client.get(path(case_id), headers=auth()).status_code == 401
            verifier.revoked = False
            missing = client.get(path(uuid4()), headers=auth())
            assert missing.status_code == 503
            assert "feature_evidence" not in missing.text
            assert factory_calls[0] == 2

            rows = audit_rows(installation)
            case_rows = [row for row in rows if row["action"] == "case.read"]
            assert [row["result"] for row in case_rows[:2]] == [
                "authorized", "succeeded",
            ]
            assert case_rows[1]["context_ref"] == context_ref
            assert case_rows[-2]["result"] == "authorized"
            assert case_rows[-1]["result"] == "failed"
            assert case_rows[-1]["reason"] == "case_feature_unavailable"
            assert len({row["attempt_ref"] for row in case_rows[:2]}) == 1
            assert all(
                len(row["attempt_ref"]) == 32 and len(row["tenant_ref"]) == 64
                for row in rows
            )
            assert "tenant-a" not in str(rows) and "tenant-b" not in str(rows)
            assert "synthetic-analyst" not in str(rows)
            assert "synthetic-only" not in str(rows)
            assert audit_rows(installation) == rows

            audit_connection.close()
            refused = client.get(path(case_id), headers=auth())
            assert refused.status_code == 503
            assert "feature_evidence" not in refused.text
            assert factory_calls[0] == 2


def test_default_and_non_durable_audit_never_expose_synthetic_features(
    installation, monkeypatch,
):
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    case_id, _, _ = features._source(installation, feature=True)
    calls = [0]

    def connections():
        calls[0] += 1
        return workflow.connect(installation)

    monkeypatch.setattr(
        app.state, "case_feature_reader",
        ExplicitPostgresCaseFeatureReader(connections=connections),
    )
    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    with TestClient(app) as client:
        monkeypatch.setattr(app.state, "security_audit", None)
        assert client.get(path(case_id), headers=auth()).status_code == 503

        class ProcessLocalAudit:
            def append(self, event):
                raise AssertionError("in-memory sink must not be used")

        monkeypatch.setattr(app.state, "security_audit", ProcessLocalAudit())
        response = client.get(path(case_id), headers=auth())
        assert response.status_code == 503
        assert "feature_evidence" not in response.text
        assert calls == [0]


def test_protected_feature_route_is_default_off_even_with_postgres_audit(
    installation, monkeypatch,
):
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    case_id, _, _ = features._source(installation, feature=True)
    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    monkeypatch.setattr(app.state, "case_feature_reader", None)
    with workflow.connect(installation) as audit_connection:
        monkeypatch.setattr(
            app.state, "security_audit", PostgresSecurityAuditSink(audit_connection),
        )
        with TestClient(app) as client:
            result = client.get(path(case_id), headers=auth())
            assert result.status_code == 503
            assert result.json() == {"detail": "case feature evidence unavailable"}
    rows = audit_rows(installation)
    case_reads = [row for row in rows if row["action"] == "case.read"]
    assert [row["result"] for row in case_reads] == ["authorized", "failed"]
