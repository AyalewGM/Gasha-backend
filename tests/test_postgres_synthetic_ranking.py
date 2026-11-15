"""Synthetic policy #142 against real #148 persisted alerts and protected HTTP."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest
import test_postgres_evaluation_alerts as alert_tests
from fastapi.testclient import TestClient
from test_postgres_case_writer_bridge import DSN, IngressAudit, connect, principal
from test_postgres_evaluation_alerts import ALERT_POLICY, evaluate, event

from gasha.api.main import app
from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader
from gasha.cases.queue import CaseQueueRejected
from gasha.cases.synthetic_ranking import SyntheticPostgresRankingSource, _RankedEvidence
from gasha.security.access import AuthorizationRejected, Capability, CredentialRejected

installation = alert_tests.installation
schema = alert_tests.schema
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")


class SyntheticVerifier:
    def verify(self, bearer):
        if bearer == "analyst":
            return principal(caps=frozenset({Capability.CASE_READ}))
        if bearer == "foreign":
            return principal(tenant="tenant-b", caps=frozenset({Capability.CASE_READ}))
        raise CredentialRejected("synthetic credential revoked")


def test_authenticated_ranking_uses_strongest_group_alert_and_isolates_tenant(
    installation, monkeypatch,
):
    low, high = event(score=0.72), event(score=0.97)
    distinct = event(score=0.90)
    distinct.canonical_transaction.device_id = "synthetic-other-device"
    foreign = event(tenant="tenant-b", score=0.99)
    for sample in (low, high, distinct, foreign):
        evaluate(installation, sample)

    def connections():
        return connect(installation)

    source = SyntheticPostgresRankingSource(
        connections=connections, tenant_id="tenant-a", alert_policies=(ALERT_POLICY,),
    )
    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    monkeypatch.setattr(app.state, "security_audit", IngressAudit())
    monkeypatch.setattr(app.state, "case_queue_reader", ExplicitPostgresCaseQueueReader(
        connections=connections, ranking=source,
    ))
    with TestClient(app) as client:
        url = "/v1/tenants/tenant-a/cases/queue"
        response = client.get(url, headers={"Authorization": "Bearer analyst"})
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["ranking_policy_version"] == "synthetic-alert-priority-v1"
        assert [row["rank"] for row in payload["items"]] == [1, 2]
        assert [row["source_event_id"] for row in payload["items"]] == [
            str(low.event_id), str(distinct.event_id),
        ]
        assert payload["bank_ranking_approved"] is payload["enforcement_activated"] is False
        assert client.get(url, headers={"Authorization": "Bearer foreign"}).status_code == 404
        assert client.get(url, headers={"Authorization": "Bearer revoked"}).status_code == 401


def test_recomputes_priority_and_rejects_tampered_or_future_evidence(installation):
    sample = event()
    evaluate(installation, sample)
    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation),
        tenant_id="tenant-a", alert_policies=(ALERT_POLICY,),
    )
    analyst = principal(caps=frozenset({Capability.CASE_READ}))
    now = datetime.now(UTC)
    assert source.select(principal=analyst, tenant_id="tenant-a", limit=1, at=now).items

    with pytest.raises(AuthorizationRejected):
        source.select(principal=replace(analyst, expires_at=now), tenant_id="tenant-a", limit=1, at=now)
    with pytest.raises(CaseQueueRejected, match="future"):
        source.select(principal=analyst, tenant_id="tenant-a", limit=1, at=now - timedelta(days=1))

    with connect(installation) as connection:
        connection.execute("UPDATE evaluation_alerts SET priority_seed = 3")
    with pytest.raises(CaseQueueRejected, match="disagree"):
        source.select(principal=analyst, tenant_id="tenant-a", limit=1, at=now)


def test_grouped_alert_cannot_be_reassigned_to_an_unrelated_case(installation):
    initial, grouped, distinct = event(score=0.72), event(score=0.97), event(score=0.9)
    distinct.canonical_transaction.device_id = "unrelated-device"
    for sample in (initial, distinct, grouped):
        evaluate(installation, sample)
    with connect(installation) as connection:
        connection.execute(
            "UPDATE evaluation_alerts SET case_id = ("
            "SELECT case_id FROM evaluation_alerts WHERE tenant_id = %s AND event_id = %s"
            ") WHERE tenant_id = %s AND event_id = %s",
            ("tenant-a", distinct.event_id, "tenant-a", grouped.event_id),
        )
    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation),
        tenant_id="tenant-a", alert_policies=(ALERT_POLICY,),
    )
    analyst = principal(caps=frozenset({Capability.CASE_READ}))
    with pytest.raises(CaseQueueRejected, match="unrelated"):
        source.select(principal=analyst, tenant_id="tenant-a", limit=2, at=datetime.now(UTC))


def test_dst_fallback_ranks_and_validates_by_utc_instant(installation):
    """The second 1 AM hour is later, despite its smaller New York wall time."""
    sample = event()
    evaluate(installation, sample)
    with connect(installation) as connection:
        row = connection.execute("""
            SELECT a.*, e.record_json, initial.source_event_id,
                   initial.source_context_ref, initial.occurred_at AS opened_at,
                   initial.occurred_at AS last_transition_at
            FROM evaluation_alerts a
            JOIN shadow_evaluations e USING (tenant_id, event_id)
            JOIN analyst_case_events initial
              ON initial.tenant_id = a.tenant_id
             AND initial.case_id = a.case_id AND initial.revision = 1
        """).fetchone()
    assert row is not None
    zone = ZoneInfo("America/New_York")
    opened = datetime(2026, 11, 1, 1, 50, tzinfo=zone, fold=0)
    later = datetime(2026, 11, 1, 1, 10, tzinfo=zone, fold=1)
    as_of = datetime(2026, 11, 1, 7, tzinfo=UTC)
    assert opened.astimezone(UTC) < later.astimezone(UTC)
    assert not opened <= later  # Regression: Python compares same-zone wall time.

    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation), tenant_id="tenant-a",
        alert_policies=(ALERT_POLICY,),
    )
    evidence = dict(row, opened_at=opened, generated_at=opened, last_transition_at=later)
    assert source._verify(evidence, at=as_of).case_id == row["case_id"]

    # Same wall-time with a different DST fold is not the same evidence instant.
    altered = dict(evidence, generated_at=opened.replace(fold=1))
    with pytest.raises(CaseQueueRejected, match="disagree"):
        source._verify(altered, at=as_of)

    first = _RankedEvidence(
        UUID(int=2), sample.event_id, sample.event_id, "0" * 64,
        "1" * 64, ("ATO-02",), opened, 2, 0.91,
    )
    second = replace(first, case_id=UUID(int=1), opened_at=later)
    assert first.sort_key(as_of) < second.sort_key(as_of)
