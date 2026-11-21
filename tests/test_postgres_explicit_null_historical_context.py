"""#43 synthetic historical explicit-null context: read/replay only.

The old Pydantic serializer could hash a persisted optional null; new writes
must never revive that representation. No Bank source, payment or activation.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from json import dumps, loads

import pytest
import test_postgres_evaluation_alerts as alerts
from test_evaluation_context_legacy import _record
from test_postgres_case_writer_bridge import DSN, connect, principal

installation = alerts.installation
schema = alerts.schema

from gasha.cases.evaluation_alerts import (
    evaluation_context_ref,
    persisted_evaluation_context_matches,
)
from gasha.cases.queue import CaseQueueRejected
from gasha.cases.synthetic_ranking import SyntheticPostgresRankingSource
from gasha.orchestration import ShadowEvaluationRecord, canonical_evaluation_context_payload
from gasha.security.access import AuthorizationRejected, Capability


def _historical_null_ref(record: ShadowEvaluationRecord) -> str:
    payload = canonical_evaluation_context_payload(record)
    payload["feature_evidence"] = None
    return sha256(dumps(
        ["gasha-shadow-evaluation-v1", payload],
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def _raw_with_null(record: ShadowEvaluationRecord) -> str:
    payload = canonical_evaluation_context_payload(record)
    payload["feature_evidence"] = None
    return dumps(payload, sort_keys=True, separators=(",", ":"))


def test_explicit_null_legacy_digest_is_read_only_and_bounded() -> None:
    legacy = _record()
    raw = _raw_with_null(legacy)
    old_ref = _historical_null_ref(legacy)
    canonical = evaluation_context_ref(legacy)
    assert old_ref != canonical
    assert persisted_evaluation_context_matches(
        legacy, raw_record_json=raw, stored_context_ref=old_ref,
    )
    assert persisted_evaluation_context_matches(
        legacy, raw_record_json=raw, stored_context_ref=canonical,
    )
    assert not persisted_evaluation_context_matches(
        legacy, raw_record_json=dumps(canonical_evaluation_context_payload(legacy)),
        stored_context_ref=old_ref,
    )  # missing optional field cannot claim the null-inclusive digest
    assert not persisted_evaluation_context_matches(
        legacy, raw_record_json=raw, stored_context_ref="0" * 64,
    )
    modified = loads(raw)
    modified["persisted_at"] = "2030-01-01T00:00:00Z"
    assert not persisted_evaluation_context_matches(
        legacy, raw_record_json=dumps(modified), stored_context_ref=old_ref,
    )
    assert not persisted_evaluation_context_matches(
        _record(with_evidence=True), raw_record_json=raw,
        stored_context_ref=old_ref,
    )
    # A historical read exception must not change the canonical write digest.
    assert evaluation_context_ref(legacy) == canonical


@pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_persisted_null_inclusive_context_survives_real_pg_replay_and_queue(
    installation, monkeypatch,
) -> None:
    """Create an old historical row with its original null-inclusive reference.

    Neither the model serializer nor the legacy digest is changed after setup.
    Confirm real saved context and history are not rewritten during replay.
    """
    from fastapi.testclient import TestClient
    from test_postgres_synthetic_ranking import SyntheticVerifier

    import gasha.cases.evaluation_alerts as evidence
    from gasha.api.main import app
    from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
    from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader

    existing_dump = ShadowEvaluationRecord.model_dump_json

    def legacy_json(self, *args, **kwargs):
        payload = loads(existing_dump(self, *args, **kwargs))
        if self.feature_evidence is None:
            payload["feature_evidence"] = None
        return dumps(payload, sort_keys=True, separators=(",", ":"))

    sample = alerts.event()
    with monkeypatch.context() as patch:
        patch.setattr(ShadowEvaluationRecord, "model_dump_json", legacy_json)
        patch.setattr(evidence, "evaluation_context_ref", _historical_null_ref)
        first = alerts.evaluate(installation, sample)

    from gasha.domain.models import DecisionAction
    assert first.effective_action is DecisionAction.NO_ACTION_SHADOW
    with connect(installation) as db:
        row = db.execute(
            """SELECT e.record_json, a.context_ref, a.case_id
               FROM shadow_evaluations e
               JOIN evaluation_alerts a USING (tenant_id, event_id)
               WHERE e.tenant_id = %s AND e.event_id = %s""",
            ("tenant-a", sample.event_id),
        ).fetchone()
        assert row is not None
        raw = str(row["record_json"])
        context_ref = str(row["context_ref"])
        assert loads(raw)["feature_evidence"] is None
        assert context_ref == _historical_null_ref(
            ShadowEvaluationRecord.model_validate_json(raw)
        )
        assert context_ref != evaluation_context_ref(
            ShadowEvaluationRecord.model_validate_json(raw)
        )

    # The new canonical writer must replay, never mutate historical context.
    assert alerts.evaluate(installation, sample).effective_action is (
        DecisionAction.NO_ACTION_SHADOW
    )
    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation), tenant_id="tenant-a",
        alert_policies=(alerts.ALERT_POLICY,),
    )
    reader = principal(caps=frozenset({Capability.CASE_READ}))
    now = datetime.now(UTC)
    selection = source.select(
        principal=reader, tenant_id="tenant-a", limit=10, at=now,
    )
    assert len(selection.items) == 1
    assert selection.items[0].source_context_ref == context_ref

    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    from test_postgres_case_writer_bridge import IngressAudit
    monkeypatch.setattr(app.state, "security_audit", IngressAudit())
    monkeypatch.setattr(
        app.state, "case_queue_reader",
        ExplicitPostgresCaseQueueReader(
            connections=lambda: connect(installation), ranking=source,
        ),
    )
    monkeypatch.setattr(
        app.state, "case_history_reader",
        ExplicitPostgresCaseHistoryReader(connections=lambda: connect(installation)),
    )
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer analyst"}
        queue = client.get("/v1/tenants/tenant-a/cases/queue", headers=headers)
        assert queue.status_code == 200, queue.text
        assert queue.json()["items"][0]["source_context_ref"] == context_ref
        detail = client.get(
            f"/v1/tenants/tenant-a/cases/{row['case_id']}/history",
            headers=headers,
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["events"][0]["source_context_ref"] == context_ref
        assert client.get(
            "/v1/tenants/tenant-a/cases/queue",
            headers={"Authorization": "Bearer foreign"},
        ).status_code == 404
        assert client.get(
            "/v1/tenants/tenant-a/cases/queue",
            headers={"Authorization": "Bearer revoked"},
        ).status_code == 401

    with connect(installation) as db:
        evidence_row = db.execute(
            """SELECT a.*, e.record_json, initial.source_event_id,
                      initial.source_context_ref, initial.occurred_at AS opened_at,
                      initial.occurred_at AS last_transition_at
               FROM evaluation_alerts a
               JOIN shadow_evaluations e USING (tenant_id, event_id)
               JOIN analyst_case_events initial
                 ON initial.tenant_id = a.tenant_id
                AND initial.case_id = a.case_id AND initial.revision = 1
               WHERE a.tenant_id = %s AND a.event_id = %s""",
            ("tenant-a", sample.event_id),
        ).fetchone()
        assert evidence_row is not None
        assert evidence_row["context_ref"] == context_ref
        assert evidence_row["record_json"] == raw
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM evaluation_alerts"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM fraud_decision_audit"
        ).fetchone()["n"] == 1

    missing_field = loads(raw)
    missing_field.pop("feature_evidence")
    for altered in (
        dict(evidence_row, record_json=dumps(missing_field)),
        dict(evidence_row, context_ref="0" * 64),
        dict(evidence_row, source_context_ref="0" * 64),
        dict(evidence_row, tenant_id="tenant-b"),
        dict(evidence_row, event_id=alerts.event().event_id),
    ):
        with pytest.raises((CaseQueueRejected, ValueError)):
            source._verify(altered, at=now)
    with pytest.raises(AuthorizationRejected):
        source.select(
            principal=replace(reader, expires_at=now - timedelta(seconds=1)),
            tenant_id="tenant-a", limit=10, at=now,
        )


@pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_mixed_absent_null_and_feature_contexts_rank_and_replay_in_real_postgres(
    installation, monkeypatch,
) -> None:
    """PO #43: one cohort, three persisted serializer shapes, no history rewrite.

    The protected queue exposes ordered top-K prefixes, not cursor/offset pages.
    Neither this fixture nor its synthetic issuer is Bank attestation.
    """
    from fastapi.testclient import TestClient
    from test_postgres_evaluations import POLICY
    from test_postgres_shadow_copy_mve import _computed_graph_assessment, _synthetic_copy
    from test_postgres_synthetic_ranking import SyntheticVerifier

    import gasha.cases.evaluation_alerts as evidence
    import test_postgres_synthetic_fraud_workflow as workflow
    from gasha.api.main import app
    from gasha.cases.evaluation_alerts import PostgresEvaluationAlertWriter
    from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
    from gasha.cases.postgres_queue_reader import ExplicitPostgresCaseQueueReader
    from gasha.domain.models import DecisionAction
    from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
    from gasha.orchestration import ShadowOrchestrator
    from gasha.postgres_evaluations import PostgresEvaluationPersistence
    from test_postgres_case_writer_bridge import IngressAudit

    # Different device grouping keys ensure three independently linked cases.
    absent = alerts.event(score=0.93)
    absent.canonical_transaction.device_id = "synthetic-absent-history-device"
    explicit_null = alerts.event(score=0.97)
    explicit_null.canonical_transaction.device_id = "synthetic-null-history-device"

    assert alerts.evaluate(installation, absent).effective_action is (
        DecisionAction.NO_ACTION_SHADOW
    )
    existing_dump = ShadowEvaluationRecord.model_dump_json

    def prior_serializer(self, *args, **kwargs):
        payload = loads(existing_dump(self, *args, **kwargs))
        if self.feature_evidence is None:
            payload["feature_evidence"] = None
        return dumps(payload, sort_keys=True, separators=(",", ":"))

    # Emulate historical writer only while creating the explicit-null row.
    with monkeypatch.context() as patch:
        patch.setattr(ShadowEvaluationRecord, "model_dump_json", prior_serializer)
        patch.setattr(evidence, "evaluation_context_ref", _historical_null_ref)
        assert alerts.evaluate(installation, explicit_null).effective_action is (
            DecisionAction.NO_ACTION_SHADOW
        )

    alerts.install_policy(installation, workflow.ALERT_POLICY)
    assessed = _computed_graph_assessment(
        SyntheticShadowCopyAdapter().adapt(_synthetic_copy())
    )

    def write_current():
        with connect(installation) as db:
            writer = PostgresEvaluationAlertWriter(
                "tenant-a", workflow.ALERT_POLICY,
                principal(caps=frozenset({Capability.CASE_CREATE})),
            )
            return ShadowOrchestrator(
                {"tenant-a": POLICY},
                persistence=PostgresEvaluationPersistence(db, alerts=writer),
            ).evaluate(
                assessed.assessed_envelope, feature_assessment=assessed,
            )

    assert write_current().effective_action is DecisionAction.NO_ACTION_SHADOW
    events = (absent.event_id, explicit_null.event_id, assessed.event_id)
    with connect(installation) as db:
        persisted = db.execute(
            """SELECT a.*, e.record_json, initial.source_event_id,
                      initial.source_context_ref,
                      initial.occurred_at AS opened_at,
                      initial.occurred_at AS last_transition_at
               FROM evaluation_alerts a
               JOIN shadow_evaluations e USING (tenant_id, event_id)
               JOIN analyst_case_events initial
                 ON initial.tenant_id = a.tenant_id
                AND initial.case_id = a.case_id AND initial.revision = 1
               WHERE a.tenant_id = %s ORDER BY a.event_id""",
            ("tenant-a",),
        ).fetchall()
        original_rows = tuple(dict(row) for row in persisted)
        counts_before = tuple(
            db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
            for table in (
                "shadow_evaluations", "evaluation_alerts", "fraud_decision_audit",
                "analyst_case_events", "security_audit_events",
            )
        )
    assert len(persisted) == len(events) == 3
    by_event = {row["event_id"]: row for row in persisted}
    assert set(by_event) == set(events)
    assert len({row["case_id"] for row in persisted}) == 3
    absent_row = by_event[absent.event_id]
    null_row = by_event[explicit_null.event_id]
    current_row = by_event[assessed.event_id]
    assert "feature_evidence" not in loads(absent_row["record_json"])
    assert loads(null_row["record_json"])["feature_evidence"] is None
    assert isinstance(loads(current_row["record_json"])["feature_evidence"], dict)
    assert null_row["context_ref"] == _historical_null_ref(
        ShadowEvaluationRecord.model_validate_json(null_row["record_json"])
    )
    assert null_row["context_ref"] != evaluation_context_ref(
        ShadowEvaluationRecord.model_validate_json(null_row["record_json"])
    )
    for row in (absent_row, current_row):
        assert row["context_ref"] == evaluation_context_ref(
            ShadowEvaluationRecord.model_validate_json(row["record_json"])
        )

    # Replay all three *after* removing the old serializer/digest monkeypatch.
    for sample in (absent, explicit_null):
        assert alerts.evaluate(installation, sample).effective_action is (
            DecisionAction.NO_ACTION_SHADOW
        )
    assert write_current().effective_action is DecisionAction.NO_ACTION_SHADOW
    with connect(installation) as db:
        replayed = db.execute(
            """SELECT a.*, e.record_json, initial.source_event_id,
                      initial.source_context_ref,
                      initial.occurred_at AS opened_at,
                      initial.occurred_at AS last_transition_at
               FROM evaluation_alerts a
               JOIN shadow_evaluations e USING (tenant_id, event_id)
               JOIN analyst_case_events initial
                 ON initial.tenant_id = a.tenant_id
                AND initial.case_id = a.case_id AND initial.revision = 1
               WHERE a.tenant_id = %s ORDER BY a.event_id""",
            ("tenant-a",),
        ).fetchall()
        assert tuple(dict(row) for row in replayed) == original_rows
        assert tuple(
            db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
            for table in (
                "shadow_evaluations", "evaluation_alerts", "fraud_decision_audit",
                "analyst_case_events", "security_audit_events",
            )
        ) == counts_before

    source = SyntheticPostgresRankingSource(
        connections=lambda: connect(installation), tenant_id="tenant-a",
        alert_policies=(alerts.ALERT_POLICY, workflow.ALERT_POLICY),
    )
    analyst = principal(caps=frozenset({Capability.CASE_READ}))
    now = datetime.now(UTC)
    complete = source.select(
        principal=analyst, tenant_id="tenant-a", limit=3, at=now,
    )
    assert len(complete.items) == 3
    assert {item.source_event_id: item.source_context_ref for item in complete.items} == {
        event: by_event[event]["context_ref"] for event in events
    }
    # No cursor-based pagination exists; prove the supported top-K prefixes.
    for bound in (1, 2, 3):
        first = source.select(
            principal=analyst, tenant_id="tenant-a", limit=bound, at=now,
        )
        second = source.select(
            principal=analyst, tenant_id="tenant-a", limit=bound, at=now,
        )
        assert first.items == second.items == complete.items[:bound]

    monkeypatch.setattr(app.state, "identity_verifier", SyntheticVerifier())
    monkeypatch.setattr(app.state, "security_audit", IngressAudit())
    monkeypatch.setattr(
        app.state, "case_queue_reader",
        ExplicitPostgresCaseQueueReader(
            connections=lambda: connect(installation), ranking=source,
        ),
    )
    monkeypatch.setattr(
        app.state, "case_history_reader",
        ExplicitPostgresCaseHistoryReader(
            connections=lambda: connect(installation),
        ),
    )
    with TestClient(app) as client:
        url = "/v1/tenants/tenant-a/cases/queue"
        auth = {"Authorization": "Bearer analyst"}
        full = client.get(f"{url}?limit=3", headers=auth)
        assert full.status_code == 200, full.text
        assert full.json()["enforcement_activated"] is False
        items = full.json()["items"]
        assert len(items) == 3
        assert [item["rank"] for item in items] == [1, 2, 3]
        for bound in (1, 2):
            top = client.get(f"{url}?limit={bound}", headers=auth)
            assert top.status_code == 200, top.text
            assert top.json()["items"] == items[:bound]
        for item in items:
            original = by_event[next(
                event for event in events if str(event) == item["source_event_id"]
            )]
            assert item["source_context_ref"] == original["context_ref"]
            detail = client.get(
                f"/v1/tenants/tenant-a/cases/{item['case_id']}/history",
                headers=auth,
            )
            assert detail.status_code == 200, detail.text
            assert detail.json()["events"][0]["source_context_ref"] == (
                original["context_ref"]
            )
            assert detail.json()["events"][0]["bank_execution"] == "unknown"
        assert client.get(url, headers={"Authorization": "Bearer foreign"}).status_code == 404
        assert client.get(url, headers={"Authorization": "Bearer revoked"}).status_code == 401

    # All in-memory source substitutions must fail before ranked presentation.
    for row in persisted:
        other = next(
            candidate for candidate in persisted
            if candidate["event_id"] != row["event_id"]
        )
        for corrupted in (
            dict(row, context_ref=other["context_ref"]),
            dict(row, source_context_ref=other["context_ref"]),
            dict(row, tenant_id="tenant-b"),
            dict(row, event_id=other["event_id"]),
        ):
            with pytest.raises((CaseQueueRejected, ValueError)):
                source._verify(corrupted, at=now)

    current_raw = loads(current_row["record_json"])
    assert current_raw["feature_evidence"]["unavailable_signals"] == []
    for field, changed in (
        ("unavailable_signals", ["synthetic_unavailable_receipt_signal"]),
        ("source_fingerprint", "0" * 64),
        ("lineage_ref", "0" * 64),
    ):
        altered = loads(current_row["record_json"])
        altered["feature_evidence"][field] = changed
        with pytest.raises((CaseQueueRejected, ValueError)):
            source._verify(
                dict(current_row, record_json=dumps(altered)), at=now,
            )
    with pytest.raises(AuthorizationRejected):
        source.select(
            principal=replace(analyst, expires_at=now - timedelta(seconds=1)),
            tenant_id="tenant-a", limit=3, at=now,
        )

    # No test attempted payment execution, model activation or Bank integration.
    with connect(installation) as db:
        assert tuple(
            db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
            for table in (
                "shadow_evaluations", "evaluation_alerts", "fraud_decision_audit",
                "analyst_case_events", "security_audit_events",
            )
        ) == counts_before
