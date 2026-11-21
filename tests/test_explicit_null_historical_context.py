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
from test_evaluation_context_legacy import _record
from test_postgres_case_writer_bridge import DSN, connect, principal
import test_postgres_evaluation_alerts as alerts

installation = alerts.installation

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
    import gasha.cases.evaluation_alerts as evidence

    from fastapi.testclient import TestClient
    from test_postgres_synthetic_ranking import SyntheticVerifier
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
