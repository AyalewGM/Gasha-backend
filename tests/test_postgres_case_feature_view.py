"""#45 synthetic-only, unmounted case-source feature evidence read regressions.

Actual PostgreSQL and tenant/capability negatives. NOT an installed browser,
approved issuer/audit ingress, real Bank/NetGuardians fault test or payment action.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from json import dumps, loads
from uuid import UUID, uuid4

import pytest
import test_postgres_evaluation_alerts as alerts
import test_postgres_explicit_null_historical_context as historical
import test_postgres_shadow_copy_mve as copies
import test_postgres_synthetic_fraud_workflow as workflow
from test_postgres_case_writer_bridge import principal
from test_postgres_evaluations import POLICY

import gasha.cases.evaluation_alerts as evidence
from gasha.cases.evaluation_alerts import (
    PostgresEvaluationAlertWriter,
    evaluation_context_ref,
    persisted_evaluation_context_matches,
)
from gasha.cases.postgres_feature_view import ExplicitPostgresCaseFeatureReader
from gasha.cases.timeline import CaseRejected, CaseSourceUnavailable
from gasha.domain.models import DecisionAction
from gasha.ingestion.service import IngestionService
from gasha.ingestion.shadow_copy import SyntheticShadowCopyAdapter
from gasha.orchestration import ShadowEvaluationRecord, ShadowOrchestrator
from gasha.postgres_evaluations import (
    PostgresEvaluationPersistence,
    PostgresShadowEvaluationRepository,
)
from gasha.security.access import AuthorizationRejected, Capability

schema = alerts.schema
installation = workflow.installation
TENANT = "tenant-a"
READ = frozenset({Capability.CASE_READ})
CREATE = frozenset({Capability.CASE_CREATE})


def test_case_feature_read_rejects_untrusted_or_expired_principals_before_sql():
    opened = []

    def fail_connection():
        opened.append(True)
        raise AssertionError("unauthorized feature read opened database")

    reader = ExplicitPostgresCaseFeatureReader(connections=fail_connection)
    now = datetime.now(UTC)
    valid = principal(caps=READ)
    expired = replace(valid, expires_at=now - timedelta(seconds=1))
    for credentials, tenant, case, at in (
        (principal(caps=CREATE), TENANT, uuid4(), now),
        (valid, "tenant-b", uuid4(), now),
        (expired, TENANT, uuid4(), now),
        (valid, TENANT, "untyped-case", now),
        (valid, TENANT, uuid4(), datetime(2026, 11, 20)),
    ):
        with pytest.raises((AuthorizationRejected, CaseRejected)):
            reader.read(
                principal=credentials, tenant_id=tenant,
                case_id=case, at=at,
            )
    assert opened == []


def _source(installation, *, feature: bool) -> tuple[UUID, UUID, str]:
    copy = copies._synthetic_copy()
    receipt = IngestionService({
        "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
    }).ingest(copy)
    assert receipt.envelope is not None
    assessment = copies._computed_graph_assessment(receipt.envelope)
    writer = PostgresEvaluationAlertWriter(
        TENANT, workflow.ALERT_POLICY, principal(caps=CREATE),
    )
    with workflow.connect(installation) as db:
        orchestration = ShadowOrchestrator(
            {TENANT: POLICY},
            persistence=PostgresEvaluationPersistence(db, alerts=writer),
        )
        outcome = orchestration.evaluate(
            assessment.assessed_envelope,
            feature_assessment=assessment if feature else None,
        )
        assert outcome.effective_action is DecisionAction.NO_ACTION_SHADOW
        record = PostgresShadowEvaluationRepository(
            db, tenant_ids=(TENANT,),
        ).get(TENANT, assessment.event_id)
        assert record is not None
        if feature:
            assert record.feature_evidence is not None
        else:
            assert record.feature_evidence is None
        row = db.execute(
            "SELECT case_id, context_ref FROM evaluation_alerts "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(assessment.event_id)),
        ).fetchone()
        assert row is not None
        return UUID(str(row["case_id"])), assessment.event_id, str(row["context_ref"])


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_durable_creation_source_projection_is_sanitized_and_not_case_wide(
    installation,
):
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    first_case, first_event, first_context = _source(installation, feature=True)
    second_case, second_event, second_context = _source(installation, feature=True)
    assert first_case == second_case  # grouping does not rewrite the founding source
    assert first_event != second_event and first_context != second_context

    reader = ExplicitPostgresCaseFeatureReader(
        connections=lambda: workflow.connect(installation),
    )
    view = reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=first_case, at=datetime.now(UTC),
    )
    assert view.availability == "available"
    assert view.source_assurance == "synthetic_unattested"
    assert view.scope == "case_creation_source_only"
    assert view.context_ref == first_context
    assert view.context_ref != second_context
    assert view.assessment_version == "gasha-synthetic-feature-assessment-v1"
    assert view.feature_set_version == "gasha-feature-set-v1"
    assert view.eligible_observations == 5
    assert view.late_observations == 1
    assert view.nonprior_observations == 0
    assert view.unavailable_signals == ()
    assert view.lineage_ref is not None and len(view.lineage_ref) == 64
    assert view.decision_as_of is not None and "+00:00" in view.decision_as_of
    assert all(len(value) == 64 for value in (
        view.source_fingerprint, view.computation_fingerprint,
    ) if value is not None)
    # Whitelisted output only. No raw identifiers, transaction payload,
    # customer/sender/device/beneficiary or issuer credentials.
    assert set(asdict(view)) == {
        "schema", "scope", "availability", "source_assurance",
        "context_ref", "assessment_version", "feature_set_version",
        "decision_as_of", "lineage_ref", "source_fingerprint",
        "computation_fingerprint", "eligible_observations",
        "late_observations", "nonprior_observations", "unavailable_signals",
    }
    for marker in (TENANT, str(first_event), str(second_event), "sender-1",
                   "synthetic-customer", "synthetic-device"):
        assert marker not in repr(view)
    assert reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=first_case, at=datetime.now(UTC),
    ) == view
    with workflow.connect(installation) as db:
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 2
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == 1


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_legacy_missing_feature_is_not_zero_and_foreign_scope_is_hidden(
    installation,
):
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    case_id, event_id, expected_context = _source(installation, feature=False)
    reader = ExplicitPostgresCaseFeatureReader(
        connections=lambda: workflow.connect(installation),
    )
    available = reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=case_id, at=datetime.now(UTC),
    )
    assert available.context_ref == expected_context
    assert available.availability == "not_recorded"
    assert available.source_assurance == "not_established"
    assert available.decision_as_of is None
    assert available.eligible_observations is None
    assert available.late_observations is None
    assert available.nonprior_observations is None
    assert available.unavailable_signals is None
    assert available.lineage_ref is None

    with pytest.raises(CaseSourceUnavailable):
        reader.read(
            principal=principal(tenant="tenant-b", caps=READ),
            tenant_id="tenant-b", case_id=case_id, at=datetime.now(UTC),
        )
    with pytest.raises(CaseSourceUnavailable):
        reader.read(
            principal=principal(caps=READ), tenant_id=TENANT,
            case_id=uuid4(), at=datetime.now(UTC),
        )
    with workflow.connect(installation) as db:
        assert db.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM security_audit_events "
            "WHERE action='alert.generate'"
        ).fetchone()["n"] == 1
        assert db.execute(
            "SELECT count(*) AS n FROM analyst_case_events"
        ).fetchone()["n"] == 1
        persisted = PostgresShadowEvaluationRepository(
            db, tenant_ids=(TENANT,),
        ).get(TENANT, event_id)
        assert persisted is not None and persisted.feature_evidence is None


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_historical_explicit_null_case_evidence_read_preserves_original_reference(
    installation, monkeypatch,
):
    """A real old-writer record stays readable without rewriting its hash."""
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    original_dump = ShadowEvaluationRecord.model_dump_json

    def old_serializer(self, *args, **kwargs):
        payload = loads(original_dump(self, *args, **kwargs))
        if self.feature_evidence is None:
            payload["feature_evidence"] = None
        return dumps(payload, sort_keys=True, separators=(",", ":"))

    # The old serializer/digest exists ONLY while writing this synthetic row.
    with monkeypatch.context() as patch:
        patch.setattr(ShadowEvaluationRecord, "model_dump_json", old_serializer)
        patch.setattr(evidence, "evaluation_context_ref", historical._historical_null_ref)
        case_id, event_id, context_ref = _source(installation, feature=False)

    with workflow.connect(installation) as db:
        row = db.execute(
            "SELECT record_json FROM shadow_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(event_id)),
        ).fetchone()
        assert row is not None
        original_raw = str(row["record_json"])
        parsed = ShadowEvaluationRecord.model_validate_json(original_raw)
        assert loads(original_raw)["feature_evidence"] is None
        assert context_ref != evaluation_context_ref(parsed)
        assert persisted_evaluation_context_matches(
            parsed, raw_record_json=original_raw, stored_context_ref=context_ref,
        )
        before = tuple(
            db.execute(f"SELECT count(*) AS n FROM {name}").fetchone()["n"]
            for name in (
                "shadow_evaluations", "evaluation_alerts", "analyst_case_events",
                "fraud_decision_audit", "security_audit_events",
            )
        )

    reader = ExplicitPostgresCaseFeatureReader(
        connections=lambda: workflow.connect(installation),
    )
    first = reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=case_id, at=datetime.now(UTC),
    )
    assert first.context_ref == context_ref
    assert first.availability == "not_recorded"
    assert first.eligible_observations is None
    assert first.unavailable_signals is None
    assert reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=case_id, at=datetime.now(UTC),
    ) == first
    # The historical fallback must NOT accept absent-field substitution,
    # altered stored source identity or an arbitrary claimed link.
    for corrupted in (
        {key: value for key, value in loads(original_raw).items()
         if key != "feature_evidence"},
        dict(loads(original_raw), persisted_at="2030-01-01T00:00:00Z"),
        dict(loads(original_raw), feature_evidence={"forged": True}),
    ):
        altered_raw = dumps(corrupted)
        try:
            changed = ShadowEvaluationRecord.model_validate_json(altered_raw)
        except ValueError:
            continue  # Invalid source schema is already fail-closed.
        assert not persisted_evaluation_context_matches(
            changed, raw_record_json=altered_raw, stored_context_ref=context_ref,
        )
    with pytest.raises(CaseSourceUnavailable):
        reader.read(
            principal=principal(tenant="tenant-b", caps=READ),
            tenant_id="tenant-b", case_id=case_id, at=datetime.now(UTC),
        )
    with workflow.connect(installation) as db:
        assert str(db.execute(
            "SELECT record_json FROM shadow_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(event_id)),
        ).fetchone()["record_json"]) == original_raw
        assert tuple(
            db.execute(f"SELECT count(*) AS n FROM {name}").fetchone()["n"]
            for name in (
                "shadow_evaluations", "evaluation_alerts", "analyst_case_events",
                "fraud_decision_audit", "security_audit_events",
            )
        ) == before


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
def test_feature_evidence_tamper_cannot_claim_existing_case_context(installation):
    """Actual durable feature record; synthetic tampering never validates."""
    alerts.install_policy(installation, workflow.ALERT_POLICY)
    case_id, event_id, context_ref = _source(installation, feature=True)
    with workflow.connect(installation) as db:
        row = db.execute(
            "SELECT record_json FROM shadow_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(event_id)),
        ).fetchone()
        assert row is not None
        raw = str(row["record_json"])
    clean_record = ShadowEvaluationRecord.model_validate_json(raw)
    assert persisted_evaluation_context_matches(
        clean_record, raw_record_json=raw, stored_context_ref=context_ref,
    )
    original = loads(raw)
    assert isinstance(original["feature_evidence"], dict)
    assert original["feature_evidence"]["unavailable_signals"] == []
    for field, replacement in (
        ("lineage_ref", "0" * 64),
        ("source_fingerprint", "0" * 64),
        ("unavailable_signals", ["fabricated_signal"]),
    ):
        forged = loads(raw)
        forged["feature_evidence"][field] = replacement
        forged_raw = dumps(forged)
        try:
            changed = ShadowEvaluationRecord.model_validate_json(forged_raw)
        except ValueError:
            continue  # Validator refuses malformed evidence.
        assert not persisted_evaluation_context_matches(
            changed, raw_record_json=forged_raw, stored_context_ref=context_ref,
        )
    reader = ExplicitPostgresCaseFeatureReader(
        connections=lambda: workflow.connect(installation),
    )
    assert reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=case_id, at=datetime.now(UTC),
    ).context_ref == context_ref
