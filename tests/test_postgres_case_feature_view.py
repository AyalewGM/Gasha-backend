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


@pytest.mark.skipif(not workflow.DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
@pytest.mark.parametrize("corruption", (
    "alert_context", "alert_case", "nested_tenant", "nested_event",
    "feature_lineage", "unknown_signal_relinked", "foreign_candidate",
))
def test_reader_rejects_persisted_corruption_with_transactional_rollback(
    installation, corruption,
):
    """#45 PO/Security matrix: invoke the reader against actual corrupted SQL.

    Test-only mutations run inside one privileged disposable-schema savepoint.
    The same injected transaction lets the reader see those uncommitted rows,
    and rollback restores the immutable production trigger and every source.
    No application API or production immutability exception is introduced.
    """
    from contextlib import contextmanager

    from gasha.intelligence.feature_evidence_v1 import _lineage_ref

    alerts.install_policy(installation, workflow.ALERT_POLICY)
    case_id, event_id, context_ref = _source(installation, feature=True)
    other_case = None
    if corruption == "alert_case":
        # Force a second valid case with a different grouping device, so the
        # wrong-case alert remains FK-valid and cannot pass the founding join.
        from gasha.ingestion.contracts import InboundBankEvent

        original_copy = copies._synthetic_copy()
        altered_copy = InboundBankEvent.model_validate({
            **original_copy.model_dump(),
            "payload": {
                **original_copy.payload,
                "device_id": "different-synthetic-grouping-device",
            },
        })
        receipt = IngestionService({
            "synthetic-shadow-copy": SyntheticShadowCopyAdapter(),
        }).ingest(altered_copy)
        assert receipt.envelope is not None
        assessment = copies._computed_graph_assessment(receipt.envelope)
        with workflow.connect(installation) as db:
            writer = PostgresEvaluationAlertWriter(
                TENANT, workflow.ALERT_POLICY, principal(caps=CREATE),
            )
            result = ShadowOrchestrator(
                {TENANT: POLICY},
                persistence=PostgresEvaluationPersistence(db, alerts=writer),
            ).evaluate(assessment.assessed_envelope, feature_assessment=assessment)
            assert result.effective_action is DecisionAction.NO_ACTION_SHADOW
            other = db.execute(
                "SELECT case_id FROM evaluation_alerts WHERE tenant_id=%s AND event_id=%s",
                (TENANT, str(assessment.event_id)),
            ).fetchone()
            assert other is not None
            other_case = other["case_id"]
            assert UUID(str(other_case)) != case_id

    reader = ExplicitPostgresCaseFeatureReader(
        connections=lambda: workflow.connect(installation),
    )
    baseline = reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=case_id, at=datetime.now(UTC),
    )
    assert baseline.availability == "available"
    assert baseline.context_ref == context_ref
    tables = (
        "shadow_evaluations", "evaluation_alerts", "analyst_case_events",
        "fraud_decision_audit", "security_audit_events",
    )
    with workflow.connect(installation) as db:
        def counts():
            return tuple(
                db.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
                for table in tables
            )

        def source_rows():
            return (
                tuple(db.execute(
                    "SELECT tenant_id, event_id, record_json FROM shadow_evaluations "
                    "ORDER BY tenant_id, event_id",
                ).fetchall()),
                tuple(db.execute(
                    "SELECT tenant_id, event_id, case_id, context_ref FROM evaluation_alerts "
                    "ORDER BY tenant_id, event_id",
                ).fetchall()),
                tuple(db.execute(
                    "SELECT tenant_id, case_id, revision, source_event_id, "
                    "source_context_ref, event_json FROM analyst_case_events "
                    "ORDER BY tenant_id, case_id, revision",
                ).fetchall()),
            )

        original_counts, original_rows = counts(), source_rows()
        source = db.execute(
            "SELECT record_json FROM shadow_evaluations "
            "WHERE tenant_id=%s AND event_id=%s",
            (TENANT, str(event_id)),
        ).fetchone()
        assert source is not None
        original_raw = str(source["record_json"])
        raw = loads(original_raw)
        assert raw["feature_evidence"] is not None

        @contextmanager
        def same_transaction():
            # Unlike a psycopg Connection context, do NOT commit or close:
            # this is a deliberately isolated read of uncommitted corruption.
            yield db

        in_transaction_reader = ExplicitPostgresCaseFeatureReader(
            connections=same_transaction,
        )
        db.execute("SAVEPOINT synthetic_reader_corruption")
        try:
            if corruption == "alert_context":
                db.execute(
                    "UPDATE evaluation_alerts SET context_ref=%s "
                    "WHERE tenant_id=%s AND event_id=%s",
                    ("0" * 64, TENANT, str(event_id)),
                )
            elif corruption == "alert_case":
                assert other_case is not None
                db.execute(
                    "UPDATE evaluation_alerts SET case_id=%s "
                    "WHERE tenant_id=%s AND event_id=%s",
                    (str(other_case), TENANT, str(event_id)),
                )
            else:
                # 019 prevents even no-op UPDATE. Privileged corruption is
                # confined to a savepoint; rollback restores trigger state.
                db.execute(
                    "ALTER TABLE shadow_evaluations "
                    "DISABLE TRIGGER shadow_evaluations_immutable"
                )
                if corruption == "nested_tenant":
                    raw["event"]["tenant_id"] = "tenant-b"
                elif corruption == "nested_event":
                    raw["event"]["event_id"] = str(uuid4())
                elif corruption == "feature_lineage":
                    raw["feature_evidence"]["source_fingerprint"] = "0" * 64
                elif corruption == "foreign_candidate":
                    # A same-event foreign row must never rescue a corrupted
                    # local record, even with an apparently valid raw source.
                    db.execute(
                        "INSERT INTO shadow_evaluations "
                        "(tenant_id, event_id, record_json, persisted_at) "
                        "VALUES (%s, %s, %s, %s)",
                        ("tenant-b", str(event_id), original_raw, datetime.now(UTC)),
                    )
                    raw["event"]["tenant_id"] = "tenant-b"
                elif corruption == "unknown_signal_relinked":
                    # Rebind *all* three stored links to a validly rehashed
                    # event/evidence. The reader allowlist, not a mismatched
                    # digest, must reject this synthetic unknown signal.
                    feature = raw["feature_evidence"]
                    feature["unavailable_signals"] = ["unknown_synthetic_signal"]
                    lineage = {key: value for key, value in feature.items()
                               if key != "lineage_ref"}
                    lineage["event_id"] = UUID(str(lineage["event_id"]))
                    lineage["decision_as_of"] = datetime.fromisoformat(
                        str(lineage["decision_as_of"])
                    )
                    feature["lineage_ref"] = _lineage_ref(lineage)
                    accepted = ShadowEvaluationRecord.model_validate_json(dumps(raw))
                    rebound = evaluation_context_ref(accepted)
                    assert rebound != context_ref
                    # A full internally coherent digest must reach the
                    # reader's *separate* unavailable-signal allowlist.
                    assert persisted_evaluation_context_matches(
                        accepted, raw_record_json=dumps(raw),
                        stored_context_ref=rebound,
                    )
                    db.execute(
                        "UPDATE evaluation_alerts SET context_ref=%s "
                        "WHERE tenant_id=%s AND event_id=%s",
                        (rebound, TENANT, str(event_id)),
                    )
                    db.execute(
                        "UPDATE analyst_case_events "
                        "SET source_context_ref=%s, "
                        "event_json=jsonb_set(event_json, '{source_context_ref}', "
                        "to_jsonb(%s::text)) "
                        "WHERE tenant_id=%s AND case_id=%s AND revision=1",
                        (rebound, rebound, TENANT, str(case_id)),
                    )
                else:
                    raise AssertionError("unrecognized synthetic corruption")
                db.execute(
                    "UPDATE shadow_evaluations SET record_json=%s "
                    "WHERE tenant_id=%s AND event_id=%s",
                    (dumps(raw), TENANT, str(event_id)),
                )
                db.execute(
                    "ALTER TABLE shadow_evaluations "
                    "ENABLE TRIGGER shadow_evaluations_immutable"
                )

            corrupted_counts, corrupted_rows = counts(), source_rows()
            with pytest.raises(CaseSourceUnavailable):
                in_transaction_reader.read(
                    principal=principal(caps=READ), tenant_id=TENANT,
                    case_id=case_id, at=datetime.now(UTC),
                )
            # No projection, hidden foreign-tenant row, extra audit or write.
            assert counts() == corrupted_counts
            assert source_rows() == corrupted_rows
            assert all(row["bank_execution"] == "unknown" for row in db.execute(
                "SELECT bank_execution FROM analyst_case_events"
            ).fetchall())
        finally:
            db.execute("ROLLBACK TO SAVEPOINT synthetic_reader_corruption")
            db.execute("RELEASE SAVEPOINT synthetic_reader_corruption")
        assert counts() == original_counts
        assert source_rows() == original_rows
    assert reader.read(
        principal=principal(caps=READ), tenant_id=TENANT,
        case_id=case_id, at=datetime.now(UTC),
    ) == baseline
