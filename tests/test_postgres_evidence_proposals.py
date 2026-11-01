"""Real PostgreSQL #49 proposal persistence; synthetic-only authority/fixtures."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from gasha.poc.evidence_identity import EvidenceBinding, EvidencePacket, EvidenceRecord
from gasha.poc.evidence_lifecycle import EvidenceAction, LifecycleRejected
from gasha.poc.postgres_evidence_proposals import (
    EvidenceLedgerRejected,
    PostgresEvidenceProposalLedger,
)
from gasha.poc.readiness import EvidenceArea, Stage
from gasha.security.access import AuthorizationRejected, Capability, TrustedPrincipal

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
NOW = datetime(2026, 11, 1, 1, tzinfo=UTC)


def principal(name: str, capability: Capability, *, tenant: str = "bank-a") -> TrustedPrincipal:
    return TrustedPrincipal(
        subject=name, issuer="synthetic-issuer", credential_ref="synthetic-credential",
        tenant_ids=frozenset({tenant}), capabilities=frozenset({capability}),
        expires_at=NOW + timedelta(days=1),
    )


COLLECTOR = principal("collector", Capability.EVIDENCE_SUBMIT)
VERIFIER = principal("verifier", Capability.EVIDENCE_VERIFY)
APPROVER = principal("approver", Capability.STAGE_APPROVE)
REVOKER = principal("revoker", Capability.EVIDENCE_REVOKE)


class ArtifactReader:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.calls = 0
        self.mismatch = mismatch

    def sha256_digest(self, record: EvidenceRecord) -> str:
        self.calls += 1
        return "sha256:" + "f" * 64 if self.mismatch else record.artifact_digest


def packet() -> EvidencePacket:
    binding = EvidenceBinding(
        tenant_id="bank-a", installation_id="synthetic-installation",
        stage=Stage.SHADOW, use_case="uc-01", commit_sha="a" * 40,
        image_digest="sha256:" + "b" * 64, dataset_digest="sha256:" + "c" * 64,
        config_version="cfg-1", policy_version="policy-1", rule_version="rule-1",
        signal_version="signal-1", adapter_version="adapter-1",
        window_start=NOW - timedelta(hours=2), window_end=NOW - timedelta(hours=1),
    )
    record = EvidenceRecord(
        evidence_id=UUID(int=1), binding=binding, area=EvidenceArea.SECURITY,
        artifact_ref="synthetic-artifact", artifact_digest="sha256:" + "d" * 64,
        source_system="synthetic-ci", collector_actor_ref=COLLECTOR.audit_actor,
        collected_at=NOW - timedelta(minutes=30), expires_at=NOW + timedelta(hours=1),
    )
    return EvidencePacket(binding, "evaluator-1", (record,))


def connect(schema_name: str):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
    connection.commit()
    return connection


@pytest.fixture
def schema():
    import psycopg
    from psycopg import sql

    name = "gasha_evidence_" + uuid4().hex[:14]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            with connect(name) as installation:
                for filename in (
                    "010_security_audit_events.sql",
                    "012_poc_evidence_proposal_ledger.sql",
                ):
                    installation.execute((MIGRATIONS / filename).read_text())
                installation.commit()
            yield name
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


def counts(connection) -> tuple[int, int, int]:
    a = connection.execute("SELECT COUNT(*) AS n FROM poc_evidence_packets").fetchone()["n"]
    b = connection.execute("SELECT COUNT(*) AS n FROM poc_evidence_events").fetchone()["n"]
    c = connection.execute("SELECT COUNT(*) AS n FROM security_audit_events").fetchone()["n"]
    connection.rollback()
    return a, b, c


def record(
    ledger: PostgresEvidenceProposalLedger,
    item: EvidencePacket,
    actor: TrustedPrincipal,
    action: EvidenceAction,
    revision: int,
    reader: ArtifactReader | None = None,
):
    return ledger.apply(
        item, principal=actor, action=action, now=NOW, expected_revision=revision,
        evidence_id=item.records[0].evidence_id if action in (
            EvidenceAction.SUBMIT, EvidenceAction.VERIFY, EvidenceAction.REVOKE_EVIDENCE
        ) else None,
        artifact_reader=reader,
    )


def test_durable_submit_verify_approve_revoke_and_redacted_atomic_audit(schema) -> None:
    item = packet()
    with connect(schema) as connection:
        ledger = PostgresEvidenceProposalLedger(connection)
        for revision, (actor, action) in enumerate((
            (COLLECTOR, EvidenceAction.SUBMIT),
            (VERIFIER, EvidenceAction.VERIFY),
            (APPROVER, EvidenceAction.APPROVE),
            (REVOKER, EvidenceAction.REVOKE_EVIDENCE),
        )):
            result = record(ledger, item, actor, action, revision, ArtifactReader())
            assert len(result.events) == revision + 1
            assert counts(connection) == (1, revision + 1, revision + 1)
        with pytest.raises(LifecycleRejected, match="no active approval"):
            ledger.apply(
                item, principal=principal("other", Capability.APPROVAL_REVOKE),
                action=EvidenceAction.REVOKE_APPROVAL, now=NOW, expected_revision=4,
            )
        assert counts(connection) == (1, 4, 4)
        audits = connection.execute(
            "SELECT action, actor_ref, tenant_ref, event_ref, context_ref, attempt_ref "
            "FROM security_audit_events ORDER BY id"
        ).fetchall()
        assert [r["action"] for r in audits] == [
            "evidence.submit", "evidence.verify", "evidence.approve",
            "evidence.revoke_evidence",
        ]
        assert all(len(r["actor_ref"]) == 64 for r in audits)
        assert all(len(r["tenant_ref"]) == 64 for r in audits)
        assert all(len(r["event_ref"]) == 64 for r in audits)
        assert all(len(r["context_ref"]) == 64 for r in audits)
        assert all(len(r["attempt_ref"]) == 32 for r in audits)
        assert "bank-a" not in str(audits)
        assert "synthetic-credential" not in str(audits)


def test_denied_tenant_capability_stale_and_reader_failure_leave_no_new_writes(schema):
    item = packet()
    with connect(schema) as connection:
        ledger = PostgresEvidenceProposalLedger(connection)
        for actor in (
            principal("wrong-tenant", Capability.EVIDENCE_SUBMIT, tenant="bank-b"),
            principal("wrong-capability", Capability.STAGE_APPROVE),
        ):
            with pytest.raises(AuthorizationRejected):
                record(ledger, item, actor, EvidenceAction.SUBMIT, 0)
        assert counts(connection) == (0, 0, 0)
        record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        reader = ArtifactReader(mismatch=True)
        with pytest.raises(LifecycleRejected, match="digest mismatch"):
            record(ledger, item, VERIFIER, EvidenceAction.VERIFY, 1, reader)
        assert reader.calls == 1
        with pytest.raises(EvidenceLedgerRejected, match="stale"):
            record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        assert counts(connection) == (1, 1, 1)


def test_audit_failure_rolls_back_evidence_packet_and_retry_succeeds(schema):
    item = packet()
    with connect(schema) as connection:
        connection.execute("""
            CREATE FUNCTION deny_evidence_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic audit outage'; END; $$;
            CREATE TRIGGER deny_evidence_audit_insert
            BEFORE INSERT ON security_audit_events
            FOR EACH ROW EXECUTE FUNCTION deny_evidence_audit();
        """)
        connection.commit()
        ledger = PostgresEvidenceProposalLedger(connection)
        with pytest.raises(Exception, match="synthetic audit outage"):
            record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        assert counts(connection) == (0, 0, 0)
        connection.execute("DROP TRIGGER deny_evidence_audit_insert ON security_audit_events")
        connection.commit()
        record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        assert counts(connection) == (1, 1, 1)


def test_append_only_triggers_and_stored_identity_tampering_fail_closed(schema):
    item = packet()
    with connect(schema) as connection:
        ledger = PostgresEvidenceProposalLedger(connection)
        record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        with pytest.raises(Exception, match="append-only"):
            connection.execute("DELETE FROM poc_evidence_events")
        connection.rollback()
        with pytest.raises(Exception, match="append-only"):
            connection.execute("UPDATE poc_evidence_packets SET packet_json = '{}'::jsonb")
        connection.rollback()
        # Deliberately bypass the application-role trigger as a migrator would:
        # replay still detects a corrupted stored identity before another insert.
        connection.execute("ALTER TABLE poc_evidence_packets DISABLE TRIGGER "
                           "poc_evidence_packet_immutable")
        connection.execute("UPDATE poc_evidence_packets SET packet_json = '{}'::jsonb")
        connection.execute("ALTER TABLE poc_evidence_packets ENABLE TRIGGER "
                           "poc_evidence_packet_immutable")
        connection.commit()
        reader = ArtifactReader()
        with pytest.raises(EvidenceLedgerRejected, match="identity mismatch"):
            record(ledger, item, VERIFIER, EvidenceAction.VERIFY, 1, reader)
        assert reader.calls == 0
        assert counts(connection) == (1, 1, 1)


def test_changed_packet_cannot_reuse_another_scope_or_revision(schema):
    item = packet()
    with connect(schema) as connection:
        ledger = PostgresEvidenceProposalLedger(connection)
        record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        changed_binding = replace(item.binding, policy_version="policy-v2")
        changed_record = replace(item.records[0], binding=changed_binding)
        changed = EvidencePacket(changed_binding, item.evaluator_version, (changed_record,))
        with pytest.raises(LifecycleRejected, match="submission"):
            record(ledger, changed, VERIFIER, EvidenceAction.VERIFY, 0, ArtifactReader())
        assert counts(connection) == (1, 1, 1)


def test_two_independent_connections_cannot_append_same_revision(schema):
    item = packet()

    def attempt(_index: int) -> str:
        with connect(schema) as connection:
            try:
                record(PostgresEvidenceProposalLedger(connection), item,
                       COLLECTOR, EvidenceAction.SUBMIT, 0)
                return "accepted"
            except EvidenceLedgerRejected:
                return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (0, 1)))
    assert sorted(outcomes) == ["accepted", "stale"]
    with connect(schema) as connection:
        assert counts(connection) == (1, 1, 1)
