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


def make_ledger(connection, schema: str) -> PostgresEvidenceProposalLedger:
    return PostgresEvidenceProposalLedger(
        connection, installation_schema=schema,
        tenant_id="bank-a", installation_id="synthetic-installation",
    )


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
        ledger = make_ledger(connection, schema)
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
        ledger = make_ledger(connection, schema)
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
        ledger = make_ledger(connection, schema)
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
        ledger = make_ledger(connection, schema)
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
        ledger = make_ledger(connection, schema)
        record(ledger, item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        changed_binding = replace(item.binding, policy_version="policy-v2")
        changed_record = replace(item.records[0], binding=changed_binding)
        changed = EvidencePacket(changed_binding, item.evaluator_version, (changed_record,))
        with pytest.raises(LifecycleRejected, match="invalid independent verification"):
            record(ledger, changed, VERIFIER, EvidenceAction.VERIFY, 0, ArtifactReader())
        assert counts(connection) == (1, 1, 1)


def test_two_independent_connections_cannot_append_same_revision(schema):
    item = packet()

    def attempt(_index: int) -> str:
        with connect(schema) as connection:
            try:
                record(make_ledger(connection, schema), item,
                       COLLECTOR, EvidenceAction.SUBMIT, 0)
                return "accepted"
            except EvidenceLedgerRejected:
                return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (0, 1)))
    assert sorted(outcomes) == ["accepted", "stale"]
    with connect(schema) as connection:
        assert counts(connection) == (1, 1, 1)


# Real non-superuser role tests. These intentionally use separate authenticated
# connections, NOT SET ROLE on the migration/superuser connection.
@pytest.fixture
def scoped_roles():
    import psycopg
    from psycopg import sql

    suffix = uuid4().hex[:12]
    installs = (
        ("gasha_role_a_" + suffix, "gasha_aw_" + suffix,
         "gasha_ar_" + suffix, "gasha_am_" + suffix),
        ("gasha_role_b_" + suffix, "gasha_bw_" + suffix,
         "gasha_br_" + suffix, "gasha_bm_" + suffix),
    )
    with psycopg.connect(DSN, autocommit=True) as admin:
        try:
            for schema_name, writer, reader, migrator_role in installs:
                # Distinct login identities: schema owner/migrator, runtime
                # writer, and read-only reader; no runtime role owns DDL.
                for role_name in (migrator_role, writer, reader):
                    admin.execute(
                        sql.SQL(
                            "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER "
                            "NOCREATEDB NOCREATEROLE NOINHERIT"
                        ).format(
                            sql.Identifier(role_name), sql.Literal("synthetic_ci_role_only"),
                        )
                    )
                admin.execute(
                    sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(
                        sql.Identifier(schema_name), sql.Identifier(migrator_role),
                    )
                )
                with restricted_connect(migrator_role) as migrator:
                    assert migrator.execute(
                        "SELECT current_user AS who"
                    ).fetchone()["who"] == migrator_role
                    migrator.execute(
                        sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name))
                    )
                    for filename in (
                        "010_security_audit_events.sql",
                        "012_poc_evidence_proposal_ledger.sql",
                    ):
                        migrator.execute((MIGRATIONS / filename).read_text())
                    migrator.execute(
                        "CREATE TABLE private_installation_control (id INTEGER NOT NULL)"
                    )
                    migrator.commit()
                admin.execute(
                    sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(
                        sql.Identifier(schema_name)
                    )
                )
                admin.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA {} TO {}, {}").format(
                        sql.Identifier(schema_name), sql.Identifier(writer),
                        sql.Identifier(reader),
                    )
                )
                admin.execute(
                    sql.SQL(
                        "GRANT SELECT, INSERT ON TABLE {}.poc_evidence_packets, "
                        "{}.poc_evidence_events TO {}"
                    ).format(
                        sql.Identifier(schema_name), sql.Identifier(schema_name),
                        sql.Identifier(writer),
                    )
                )
                admin.execute(
                    sql.SQL("GRANT INSERT ON TABLE {}.security_audit_events TO {}").format(
                        sql.Identifier(schema_name), sql.Identifier(writer),
                    )
                )
                admin.execute(
                    sql.SQL(
                        "GRANT SELECT ON TABLE {}.poc_evidence_packets, "
                        "{}.poc_evidence_events, {}.security_audit_events TO {}"
                    ).format(
                        sql.Identifier(schema_name), sql.Identifier(schema_name),
                        sql.Identifier(schema_name), sql.Identifier(reader),
                    )
                )
            yield installs
        finally:
            for schema_name, _, _, _ in installs:
                admin.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                        sql.Identifier(schema_name)
                    )
                )
            for _, writer, reader, migrator_role in installs:
                for role_name in (writer, reader, migrator_role):
                    admin.execute(
                        sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_name))
                    )


def restricted_connect(role_name: str):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    return psycopg.connect(
        make_conninfo(DSN, user=role_name, password="synthetic_ci_role_only"),
        row_factory=dict_row,
    )


def assert_sql_denied(connection, statement: str) -> None:
    import psycopg

    with pytest.raises(psycopg.Error) as exc:
        connection.execute(statement)
    assert exc.value.sqlstate in {"42501", "42P01"}, exc.value.sqlstate
    connection.rollback()


def test_restricted_role_lifecycle_and_reader_isolation(scoped_roles):
    (schema_a, writer_a, reader_a, migrator_a), (schema_b, writer_b, _, _) = scoped_roles
    item = packet()
    with restricted_connect(writer_a) as connection:
        assert connection.execute("SELECT current_user").fetchone()["current_user"] == writer_a
        attributes = connection.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles "
            "WHERE rolname = current_user"
        ).fetchone()
        assert attributes == {
            "rolsuper": False, "rolcreatedb": False, "rolcreaterole": False,
        }
        assert_sql_denied(connection, f'SET ROLE "{migrator_a}"')
        runtime = make_ledger(connection, schema_a)
        for revision, (actor, action) in enumerate((
            (COLLECTOR, EvidenceAction.SUBMIT),
            (VERIFIER, EvidenceAction.VERIFY),
            (APPROVER, EvidenceAction.APPROVE),
            (REVOKER, EvidenceAction.REVOKE_EVIDENCE),
        )):
            result = record(runtime, item, actor, action, revision, ArtifactReader())
            assert len(result.events) == revision + 1
        # Caller-supplied scope must not override the installed schema binding.
        changed_binding = replace(item.binding, installation_id="another-installation")
        changed = EvidencePacket(
            changed_binding, item.evaluator_version,
            (replace(item.records[0], binding=changed_binding),),
        )
        with pytest.raises(EvidenceLedgerRejected, match="installation scope"):
            record(runtime, changed, COLLECTOR, EvidenceAction.SUBMIT, 0)
        assert_sql_denied(
            connection,
            f'SELECT packet_json FROM "{schema_a}".poc_evidence_packets FOR UPDATE',
        )
        assert_sql_denied(
            connection, f'SELECT * FROM "{schema_a}".security_audit_events',
        )
        for statement in (
            f'SELECT COUNT(*) FROM "{schema_b}".poc_evidence_packets',
            f'SELECT * FROM "{schema_b}".poc_evidence_packets FOR UPDATE',
            f'LOCK TABLE "{schema_b}".poc_evidence_events IN SHARE MODE',
            f'INSERT INTO "{schema_b}".poc_evidence_packets (tenant_id) VALUES (\'x\')',
        ):
            assert_sql_denied(connection, statement)
    with connect(schema_a) as admin:
        assert counts(admin) == (1, 4, 4)
    with restricted_connect(reader_a) as connection:
        assert connection.execute(
            f'SELECT COUNT(*) AS n FROM "{schema_a}".poc_evidence_events'
        ).fetchone()["n"] == 4
        for statement in (
            f'SELECT packet_json FROM "{schema_a}".poc_evidence_packets FOR UPDATE',
            f'INSERT INTO "{schema_a}".poc_evidence_packets (tenant_id) VALUES (\'x\')',
            f'DELETE FROM "{schema_a}".poc_evidence_events',
            f'SELECT COUNT(*) FROM "{schema_b}".poc_evidence_packets',
        ):
            assert_sql_denied(connection, statement)
    # A distinct installation writer cannot read A by changing its search_path.
    with restricted_connect(writer_b) as connection:
        connection.execute(f'SET search_path TO "{schema_a}"')
        connection.commit()
        assert_sql_denied(
            connection, f'SELECT COUNT(*) FROM "{schema_a}".poc_evidence_packets'
        )


def test_restricted_writer_cannot_mutate_schema_or_triggers(scoped_roles):
    (schema_a, writer_a, _, migrator_a), _ = scoped_roles
    item = packet()
    with restricted_connect(writer_a) as connection:
        record(make_ledger(connection, schema_a), item, COLLECTOR, EvidenceAction.SUBMIT, 0)
        for table in ("poc_evidence_packets", "poc_evidence_events", "security_audit_events"):
            for command in (
                f'UPDATE "{schema_a}".{table} SET tenant_id = \'bank-b\''
                if table != "security_audit_events" else
                f'UPDATE "{schema_a}".{table} SET reason = \'forged\'',
                f'DELETE FROM "{schema_a}".{table}',
                f'TRUNCATE "{schema_a}".{table}',
                f'ALTER TABLE "{schema_a}".{table} DISABLE TRIGGER ALL',
                f'DROP TABLE "{schema_a}".{table}',
            ):
                assert_sql_denied(connection, command)
        for command in (
            f'CREATE TABLE "{schema_a}".forged_evidence (id int)',
            f'DROP FUNCTION "{schema_a}".reject_poc_evidence_mutation()',
            f'INSERT INTO "{schema_a}".private_installation_control (id) VALUES (1)',
            f'SELECT * FROM "{schema_a}".private_installation_control',
            f'SET ROLE "{migrator_a}"',
            (f'CREATE OR REPLACE FUNCTION "{schema_a}".reject_poc_evidence_mutation() '
             "RETURNS trigger LANGUAGE plpgsql AS $body$BEGIN RETURN NEW; END;$body$"),
        ):
            assert_sql_denied(connection, command)
    with connect(schema_a) as admin:
        assert counts(admin) == (1, 1, 1)


def test_restricted_runtime_search_path_and_temp_shadows_do_not_redirect(scoped_roles):
    (schema_a, writer_a, _, _), _ = scoped_roles
    with restricted_connect(writer_a) as connection:
        connection.execute("CREATE TEMP TABLE poc_evidence_packets (forged int)")
        connection.execute("CREATE TEMP TABLE poc_evidence_events (forged int)")
        connection.execute("CREATE TEMP TABLE security_audit_events (forged int)")
        connection.execute("SET search_path TO pg_temp, public")
        connection.commit()
        record(
            make_ledger(connection, schema_a), packet(),
            COLLECTOR, EvidenceAction.SUBMIT, 0,
        )
        assert connection.execute(
            "SELECT COUNT(*) AS n FROM pg_temp.poc_evidence_packets"
        ).fetchone()["n"] == 0
        assert connection.execute(
            "SELECT COUNT(*) AS n FROM pg_temp.security_audit_events"
        ).fetchone()["n"] == 0
        connection.rollback()
    with connect(schema_a) as admin:
        assert counts(admin) == (1, 1, 1)


def test_restricted_role_two_writer_revision_race(scoped_roles):
    (schema_a, writer_a, _, _), _ = scoped_roles
    item = packet()
    with restricted_connect(writer_a) as connection:
        record(make_ledger(connection, schema_a), item, COLLECTOR, EvidenceAction.SUBMIT, 0)

    def attempt(_index: int) -> str:
        with restricted_connect(writer_a) as connection:
            try:
                record(
                    make_ledger(connection, schema_a), item, VERIFIER,
                    EvidenceAction.VERIFY, 1, ArtifactReader(),
                )
                return "accepted"
            except EvidenceLedgerRejected:
                return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (0, 1)))
    assert sorted(outcomes) == ["accepted", "stale"]
    with connect(schema_a) as admin:
        assert counts(admin) == (1, 2, 2)


def test_restricted_role_audit_failure_rolls_back_packet_and_event(scoped_roles):
    (schema_a, writer_a, _, _), _ = scoped_roles
    import psycopg
    from psycopg import sql

    with connect(schema_a) as migrator:
        migrator.execute(sql.SQL(
            "CREATE FUNCTION {}.deny_restricted_audit() RETURNS trigger "
            "LANGUAGE plpgsql AS $$BEGIN "
            "RAISE EXCEPTION 'synthetic restricted audit outage'; END;$$"
        ).format(sql.Identifier(schema_a)))
        migrator.execute(sql.SQL(
            "CREATE TRIGGER deny_restricted_audit_insert "
            "BEFORE INSERT ON {}.security_audit_events "
            "FOR EACH ROW EXECUTE FUNCTION {}.deny_restricted_audit()"
        ).format(sql.Identifier(schema_a), sql.Identifier(schema_a)))
        migrator.commit()
    with (
        restricted_connect(writer_a) as connection,
        pytest.raises(psycopg.Error, match="synthetic restricted audit outage"),
    ):
        record(make_ledger(connection, schema_a), packet(), COLLECTOR,
               EvidenceAction.SUBMIT, 0)
    with connect(schema_a) as admin:
        assert counts(admin) == (0, 0, 0)
        admin.execute(sql.SQL(
            "DROP TRIGGER deny_restricted_audit_insert ON {}.security_audit_events"
        ).format(sql.Identifier(schema_a)))
        admin.commit()
    with restricted_connect(writer_a) as connection:
        record(make_ledger(connection, schema_a), packet(), COLLECTOR,
               EvidenceAction.SUBMIT, 0)
    with connect(schema_a) as admin:
        assert counts(admin) == (1, 1, 1)
