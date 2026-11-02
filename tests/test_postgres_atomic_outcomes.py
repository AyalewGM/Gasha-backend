"""#42/#43 inactive PostgreSQL atomic outcome + redacted audit negatives.

These use synthetic identities in an isolated schema; they do not test a bank
IdP, signed source evidence, protected HTTP activation or bank payment action.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from gasha.ingestion.outcome_ingestion import (
    IncumbentOutcomeRecord,
    SubmissionStatus,
)
from gasha.ingestion.postgres_atomic_outcomes import (
    AtomicOutcomeRejected,
    PostgresAtomicOutcomeWriter,
)
from gasha.poc.outcomes import IncumbentControlOutcome, OutcomeRecord, OutcomeType
from gasha.security.access import Capability, TrustedPrincipal

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
NOW = datetime(2026, 11, 2, 3, tzinfo=UTC)
EVENT_ID = UUID(int=42)


def principal(
    capability: Capability, *, tenant: str = "bank-a",
    expires_at: datetime | None = None,
) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-operator", issuer="synthetic-issuer",
        credential_ref="synthetic-credential", tenant_ids=frozenset({tenant}),
        capabilities=frozenset({capability}),
        expires_at=expires_at or NOW + timedelta(days=1),
    )


def outcome(value: OutcomeType = OutcomeType.CONFIRMED_FRAUD) -> OutcomeRecord:
    return OutcomeRecord(
        tenant_id="bank-a", event_id=EVENT_ID, outcome=value,
        outcome_source="synthetic-case-system", outcome_version="1",
        confirmed_at=NOW - timedelta(minutes=1),
    )


def incumbent() -> IncumbentOutcomeRecord:
    return IncumbentOutcomeRecord(
        tenant_id="bank-a", event_id=EVENT_ID,
        outcome=IncumbentControlOutcome.ALERT, source_system="synthetic-control",
        recorded_at=NOW - timedelta(minutes=1),
    )


def connect(schema: str):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
    connection.commit()
    return connection


@pytest.fixture
def schema():
    import psycopg
    from psycopg import sql

    name = "gasha_atomic_" + uuid4().hex[:15]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            with connect(name) as connection:
                # The Bank migrator must supply the trusted installation
                # schema in the same transaction; session search_path alone
                # must never choose the destination of migration 013.
                connection.execute(
                    "SELECT set_config('gasha.installation_schema', %s, true)",
                    (name,),
                )
                for filename in (
                    "010_security_audit_events.sql",
                    "013_poc_atomic_outcomes.sql",
                ):
                    connection.execute((MIGRATIONS / filename).read_text())
                connection.commit()
            yield name
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


def writer(connection, schema: str) -> PostgresAtomicOutcomeWriter:
    return PostgresAtomicOutcomeWriter(
        connection, installation_schema=schema, tenant_id="bank-a",
    )


def counts(connection) -> tuple[int, int]:
    outcomes = connection.execute(
        "SELECT COUNT(*) AS n FROM poc_atomic_outcomes"
    ).fetchone()["n"]
    audit = connection.execute(
        "SELECT COUNT(*) AS n FROM security_audit_events"
    ).fetchone()["n"]
    connection.rollback()
    return int(outcomes), int(audit)


def test_atomic_accept_duplicate_and_append_correction(schema: str) -> None:
    with connect(schema) as connection:
        service = writer(connection, schema)
        identity = principal(Capability.OUTCOME_SUBMIT)
        accepted = service.submit(outcome(), principal=identity, now=NOW)
        assert accepted.status is SubmissionStatus.ACCEPTED
        assert len(accepted.history) == 1
        same = service.submit(outcome(), principal=identity, now=NOW)
        assert same.status is SubmissionStatus.DUPLICATE
        assert len(same.history) == 1
        corrected = service.submit(
            outcome(OutcomeType.CONFIRMED_LEGITIMATE), principal=identity, now=NOW,
        )
        assert corrected.status is SubmissionStatus.ACCEPTED
        assert [r.outcome for r in corrected.history] == [
            OutcomeType.CONFIRMED_FRAUD, OutcomeType.CONFIRMED_LEGITIMATE,
        ]
        assert counts(connection) == (2, 3)
        events = connection.execute(
            "SELECT action, result, reason, actor_ref, tenant_ref, event_ref "
            "FROM security_audit_events ORDER BY id"
        ).fetchall()
        assert [r["reason"] for r in events] == [
            "outcome_accepted", "outcome_duplicate", "outcome_accepted",
        ]
        assert all(r["action"] == "outcome.submit" and r["result"] == "succeeded"
                   and r["actor_ref"] == identity.audit_actor
                   and len(r["tenant_ref"]) == 64 and len(r["event_ref"]) == 64
                   for r in events)


def test_equivalent_utc_instants_are_idempotent_across_source_offsets(
    schema: str,
) -> None:
    with connect(schema) as connection:
        service = writer(connection, schema)
        gasha = outcome()
        assert gasha.confirmed_at is not None
        offset_gasha = gasha.model_copy(update={
            "confirmed_at": gasha.confirmed_at.astimezone(timezone(timedelta(hours=-5)))
        })
        identity = principal(Capability.OUTCOME_SUBMIT)
        assert service.submit(gasha, principal=identity, now=NOW).status is SubmissionStatus.ACCEPTED
        assert (
            service.submit(offset_gasha, principal=identity, now=NOW).status
            is SubmissionStatus.DUPLICATE
        )
        bank = incumbent()
        offset_bank = bank.model_copy(update={
            "recorded_at": bank.recorded_at.astimezone(timezone(timedelta(hours=7)))
        })
        incumbent_id = principal(Capability.INCUMBENT_OUTCOME_SUBMIT)
        assert (
            service.submit_incumbent(bank, principal=incumbent_id, now=NOW).status
            is SubmissionStatus.ACCEPTED
        )
        assert (
            service.submit_incumbent(
                offset_bank, principal=incumbent_id, now=NOW
            ).status is SubmissionStatus.DUPLICATE
        )
        assert counts(connection) == (2, 4)


def test_incumbent_path_is_distinct_and_capability_scoped(schema: str) -> None:
    with connect(schema) as connection:
        service = writer(connection, schema)
        identity = principal(Capability.INCUMBENT_OUTCOME_SUBMIT)
        accepted = service.submit_incumbent(incumbent(), principal=identity, now=NOW)
        assert accepted.status is SubmissionStatus.ACCEPTED
        assert len(accepted.incumbent_history) == 1
        assert not accepted.history
        assert service.submit_incumbent(
            incumbent(), principal=identity, now=NOW
        ).status is SubmissionStatus.DUPLICATE
        with pytest.raises(AtomicOutcomeRejected, match="tenant/capability denied"):
            service.submit(outcome(), principal=identity, now=NOW)
        assert counts(connection) == (1, 2)


@pytest.mark.parametrize("reason", [
    "wrong_tenant", "wrong_role", "expired", "future_outcome",
    "invalid_source", "wrong_installation_tenant",
])
def test_denials_have_no_outcome_or_terminal_success_audit(
    schema: str, reason: str
) -> None:
    with connect(schema) as connection:
        service = writer(connection, schema)
        identity = principal(Capability.OUTCOME_SUBMIT)
        record = outcome()
        if reason == "wrong_tenant":
            identity = principal(Capability.OUTCOME_SUBMIT, tenant="bank-b")
        elif reason == "wrong_role":
            identity = principal(Capability.DECISION_SUBMIT)
        elif reason == "expired":
            identity = principal(Capability.OUTCOME_SUBMIT, expires_at=NOW)
        elif reason == "future_outcome":
            record = record.model_copy(
                update={"confirmed_at": NOW + timedelta(seconds=1)}
            )
        elif reason == "invalid_source":
            record = record.model_copy(update={"outcome_source": "raw customer PII"})
        elif reason == "wrong_installation_tenant":
            record = record.model_copy(update={"tenant_id": "bank-b"})
        with pytest.raises(AtomicOutcomeRejected):
            service.submit(record, principal=identity, now=NOW)
        assert counts(connection) == (0, 0)


def test_terminal_audit_failure_rolls_back_insert(schema: str) -> None:
    with connect(schema) as connection:
        connection.execute("DROP TABLE security_audit_events")
        connection.commit()
        with pytest.raises(Exception, match="security_audit_events"):
            writer(connection, schema).submit(
                outcome(), principal=principal(Capability.OUTCOME_SUBMIT), now=NOW,
            )
        remaining = connection.execute(
            "SELECT COUNT(*) AS n FROM poc_atomic_outcomes"
        ).fetchone()["n"]
        assert remaining == 0


def test_corrupt_history_rejected_and_no_new_audit(schema: str) -> None:
    with connect(schema) as connection:
        service = writer(connection, schema)
        identity = principal(Capability.OUTCOME_SUBMIT)
        service.submit(outcome(), principal=identity, now=NOW)
        # Simulate privileged storage tamper. The runtime writer itself has
        # no update/delete capability, and the table trigger blocks normal use.
        connection.execute(
            "ALTER TABLE poc_atomic_outcomes DISABLE TRIGGER "
            "poc_atomic_outcomes_immutable"
        )
        connection.execute(
            "UPDATE poc_atomic_outcomes SET record_json = "
            "jsonb_set(record_json, '{event_id}', '\"00000000-0000-0000-0000-000000000043\"')"
        )
        connection.execute(
            "ALTER TABLE poc_atomic_outcomes ENABLE TRIGGER "
            "poc_atomic_outcomes_immutable"
        )
        connection.commit()
        with pytest.raises(AtomicOutcomeRejected, match="stored outcome integrity"):
            service.submit(outcome(), principal=identity, now=NOW)
        assert counts(connection) == (1, 1)


def test_append_only_outcome_table_blocks_update_and_delete(schema: str) -> None:
    with connect(schema) as connection:
        writer(connection, schema).submit(
            outcome(), principal=principal(Capability.OUTCOME_SUBMIT), now=NOW,
        )
        for sql in (
            "UPDATE poc_atomic_outcomes SET tenant_id = 'bank-b'",
            "DELETE FROM poc_atomic_outcomes",
        ):
            with pytest.raises(Exception, match="append-only"):
                connection.execute(sql)
            connection.rollback()
        assert counts(connection) == (1, 1)


def test_concurrent_duplicate_has_one_record_and_two_terminal_audits(
    schema: str
) -> None:
    def submit_one() -> SubmissionStatus:
        with connect(schema) as connection:
            return writer(connection, schema).submit(
                outcome(), principal=principal(Capability.OUTCOME_SUBMIT), now=NOW,
            ).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _: submit_one(), range(2)))
    assert sorted(statuses) == [
        SubmissionStatus.ACCEPTED, SubmissionStatus.DUPLICATE,
    ]
    with connect(schema) as connection:
        assert counts(connection) == (1, 2)


def test_constructor_requires_opaque_installation_scope(schema: str) -> None:
    with connect(schema) as connection:
        for bad in ("", "../public", "public;DROP", "MixedCase", "0invalid"):
            with pytest.raises(AtomicOutcomeRejected):
                PostgresAtomicOutcomeWriter(
                    connection, installation_schema=bad, tenant_id="bank-a"
                )
        with pytest.raises(AtomicOutcomeRejected):
            PostgresAtomicOutcomeWriter(
                connection, installation_schema=schema, tenant_id="bad tenant"
            )



@pytest.mark.parametrize("untrusted_schema", [
    None, "", "public", "information_schema", "pg_catalog",
    "pg_temp_7", "../public", "MixedCase", "schema;DROP",
])
def test_migration_fails_without_canonical_trusted_installation_schema(
    schema: str, untrusted_schema: str | None,
) -> None:
    # A prior (legitimate) installation does not waive the requirement on
    # repeated migration attempts. A bad search_path is not authority.
    with connect(schema) as connection:
        if untrusted_schema is not None:
            connection.execute(
                "SELECT set_config('gasha.installation_schema', %s, true)",
                (untrusted_schema,),
            )
        with pytest.raises(Exception, match="trusted installation schema"):
            connection.execute(
                (MIGRATIONS / "013_poc_atomic_outcomes.sql").read_text()
            )
        connection.rollback()


def test_migration_ignores_hostile_earlier_search_path_schema(
    schema: str,
) -> None:
    import psycopg
    from psycopg import sql

    hostile = "gasha_spoof_" + uuid4().hex[:15]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(hostile))
        )
        try:
            with connect(schema) as connection:
                connection.execute(
                    sql.SQL("SET search_path TO {}, {}").format(
                        sql.Identifier(hostile), sql.Identifier(schema)
                    )
                )
                connection.execute(
                    "SELECT set_config('gasha.installation_schema', %s, true)",
                    (schema,),
                )
                connection.execute(
                    (MIGRATIONS / "013_poc_atomic_outcomes.sql").read_text()
                )
                # Assert inside the transaction, before SET LOCAL resets.
                assert connection.execute(
                    "SELECT current_schema() AS name"
                ).fetchone()["name"] == schema
                redirected = connection.execute(
                    """SELECT count(*) AS n FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = %s AND c.relname = 'poc_atomic_outcomes'""",
                    (hostile,),
                ).fetchone()["n"]
                redirected_function = connection.execute(
                    """SELECT count(*) AS n FROM pg_catalog.pg_proc p
                    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                    WHERE n.nspname = %s
                      AND p.proname = 'reject_poc_atomic_outcome_mutation'""",
                    (hostile,),
                ).fetchone()["n"]
                assert redirected == 0
                assert redirected_function == 0
                connection.commit()
            with connect(schema) as connection:
                accepted = writer(connection, schema).submit(
                    outcome(), principal=principal(Capability.OUTCOME_SUBMIT),
                    now=NOW,
                )
                assert accepted.status is SubmissionStatus.ACCEPTED
                assert counts(connection) == (1, 1)
        finally:
            admin.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(hostile))
            )
