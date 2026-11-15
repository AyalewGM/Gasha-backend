"""#147 installed PostgreSQL tenant configuration store: synthetic only.

Isolated schemas and real PG transactions exercise the store. They are not
bank credentials, a provisioning authority, or protected-route activation.
Skipped unless GASHA_TEST_POSTGRES_DSN is set.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from gasha.configuration.kernel import (
    ConfigKind,
    ConfigLifecycle,
    TenantConfigRejected,
)
from gasha.configuration.postgres_repository import (
    PostgresTenantConfigurationService,
)

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="GASHA_TEST_POSTGRES_DSN not set")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
AT = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
PROVISIONER = "b" * 64
OTHER_PROVISIONER = "c" * 64

POLICY = {
    "configuration_version": "cfg-1",
    "policy_version": "policy-1",
    "rule_version": "rules-1",
    "model_version": None,
    "monitor_threshold": 0.5,
    "review_threshold": 0.7,
    "hold_threshold": 0.85,
    "block_threshold": 0.95,
}
POLICY_V2 = {**POLICY, "policy_version": "policy-2", "block_threshold": 0.97}
BUNDLE = {"journey": {"policy_version": "j-1", "window_minutes": 60}}


@pytest.fixture
def schema():
    import psycopg
    from psycopg import sql

    name = "gasha_config_" + uuid4().hex[:14]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            with connect(name) as installation:
                for version in (
                    "010_security_audit_events.sql",
                    "016_tenant_configurations.sql",
                ):
                    installation.execute((MIGRATIONS / version).read_text())
                installation.commit()
            yield name
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


def connect(schema_name):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
    connection.commit()
    return connection


def counts(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS n FROM tenant_configurations")
        rows = cursor.fetchone()["n"]
        cursor.execute("SELECT COUNT(*) AS n FROM security_audit_events")
        audits = cursor.fetchone()["n"]
    connection.rollback()
    return rows, audits


def draft(service, *, version_payload=POLICY, at=AT):
    return service.create_draft(
        provisioner_ref=PROVISIONER,
        tenant_id="tenant-a",
        config_kind=ConfigKind.DECISION_POLICY,
        payload=version_payload,
        at=at,
    )


def test_draft_activate_retire_lifecycle_with_atomic_audit(schema):
    with connect(schema) as connection:
        service = PostgresTenantConfigurationService(connection)
        entry = draft(service)
        assert entry.lifecycle is ConfigLifecycle.DRAFT
        assert entry.version == 1
        activated = service.activate(
            provisioner_ref=OTHER_PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=1),
        )
        assert activated.lifecycle is ConfigLifecycle.ACTIVE
        assert activated.activated_at == AT + timedelta(hours=1)
        resolved = service.resolve(
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=AT + timedelta(hours=2),
            horizon=AT + timedelta(hours=2),
        )
        assert resolved.version == 1
        assert resolved.content_digest == activated.content_digest
        retired = service.retire(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=3),
        )
        assert retired.lifecycle is ConfigLifecycle.RETIRED
        # One row, three lifecycle audit events — each atomic with its write.
        assert counts(connection) == (1, 3)


def test_activation_retires_incumbent_and_advances_resolution(schema):
    with connect(schema) as connection:
        service = PostgresTenantConfigurationService(connection)
        first = draft(service)
        service.activate(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=first.version,
            at=AT + timedelta(hours=1),
        )
        second = draft(service, version_payload=POLICY_V2)
        assert second.version == 2
        service.activate(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=second.version,
            at=AT + timedelta(hours=2),
        )
        current = service.resolve(
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=AT + timedelta(hours=3),
        )
        assert current.version == 2 and current.supersedes_version == 1
        past = service.resolve(
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=AT + timedelta(hours=1, minutes=30),
        )
        assert past.version == 1
        entries = service.entries(tenant_id="tenant-a", config_kind=ConfigKind.DECISION_POLICY)
        assert [e.lifecycle for e in entries] == [
            ConfigLifecycle.RETIRED,
            ConfigLifecycle.ACTIVE,
        ]


def test_identical_replay_avoids_duplicate_writes_and_audits(schema):
    with connect(schema) as connection:
        service = PostgresTenantConfigurationService(connection)
        draft(service)
        replay = draft(service)
        assert replay.version == 1  # same content draft, not a new version
        service.activate(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=1),
        )
        again = service.activate(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=1),
        )
        assert again.lifecycle is ConfigLifecycle.ACTIVE
        retired = service.retire(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=2),
        )
        re_retired = service.retire(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=2),
        )
        assert re_retired == retired
        # 1 row; 3 audits (draft + activate + retire), replays add none.
        assert counts(connection) == (1, 3)


def test_tenant_and_kind_isolation(schema):
    with connect(schema) as connection:
        service = PostgresTenantConfigurationService(connection)
        draft(service)
        service.activate(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=1,
            at=AT + timedelta(hours=1),
        )
        other = service.create_draft(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-b",
            config_kind=ConfigKind.DECISION_POLICY,
            payload=POLICY,
            at=AT,
        )
        assert other.version == 1  # independent version sequence per scope
        bundle = service.create_draft(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DETECTOR_POLICY_BUNDLE,
            payload=BUNDLE,
            at=AT,
        )
        assert bundle.version == 1
        with pytest.raises(TenantConfigRejected):
            service.resolve(
                tenant_id="tenant-b",
                config_kind=ConfigKind.DECISION_POLICY,
                at=AT + timedelta(hours=2),
            )
        with pytest.raises(TenantConfigRejected):
            service.resolve(
                tenant_id="tenant-a",
                config_kind=ConfigKind.DETECTOR_POLICY_BUNDLE,
                at=AT + timedelta(hours=2),
            )


def test_write_once_trigger_and_invalid_inputs(schema):
    import psycopg

    with connect(schema) as connection:
        service = PostgresTenantConfigurationService(connection)
        draft(service)
        with pytest.raises(psycopg.errors.RaiseException):
            with connection.cursor() as cursor:
                cursor.execute("UPDATE tenant_configurations SET content_json = '{}'::jsonb")
            connection.commit()
        connection.rollback()
        with pytest.raises(TenantConfigRejected):
            service.create_draft(
                provisioner_ref="not-hex",
                tenant_id="tenant-a",
                config_kind=ConfigKind.DECISION_POLICY,
                payload=POLICY,
                at=AT,
            )
        with pytest.raises(TenantConfigRejected):
            service.activate(
                provisioner_ref=PROVISIONER,
                tenant_id="tenant-a",
                config_kind=ConfigKind.DECISION_POLICY,
                version=9,
                at=AT,
            )
        with pytest.raises(TenantConfigRejected):
            service.activate(
                provisioner_ref=PROVISIONER,
                tenant_id="tenant-a",
                config_kind=ConfigKind.DECISION_POLICY,
                version="1",
                at=AT,
            )
        # Retiring a draft is invalid; activation must happen first.
        with pytest.raises(TenantConfigRejected):
            service.retire(
                provisioner_ref=PROVISIONER,
                tenant_id="tenant-a",
                config_kind=ConfigKind.DECISION_POLICY,
                version=1,
                at=AT,
            )



def test_autocommit_connection_is_rejected_before_any_write(schema):
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as connection:
        with pytest.raises(TenantConfigRejected, match="autocommit"):
            PostgresTenantConfigurationService(connection)


def test_failed_activation_audit_rolls_back_incumbent_retirement(schema):
    import psycopg

    with connect(schema) as connection:
        service = PostgresTenantConfigurationService(connection)
        first = draft(service)
        service.activate(
            provisioner_ref=PROVISIONER,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            version=first.version,
            at=AT + timedelta(hours=1),
        )
        second = draft(service, version_payload=POLICY_V2)
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE FUNCTION reject_config_activation_audit()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.action = 'tenant_config.activate' THEN
                        RAISE EXCEPTION 'simulated audit write failure';
                    END IF;
                    RETURN NEW;
                END $$
                """
            )
            cursor.execute(
                """
                CREATE TRIGGER reject_config_activation_audit_trigger
                BEFORE INSERT ON security_audit_events
                FOR EACH ROW EXECUTE FUNCTION reject_config_activation_audit()
                """
            )
        connection.commit()

        with pytest.raises(psycopg.errors.RaiseException):
            service.activate(
                provisioner_ref=PROVISIONER,
                tenant_id="tenant-a",
                config_kind=ConfigKind.DECISION_POLICY,
                version=second.version,
                at=AT + timedelta(hours=2),
            )
        entries = service.entries(
            tenant_id="tenant-a", config_kind=ConfigKind.DECISION_POLICY
        )
        assert [entry.lifecycle for entry in entries] == [
            ConfigLifecycle.ACTIVE, ConfigLifecycle.DRAFT
        ]
        assert counts(connection) == (2, 3)  # No orphan lifecycle or audit.


def test_two_schemas_each_install_content_immutability_trigger(schema):
    import psycopg
    from psycopg import sql

    second_schema = "gasha_config_" + uuid4().hex[:14]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(second_schema))
        )
        try:
            with connect(second_schema) as connection:
                for migration in (
                    "010_security_audit_events.sql",
                    "016_tenant_configurations.sql",
                ):
                    connection.execute((MIGRATIONS / migration).read_text())
                connection.commit()
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT n.nspname, count(*) AS n
                        FROM pg_trigger AS t
                        JOIN pg_class AS c ON c.oid = t.tgrelid
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE t.tgname = 'tenant_configurations_content_immutable'
                          AND n.nspname IN (%s, %s)
                        GROUP BY n.nspname
                        """,
                        (schema, second_schema),
                    )
                    found = {row["nspname"]: row["n"] for row in cursor.fetchall()}
                assert found == {schema: 1, second_schema: 1}
                service = PostgresTenantConfigurationService(connection)
                draft(service)
                with pytest.raises(psycopg.errors.RaiseException):
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "UPDATE tenant_configurations SET content_json = '{}'::jsonb"
                        )
                connection.rollback()
        finally:
            admin.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(second_schema))
            )
