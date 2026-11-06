"""#45 explicit PostgreSQL history reader: unit and protected-HTTP integration.

Uses isolated PostgreSQL schemas and fictional identity records. These tests
prove a bounded read bridge, not Bank IdP, TLS, DB grants, dataset provenance,
an authenticated browser session or authorized payment action.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.cases.postgres_history_reader import ExplicitPostgresCaseHistoryReader
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import (
    CaseCommand,
    CaseOperation,
    CaseReason,
    CaseRejected,
    VerifiedEvaluation,
)
from gasha.security.access import (
    AuthorizationRejected,
    Capability,
    CredentialRejected,
    SecurityAuditEvent,
    TrustedPrincipal,
)

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
MIGRATIONS = Path(__file__).resolve().parent.parent / "db/migrations"
AT = datetime.now(UTC)
TENANTS = ("fictional-a", "fictional-b")


def principal(
    tenant: str = TENANTS[0], *,
    caps: frozenset[Capability] = frozenset({Capability.CASE_READ}),
    expiry: datetime | None = None,
) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-reader", issuer="synthetic-verifier",
        credential_ref="synthetic-only", tenant_ids=frozenset({tenant}),
        capabilities=caps,
        expires_at=expiry if expiry is not None else AT + timedelta(hours=1),
    )


class HostileTimezone(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        self.calls += 1
        raise AssertionError("untrusted timezone callback executed")

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)


def test_invalid_or_unauthorized_history_requests_never_open_database() -> None:
    opens: list[str] = []

    def forbidden_connection():
        opens.append("unexpected")
        raise AssertionError("database opened before authorization")

    reader = ExplicitPostgresCaseHistoryReader(connections=forbidden_connection)
    case_id = uuid4()
    no_read = principal(caps=frozenset({Capability.CASE_TRIAGE}))
    expired = principal(expiry=AT - timedelta(seconds=1))
    for bad_principal, tenant, case, at in (
        (no_read, TENANTS[0], case_id, AT),
        (principal(), TENANTS[1], case_id, AT),
        (expired, TENANTS[0], case_id, AT),
        (principal(), TENANTS[0], "untrusted", AT),
        (principal(), " untrusted ", case_id, AT),
        (principal(), TENANTS[0], case_id, datetime(2026, 11, 6)),
    ):
        with pytest.raises((AuthorizationRejected, CaseRejected)):
            reader.history(
                principal=bad_principal, tenant_id=tenant,
                case_id=case, at=at,
            )  # type: ignore[arg-type]
    assert opens == []


def test_hostile_clocks_fail_before_callback_or_database() -> None:
    opens = []

    def forbidden_connection():
        opens.append("unexpected")
        raise AssertionError("database must not open")

    reader = ExplicitPostgresCaseHistoryReader(connections=forbidden_connection)
    clock = HostileTimezone()
    bad_at = AT.replace(tzinfo=clock)
    with pytest.raises(CaseRejected):
        reader.history(
            principal=principal(), tenant_id=TENANTS[0],
            case_id=uuid4(), at=bad_at,
        )
    damaged_principal = principal()
    object.__setattr__(
        damaged_principal, "expires_at", AT.replace(tzinfo=clock),
    )
    with pytest.raises(AuthorizationRejected):
        reader.history(
            principal=damaged_principal, tenant_id=TENANTS[0],
            case_id=uuid4(), at=AT,
        )
    assert clock.calls == 0
    assert opens == []


def connect(schema: str):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    connection.execute(
        sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
    )
    connection.commit()
    return connection


@pytest.fixture
def schema():
    if not DSN:
        pytest.skip("GASHA_TEST_POSTGRES_DSN not set")
    import psycopg
    from psycopg import sql

    name = "gasha_history_reader_" + uuid4().hex[:12]
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        try:
            with connect(name) as conn:
                for filename in ("010_security_audit_events.sql", "011_analyst_case_events.sql"):
                    conn.execute((MIGRATIONS / filename).read_text())
                conn.commit()
            yield name
        finally:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


class Source:
    def resolve(self, tenant_id: str, event_id: UUID) -> VerifiedEvaluation:
        return VerifiedEvaluation(tenant_id, event_id, "c" * 64)


class Verifier:
    def __init__(self) -> None:
        self.revoked: set[str] = set()

    def verify(self, token: str) -> TrustedPrincipal:
        if token in self.revoked or token not in TENANTS:
            raise CredentialRejected("synthetic credential revoked")
        return principal(token)


class Audit:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    def append(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


class ConnectionFactory:
    def __init__(self, schema_name: str) -> None:
        self.schema_name = schema_name
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return connect(self.schema_name)


@pytest.fixture
def installed_synthetic_history(schema):
    cases: dict[str, UUID] = {}
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        for tenant in TENANTS:
            case_id, event_id = uuid4(), uuid4()
            command = CaseCommand(
                tenant_id=tenant, case_id=case_id, source_event_id=event_id,
                operation=CaseOperation.CREATE, expected_revision=0,
                idempotency_key=uuid4().hex,
                reason_code=CaseReason.SOURCE_EVALUATION,
            )
            service.apply(
                command, principal=principal(
                    tenant, caps=frozenset({Capability.CASE_CREATE, Capability.CASE_READ}),
                ), source=Source(), at=AT,
            )
            cases[tenant] = case_id
    keys = ("identity_verifier", "security_audit", "case_history_reader")
    previous = {key: getattr(app.state, key) for key in keys}
    verifier, audit, factory = Verifier(), Audit(), ConnectionFactory(schema)
    app.state.identity_verifier = verifier
    app.state.security_audit = audit
    app.state.case_history_reader = ExplicitPostgresCaseHistoryReader(connections=factory)
    try:
        yield schema, cases, verifier, audit, factory, TestClient(app)
    finally:
        for key, value in previous.items():
            setattr(app.state, key, value)


def url(tenant: str, case_id: UUID) -> str:
    return f"/v1/tenants/{tenant}/cases/{case_id}/history"


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_real_postgres_history_through_protected_api_is_tenant_scoped(
    installed_synthetic_history,
) -> None:
    _, cases, _, audit, factory, client = installed_synthetic_history
    for tenant in TENANTS:
        response = client.get(url(tenant, cases[tenant]), headers=auth(tenant))
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["case_id"] == str(cases[tenant])
        assert len(body["events"]) == 1
        assert body["events"][0]["operation"] == "create"
        assert body["events"][0]["bank_execution"] == "unknown"
        assert body["enforcement_activated"] is False
        assert "idempotency_ref" not in response.text
        assert "command_ref" not in response.text
    assert factory.calls == 2
    assert [e.result for e in audit.events if e.action == "case.read"] == [
        "authorized", "succeeded", "authorized", "succeeded",
    ]
    assert all(tenant not in str(audit.events) for tenant in TENANTS)


def test_cross_tenant_unknown_and_revoked_requests_never_leak_history(
    installed_synthetic_history,
) -> None:
    _, cases, verifier, audit, factory, client = installed_synthetic_history
    assert client.get(
        url(TENANTS[1], cases[TENANTS[1]]),
        headers={**auth(TENANTS[0]), "X-Tenant-Id": TENANTS[1], "X-Role": "admin"},
    ).status_code == 404
    assert factory.calls == 0
    assert client.get(
        url(TENANTS[0], cases[TENANTS[1]]), headers=auth(TENANTS[0]),
    ).status_code == 404
    assert factory.calls == 1
    verifier.revoked.add(TENANTS[0])
    assert client.get(
        url(TENANTS[0], cases[TENANTS[0]]), headers=auth(TENANTS[0]),
    ).status_code == 401
    assert factory.calls == 1
    assert not any(e.result == "succeeded" for e in audit.events)


def test_stored_row_json_mismatch_fails_closed_at_protected_api(
    installed_synthetic_history,
) -> None:
    schema, cases, _, audit, factory, client = installed_synthetic_history
    with connect(schema) as connection:
        connection.execute(
            """UPDATE analyst_case_events
            SET event_json = jsonb_set(event_json, '{tenant_id}', to_jsonb(%s::text))
            WHERE tenant_id = %s AND case_id = %s""",
            (TENANTS[1], TENANTS[0], cases[TENANTS[0]]),
        )
        connection.commit()
    response = client.get(
        url(TENANTS[0], cases[TENANTS[0]]), headers=auth(TENANTS[0]),
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "case history unavailable"}
    assert factory.calls == 1
    assert [e.result for e in audit.events if e.action == "case.read"] == [
        "authorized", "failed",
    ]
    assert TENANTS[1] not in response.text
