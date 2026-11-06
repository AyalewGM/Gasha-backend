"""#45 inactive queue read bridge: tenant-safe PostgreSQL and HTTP regressions.

Only fictional identities, cases and source/ranking claims. No Bank data,
authoritative risk ranking, session integration or operational execution.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.cases.postgres_queue_reader import (
    ExplicitPostgresCaseQueueReader,
    RankedCaseReference,
    RankedCaseSelection,
)
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.queue import CaseQueueRejected
from gasha.cases.timeline import (
    CaseCommand,
    CaseOperation,
    CaseReason,
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
TENANTS = ("fictional-queue-a", "fictional-queue-b")
CONTEXT = "c" * 64


def principal(
    tenant: str = TENANTS[0], *,
    caps: frozenset[Capability] = frozenset({Capability.CASE_READ}),
    expiry: datetime | None = None,
) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-queue", issuer="synthetic-verifier",
        credential_ref="synthetic-only", tenant_ids=frozenset({tenant}),
        capabilities=caps,
        expires_at=expiry if expiry is not None else AT + timedelta(hours=1),
    )


class HostileTimezone(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        self.calls += 1
        raise AssertionError("untrusted timezone callback invoked")

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)


class Ranking:
    def __init__(self, selections: dict[str, RankedCaseSelection]) -> None:
        self.selections = selections
        self.calls = 0

    def select(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        limit: int, at: datetime,
    ) -> RankedCaseSelection:
        self.calls += 1
        return self.selections[tenant_id]


def reference(case: UUID | None = None, event: UUID | None = None) -> RankedCaseReference:
    return RankedCaseReference(
        case_id=case or uuid4(), source_event_id=event or uuid4(),
        source_context_ref=CONTEXT, scenario_ids=("APP-01",),
    )


def selection(tenant: str = TENANTS[0], *items: RankedCaseReference) -> RankedCaseSelection:
    return RankedCaseSelection(tenant, "synthetic-ranked-v1", items)


def test_unauthorized_selector_fails_before_ranking_and_database() -> None:
    ranking = Ranking({TENANTS[0]: selection()})
    opens = []

    def forbidden_connection():
        opens.append(True)
        raise AssertionError("unexpected connection")

    reader = ExplicitPostgresCaseQueueReader(
        connections=forbidden_connection, ranking=ranking,
    )
    bad = [
        (principal(caps=frozenset({Capability.CASE_TRIAGE})), TENANTS[0], 1, AT),
        (principal(), TENANTS[1], 1, AT),
        (principal(expiry=AT - timedelta(seconds=1)), TENANTS[0], 1, AT),
        (principal(), " untrusted ", 1, AT),
        (principal(), TENANTS[0], 101, AT),
        (principal(), TENANTS[0], True, AT),
        (principal(), TENANTS[0], 1, datetime(2026, 11, 6)),
    ]
    for actor, tenant, limit, at in bad:
        with pytest.raises((AuthorizationRejected, CaseQueueRejected)):
            reader.read(principal=actor, tenant_id=tenant, limit=limit, at=at)
    hostile = HostileTimezone()
    with pytest.raises(CaseQueueRejected):
        reader.read(
            principal=principal(), tenant_id=TENANTS[0], limit=1,
            at=AT.replace(tzinfo=hostile),
        )
    assert hostile.calls == 0
    assert ranking.calls == 0
    assert not opens


def test_invalid_ranking_selection_fails_before_database() -> None:
    cases = [
        selection(TENANTS[1], reference()),
        RankedCaseSelection(TENANTS[0], " invalid ", (reference(),)),
        selection(TENANTS[0], reference(), reference()),
    ]
    duplicate = reference()
    cases.extend([
        selection(TENANTS[0], duplicate, duplicate),
        selection(TENANTS[0], RankedCaseReference(
            duplicate.case_id, duplicate.source_event_id, "invalid", ("APP-01",),
        )),
        selection(TENANTS[0], RankedCaseReference(
            duplicate.case_id, duplicate.source_event_id, CONTEXT, ["APP-01"],
        )),
    ])
    for bad in cases:
        ranking = Ranking({TENANTS[0]: bad})
        reader = ExplicitPostgresCaseQueueReader(
            connections=lambda: (_ for _ in ()).throw(AssertionError("DB opened")),
            ranking=ranking,
        )
        with pytest.raises(CaseQueueRejected):
            reader.read(
                principal=principal(), tenant_id=TENANTS[0], limit=1, at=AT,
            )
        assert ranking.calls == 1


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
    if not DSN:
        pytest.skip("GASHA_TEST_POSTGRES_DSN not set")
    import psycopg
    from psycopg import sql

    name = "gasha_ranked_queue_" + uuid4().hex[:12]
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
        return VerifiedEvaluation(tenant_id, event_id, CONTEXT)


class Verifier:
    def __init__(self) -> None:
        self.revoked: set[str] = set()

    def verify(self, token: str) -> TrustedPrincipal:
        if token in self.revoked or token not in TENANTS:
            raise CredentialRejected("synthetic credential rejected")
        return principal(token)


class Audit:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    def append(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


class ConnectionFactory:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return connect(self.name)


@pytest.fixture
def installed_synthetic_queue(schema):
    refs: dict[str, RankedCaseReference] = {}
    with connect(schema) as connection:
        service = PostgresCaseTimelineService(connection)
        for tenant in TENANTS:
            case_id, event_id = uuid4(), uuid4()
            service.apply(
                CaseCommand(
                    tenant_id=tenant, case_id=case_id, source_event_id=event_id,
                    operation=CaseOperation.CREATE, expected_revision=0,
                    idempotency_key=uuid4().hex,
                    reason_code=CaseReason.SOURCE_EVALUATION,
                ),
                principal=principal(tenant, caps=frozenset({
                    Capability.CASE_CREATE, Capability.CASE_READ,
                })),
                source=Source(), at=AT,
            )
            refs[tenant] = reference(case_id, event_id)
    ranking = Ranking({tenant: selection(tenant, refs[tenant]) for tenant in TENANTS})
    verifier, audit, factory = Verifier(), Audit(), ConnectionFactory(schema)
    keys = ("identity_verifier", "security_audit", "case_queue_reader")
    previous = {key: getattr(app.state, key) for key in keys}
    app.state.identity_verifier = verifier
    app.state.security_audit = audit
    app.state.case_queue_reader = ExplicitPostgresCaseQueueReader(
        connections=factory, ranking=ranking,
    )
    try:
        yield schema, refs, ranking, verifier, audit, factory, TestClient(app)
    finally:
        for key, value in previous.items():
            setattr(app.state, key, value)


def queue_url(tenant: str) -> str:
    return f"/v1/tenants/{tenant}/cases/queue"


def auth(tenant: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tenant}"}


def test_postgres_ranked_queue_through_protected_http_is_tenant_scoped(
    installed_synthetic_queue,
) -> None:
    _, refs, _, _, audit, factory, client = installed_synthetic_queue
    for tenant in TENANTS:
        response = client.get(queue_url(tenant), headers=auth(tenant))
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ranking_policy_version"] == "synthetic-ranked-v1"
        assert body["bank_ranking_approved"] is False
        assert body["enforcement_activated"] is False
        assert len(body["items"]) == 1
        assert body["items"][0]["case_id"] == str(refs[tenant].case_id)
        assert body["items"][0]["source_event_id"] == str(refs[tenant].source_event_id)
        assert body["items"][0]["scenario_ids"] == ["APP-01"]
        assert body["items"][0]["status"] == "create"
        assert "idempotency_ref" not in response.text
        assert "command_ref" not in response.text
    assert factory.calls == 2
    assert [e.result for e in audit.events if e.action == "case.read"] == [
        "authorized", "succeeded", "authorized", "succeeded",
    ]
    assert all(t not in str(audit.events) for t in TENANTS)


def test_foreign_ranked_case_or_revoked_token_cannot_disclose_queue(
    installed_synthetic_queue,
) -> None:
    _, refs, ranking, verifier, audit, factory, client = installed_synthetic_queue
    tenant = TENANTS[0]
    assert client.get(
        queue_url(TENANTS[1]),
        headers={**auth(tenant), "X-Tenant-Id": TENANTS[1], "X-Role": "admin"},
    ).status_code == 404
    assert factory.calls == 0
    ranking.selections[tenant] = selection(tenant, refs[TENANTS[1]])
    response = client.get(queue_url(tenant), headers=auth(tenant))
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert TENANTS[1] not in response.text
    assert factory.calls == 1
    verifier.revoked.add(tenant)
    assert client.get(queue_url(tenant), headers=auth(tenant)).status_code == 401
    assert factory.calls == 1
    assert not any(e.result == "succeeded" for e in audit.events)


def test_tampered_history_fails_whole_ranked_queue_with_redacted_audit(
    installed_synthetic_queue,
) -> None:
    schema, refs, _, _, audit, factory, client = installed_synthetic_queue
    with connect(schema) as connection:
        connection.execute(
            """UPDATE analyst_case_events
            SET event_json = jsonb_set(event_json, '{tenant_id}', to_jsonb(%s::text))
            WHERE tenant_id = %s AND case_id = %s""",
            (TENANTS[1], TENANTS[0], refs[TENANTS[0]].case_id),
        )
        connection.commit()
    response = client.get(queue_url(TENANTS[0]), headers=auth(TENANTS[0]))
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert TENANTS[1] not in response.text
    assert factory.calls == 1
    assert [e.result for e in audit.events if e.action == "case.read"] == [
        "authorized", "failed",
    ]


def test_empty_queue_and_limits_have_no_database_side_effects() -> None:
    ranking = Ranking({TENANTS[0]: selection()})
    opens: list[str] = []

    def forbidden_connection():
        opens.append("unexpected database")
        raise AssertionError("empty queue opened database")

    reader = ExplicitPostgresCaseQueueReader(
        connections=forbidden_connection, ranking=ranking,
    )
    for limit in (1, 100):
        snapshot = reader.read(
            principal=principal(), tenant_id=TENANTS[0], limit=limit, at=AT,
        )
        assert snapshot.items == ()
        assert snapshot.ranking_policy_version == "synthetic-ranked-v1"
    for limit in (0, 101):
        with pytest.raises(CaseQueueRejected):
            reader.read(
                principal=principal(), tenant_id=TENANTS[0], limit=limit, at=AT,
            )
    assert ranking.calls == 2
    assert opens == []


def test_invalid_scenario_references_fail_before_database() -> None:
    variants = (("APP-99",), ("APP-01", "APP-01"), ("MM-01", "APP-01"), ())
    opens: list[str] = []

    def forbidden_connection():
        opens.append("unexpected database")
        raise AssertionError("invalid rank reached database")

    for scenarios in variants:
        opens.clear()
        ref = reference()
        bad = RankedCaseReference(
            ref.case_id, ref.source_event_id, CONTEXT, scenarios,
        )
        ranking = Ranking({TENANTS[0]: selection(TENANTS[0], bad)})
        reader = ExplicitPostgresCaseQueueReader(
            connections=forbidden_connection, ranking=ranking,
        )
        with pytest.raises(CaseQueueRejected):
            reader.read(
                principal=principal(), tenant_id=TENANTS[0], limit=1, at=AT,
            )
        assert ranking.calls == 1
        assert not opens


def _create_additional_case(schema_name: str, tenant: str) -> RankedCaseReference:
    case_id, event_id = uuid4(), uuid4()
    with connect(schema_name) as connection:
        PostgresCaseTimelineService(connection).apply(
            CaseCommand(
                tenant_id=tenant, case_id=case_id, source_event_id=event_id,
                operation=CaseOperation.CREATE, expected_revision=0,
                idempotency_key=uuid4().hex,
                reason_code=CaseReason.SOURCE_EVALUATION,
            ),
            principal=principal(
                tenant, caps=frozenset({Capability.CASE_READ, Capability.CASE_CREATE}),
            ),
            source=Source(), at=AT,
        )
    return reference(case_id, event_id)


def test_multi_case_queue_uses_per_case_history_reader_transactions(
    installed_synthetic_queue,
) -> None:
    schema_name, refs, ranking, _, audit, factory, client = installed_synthetic_queue
    tenant = TENANTS[0]
    additional = _create_additional_case(schema_name, tenant)
    ranking.selections[tenant] = selection(tenant, refs[tenant], additional)
    response = client.get(queue_url(tenant) + "?limit=2", headers=auth(tenant))
    assert response.status_code == 200, response.text
    assert [item["case_id"] for item in response.json()["items"]] == [
        str(refs[tenant].case_id), str(additional.case_id),
    ]
    # Each #130 history read closes its own connection/read transaction.
    # This proves no queue-wide repeatable-read snapshot is being claimed.
    assert factory.calls == 2
    assert [event.result for event in audit.events if event.action == "case.read"] == [
        "authorized", "succeeded",
    ]


def test_concurrent_second_case_corruption_fails_entire_queue(
    installed_synthetic_queue,
) -> None:
    schema_name, refs, ranking, _, audit, _, client = installed_synthetic_queue
    tenant = TENANTS[0]
    additional = _create_additional_case(schema_name, tenant)
    ranking.selections[tenant] = selection(tenant, refs[tenant], additional)

    class CorruptBeforeSecondRead:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self):
            self.calls += 1
            if self.calls == 2:
                # Simulate a different connection changing the second case
                # between independent reads. No partial queue may escape.
                with connect(schema_name) as updater:
                    updater.execute(
                        """UPDATE analyst_case_events
                           SET event_json = jsonb_set(
                               event_json, '{tenant_id}', to_jsonb(%s::text))
                           WHERE tenant_id = %s AND case_id = %s""",
                        (TENANTS[1], tenant, additional.case_id),
                    )
                    updater.commit()
            return connect(schema_name)

    connections = CorruptBeforeSecondRead()
    app.state.case_queue_reader = ExplicitPostgresCaseQueueReader(
        connections=connections, ranking=ranking,
    )
    response = client.get(queue_url(tenant) + "?limit=2", headers=auth(tenant))
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert "items" not in response.text
    assert tenant not in response.text
    assert TENANTS[1] not in response.text
    assert connections.calls == 2
    assert [event.result for event in audit.events if event.action == "case.read"] == [
        "authorized", "failed",
    ]


def test_second_case_connection_outage_never_returns_partial_queue(
    installed_synthetic_queue,
) -> None:
    schema_name, refs, ranking, _, audit, _, client = installed_synthetic_queue
    tenant = TENANTS[0]
    additional = _create_additional_case(schema_name, tenant)
    ranking.selections[tenant] = selection(tenant, refs[tenant], additional)
    calls = []

    def failing_second_connection():
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError("synthetic sensitive connection error")
        return connect(schema_name)

    app.state.case_queue_reader = ExplicitPostgresCaseQueueReader(
        connections=failing_second_connection, ranking=ranking,
    )
    response = client.get(queue_url(tenant) + "?limit=2", headers=auth(tenant))
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert "sensitive" not in response.text
    assert len(calls) == 2
    assert [event.result for event in audit.events if event.action == "case.read"] == [
        "authorized", "failed",
    ]
