"""#42/#45 authenticated, fail-closed, UNWIRED multi-scenario ranked queue contract."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.cases.queue import CaseQueueSnapshot, RankedCase
from gasha.cases.timeline import (
    BankExecution,
    CaseDisposition,
    CaseEvent,
    CaseOperation,
    CaseReason,
)
from gasha.security.access import Capability, CredentialRejected, TrustedPrincipal

CASE = UUID("00000000-0000-4000-8000-000000000041")
SOURCE = UUID("00000000-0000-4000-8000-000000000042")
OTHER_CASE = UUID("00000000-0000-4000-8000-000000000043")
OTHER_SOURCE = UUID("00000000-0000-4000-8000-000000000044")
CONTEXT = "c" * 64
ACTOR = "a" * 64


def event(
    *, case_id: UUID = CASE, source_id: UUID = SOURCE, when: datetime | None = None,
) -> CaseEvent:
    return CaseEvent(
        tenant_id="tenant-a", case_id=case_id, source_event_id=source_id,
        source_context_ref=CONTEXT, revision=1, previous_revision=None,
        operation=CaseOperation.CREATE, actor_ref=ACTOR,
        recorded_at=when or datetime.now(UTC) - timedelta(minutes=10),
        reason_code=CaseReason.SOURCE_EVALUATION, disposition=None,
        assignee_ref=None, idempotency_ref="d" * 64, command_ref="e" * 64,
        bank_execution=BankExecution.UNKNOWN,
    )


def item(
    *, case_id: UUID = CASE, source_id: UUID = SOURCE, rank: int = 1,
    scenarios: tuple[str, ...] = ("APP-01", "ATO-02"),
) -> RankedCase:
    return RankedCase(
        rank=rank, case_id=case_id, source_event_id=source_id,
        source_context_ref=CONTEXT, scenario_ids=scenarios,
        history=(event(case_id=case_id, source_id=source_id),),
    )


def principal(
    *, tenant: str = "tenant-a", read: bool = True, expired: bool = False,
) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-queue-analyst-secret", issuer="synthetic-verifier",
        credential_ref="synthetic-credential-secret", tenant_ids=frozenset({tenant}),
        capabilities=frozenset({Capability.CASE_READ} if read else {Capability.CASE_TRIAGE}),
        expires_at=datetime.now(UTC) + timedelta(hours=-1 if expired else 1),
    )


class Verifier:
    def verify(self, bearer: str) -> TrustedPrincipal:
        if bearer == "outage":
            raise RuntimeError("synthetic identity provider unavailable")
        if bearer == "valid":
            return principal()
        if bearer == "no-read":
            return principal(read=False)
        if bearer == "wrong-tenant":
            return principal(tenant="tenant-b")
        if bearer == "expired":
            return principal(expired=True)
        raise CredentialRejected("revoked or invalid token")


class Audit:
    def __init__(self) -> None:
        self.events: list[object] = []
        self.fail = False

    def append(self, event_record: object) -> None:
        if self.fail:
            raise RuntimeError("synthetic audit failure")
        self.events.append(event_record)


class Reader:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []
        self.change = lambda snapshot: snapshot
        self.fail = False
        self.principal_mutation: tuple[str, object] | None = None
        self.fail_after_mutation = False

    def read(self, *, principal: TrustedPrincipal, tenant_id: str,
             limit: int, at: datetime) -> CaseQueueSnapshot:
        self.calls.append((tenant_id, limit))
        assert principal.audit_actor and tenant_id in principal.tenant_ids
        assert at.tzinfo is not None
        if self.principal_mutation is not None:
            field, replacement = self.principal_mutation
            object.__setattr__(principal, field, replacement)
            if self.fail_after_mutation:
                raise RuntimeError("synthetic queue reader mutated principal then failed")
        if self.fail:
            raise RuntimeError("synthetic storage failure")
        snapshot = CaseQueueSnapshot(
            tenant_id=tenant_id, ranking_policy_version="synthetic-ranked-v1",
            generated_at=at, items=(item(),),
        )
        return self.change(snapshot)


@pytest.fixture
def wired_queue():
    keys = ("identity_verifier", "security_audit", "case_queue_reader")
    original = tuple(getattr(app.state, key) for key in keys)
    reader, audit = Reader(), Audit()
    app.state.identity_verifier = Verifier()
    app.state.security_audit = audit
    app.state.case_queue_reader = reader
    try:
        yield TestClient(app), reader, audit
    finally:
        for key, value in zip(keys, original, strict=True):
            setattr(app.state, key, value)


def endpoint(*, tenant: str = "tenant-a", limit: int = 25) -> str:
    return f"/v1/tenants/{tenant}/cases/queue?limit={limit}"


def bearer(value: str = "valid") -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def test_ranked_multi_scenario_queue_is_authenticated_redacted_and_non_authoritative(wired_queue):
    client, reader, audit = wired_queue
    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["ranking_policy_version"] == "synthetic-ranked-v1"
    assert data["bank_ranking_approved"] is False
    assert data["enforcement_activated"] is False
    assert data["items"][0]["rank"] == 1
    assert data["items"][0]["scenario_ids"] == ["APP-01", "ATO-02"]
    assert data["items"][0]["status"] == "create"
    assert data["items"][0]["bank_execution"] == "unknown"
    assert "idempotency_ref" not in response.text
    assert "synthetic-queue-analyst-secret" not in response.text
    assert "synthetic-credential-secret" not in str(audit.events)
    assert "tenant-a" not in str(audit.events)
    assert reader.calls == [("tenant-a", 25)]
    assert any(e.action == "case.read" and e.result == "succeeded"
               and e.reason == "case_queue_read" for e in audit.events)


@pytest.mark.parametrize(("credential", "expected"), [
    (None, 401), ("revoked", 401), ("expired", 401), ("outage", 503),
    ("no-read", 403), ("wrong-tenant", 404),
])
def test_queue_denials_never_read(wired_queue, credential, expected):
    client, reader, audit = wired_queue
    headers = bearer(credential) if credential else {}
    response = client.get(endpoint(), headers=headers)
    assert response.status_code == expected
    assert reader.calls == []
    assert any(e.result == "denied" for e in audit.events)


def test_spoofed_tenant_role_and_proxy_do_not_authorize(wired_queue):
    client, reader, audit = wired_queue
    response = client.get(
        endpoint(tenant="tenant-b"),
        headers={**bearer(), "X-Tenant-Id": "tenant-b", "X-Role": "admin",
                 "X-Forwarded-Prefix": "/v1"},
    )
    assert response.status_code == 404
    assert reader.calls == []
    assert "tenant-b" not in str(audit.events)


def test_missing_reader_fails_closed(wired_queue):
    client, reader, audit = wired_queue
    app.state.case_queue_reader = None
    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert reader.calls == []
    assert any(e.result == "failed" and e.reason == "case_queue_unavailable"
               for e in audit.events)


def test_audit_failure_prevents_reader_access(wired_queue):
    client, reader, audit = wired_queue
    audit.fail = True
    assert client.get(endpoint(), headers=bearer()).status_code == 503
    assert reader.calls == []


def test_reader_failure_redacts_and_denies(wired_queue):
    client, reader, audit = wired_queue
    reader.fail = True
    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert "synthetic storage failure" not in response.text
    assert any(e.result == "failed" and e.reason == "case_queue_unavailable"
               for e in audit.events)



@pytest.mark.parametrize(
    ("token", "reader_fails", "expected_status", "expected_results"),
    [
        ("valid", False, 200, ("authorized", "succeeded")),
        ("valid", True, 503, ("authorized", "failed")),
        ("no-read", False, 403, ("denied",)),
    ],
)
def test_queue_read_audit_correlation_is_request_unique(
    wired_queue, token, reader_fails, expected_status, expected_results,
):
    """Authorization and terminal audit correlate without reusing an operation ID."""
    client, reader, audit = wired_queue
    reader.fail = reader_fails
    operation_refs = []
    attempt_refs = []
    for _ in range(2):
        before = len(audit.events)
        response = client.get(endpoint(), headers=bearer(token))
        assert response.status_code == expected_status, response.text
        events = [
            entry for entry in audit.events[before:]
            if entry.action == Capability.CASE_READ.value
        ]
        assert tuple(entry.result for entry in events) == expected_results
        # The operation is different for each HTTP request, but every
        # authorization / terminal record within it uses the same reference.
        assert len({entry.event_ref for entry in events}) == 1
        assert len({entry.attempt_ref for entry in events}) == 1
        assert events[0].event_ref
        assert len(events[0].event_ref) == 64
        assert set(events[0].event_ref) <= set("0123456789abcdef")
        assert events[0].attempt_ref
        assert all(entry.tenant_ref != "tenant-a" for entry in events)
        operation_refs.append(events[0].event_ref)
        attempt_refs.append(events[0].attempt_ref)
    assert operation_refs[0] != operation_refs[1]
    assert attempt_refs[0] != attempt_refs[1]
    assert reader.calls == ([] if token == "no-read" else [("tenant-a", 25)] * 2)
    assert "synthetic-queue-analyst-secret" not in str(audit.events)
    assert "synthetic-credential-secret" not in str(audit.events)


@pytest.mark.parametrize("mutate", [
    lambda s: replace(s, tenant_id="tenant-b"),
    lambda s: replace(s, ranking_policy_version="unapproved\nheader"),
    lambda s: replace(s, generated_at=s.generated_at + timedelta(seconds=1)),
    lambda s: replace(s, generated_at=datetime.now(UTC).replace(tzinfo=None)),
    lambda s: replace(s, items=list(s.items)),
    lambda s: replace(s, items=(replace(s.items[0], rank=True),)),
    lambda s: replace(s, items=(replace(s.items[0], rank=2),)),
    lambda s: replace(s, items=(replace(s.items[0], scenario_ids=("ATO-02", "APP-01")),)),
    lambda s: replace(s, items=(replace(s.items[0], scenario_ids=("APP-01", "APP-01")),)),
    lambda s: replace(s, items=(replace(s.items[0], scenario_ids=("UNKNOWN-99",)),)),
    lambda s: replace(s, items=(replace(s.items[0], source_event_id=OTHER_SOURCE),)),
    lambda s: replace(s, items=(replace(s.items[0], source_context_ref="bad"),)),
    lambda s: replace(s, items=(replace(s.items[0], history=()),)),
    lambda s: replace(s, items=(replace(
        s.items[0], history=(replace(s.items[0].history[0], tenant_id="tenant-b"),)
    ),)),
    lambda s: replace(s, items=(replace(
        s.items[0], history=(replace(s.items[0].history[0], recorded_at=s.generated_at
                                         + timedelta(seconds=1)),)
    ),)),
    lambda s: replace(s, items=(replace(
        s.items[0], history=(replace(
            s.items[0].history[0], operation=CaseOperation.DISPOSE,
            reason_code=CaseReason.FRAUD_EVIDENCE,
            disposition=CaseDisposition.FRAUD,
        ),)
    ),)),
    lambda s: replace(s, items=(s.items[0], replace(s.items[0], rank=2))),
    lambda s: replace(s, items=(
        s.items[0], replace(item(case_id=OTHER_CASE, source_id=SOURCE, rank=2)),
    )),
])
def test_malformed_whole_snapshot_is_rejected_without_partial_rows(wired_queue, mutate):
    client, reader, audit = wired_queue
    reader.change = mutate
    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert not any(e.result == "succeeded" and e.reason == "case_queue_read"
                   for e in audit.events)


def test_valid_two_case_ranked_response_and_limit_rejection(wired_queue):
    client, reader, _ = wired_queue
    reader.change = lambda s: replace(s, items=(
        item(), item(case_id=OTHER_CASE, source_id=OTHER_SOURCE, rank=2,
                     scenarios=("MM-01", "MM-02")),
    ))
    ok = client.get(endpoint(limit=2), headers=bearer())
    assert ok.status_code == 200, ok.text
    assert [case["rank"] for case in ok.json()["items"]] == [1, 2]
    assert [case["scenario_ids"] for case in ok.json()["items"]] == [
        ["APP-01", "ATO-02"], ["MM-01", "MM-02"],
    ]
    too_small = client.get(endpoint(limit=1), headers=bearer())
    assert too_small.status_code == 503
    for value in (0, 101):
        invalid = client.get(endpoint(limit=value), headers=bearer())
        assert invalid.status_code == 422


def test_queue_route_authenticates_before_query_validation(wired_queue):
    client, reader, _ = wired_queue
    assert client.get(endpoint(limit=0)).status_code == 401
    assert reader.calls == []

@pytest.mark.parametrize(("field", "replacement"), [
    ("subject", "synthetic-forged-queue-subject-secret"),
    ("issuer", "synthetic-forged-queue-issuer-secret"),
    ("credential_ref", "synthetic-forged-queue-credential-secret"),
    ("tenant_ids", frozenset({"tenant-b"})),
    ("capabilities", frozenset({Capability.CASE_TRIAGE})),
    ("expires_at", datetime.now(UTC) + timedelta(hours=2)),
])
@pytest.mark.parametrize("fail_after_mutation", [False, True])
def test_queue_reader_cannot_modify_authenticated_principal(
    wired_queue, field: str, replacement: object, fail_after_mutation: bool,
) -> None:
    """A callback must not change verified authorization or audit attribution."""
    client, reader, audit = wired_queue
    expected_actor = principal().audit_actor
    reader.principal_mutation = (field, replacement)
    reader.fail_after_mutation = fail_after_mutation

    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    records = [
        entry for entry in audit.events
        if entry.action == Capability.CASE_READ.value
    ]
    assert [entry.result for entry in records] == ["authorized", "failed"]
    assert {entry.actor_ref for entry in records} == {expected_actor}
    assert reader.calls == [("tenant-a", 25)]
    assert "synthetic-forged" not in response.text
    assert "synthetic-forged" not in str(audit.events)
class HostileQueueTimezone(tzinfo):
    """A forged server-reader timezone must not execute when reading cases."""

    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        self.calls += 1
        raise AssertionError("injected queue clock callback executed")

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)


@pytest.mark.parametrize("clock_location", ["snapshot", "history"])
def test_case_queue_rejects_callback_clock_before_any_custom_code(
    wired_queue, clock_location: str,
) -> None:
    client, reader, audit = wired_queue
    hostile = HostileQueueTimezone()
    bad_clock = datetime.now(UTC).replace(tzinfo=hostile)

    def tainted(snapshot: CaseQueueSnapshot) -> CaseQueueSnapshot:
        if clock_location == "snapshot":
            return replace(snapshot, generated_at=bad_clock)
        row = snapshot.items[0]
        bad_row = replace(row, history=(
            replace(row.history[0], recorded_at=bad_clock),
        ))
        return replace(snapshot, items=(bad_row,))

    reader.change = tainted
    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 503
    assert response.json() == {"detail": "case queue unavailable"}
    assert hostile.calls == 0
    assert reader.calls == [("tenant-a", 25)]
    assert [entry.result for entry in audit.events
            if entry.action == Capability.CASE_READ.value] == ["authorized", "failed"]
    assert "injected queue clock" not in response.text


@pytest.mark.parametrize("zone", [
    timezone(timedelta(hours=-4)),
    ZoneInfo("America/New_York"),
])
def test_case_queue_accepts_standard_offset_and_zoneinfo_clocks(
    wired_queue, zone: tzinfo,
) -> None:
    client, reader, _ = wired_queue

    def converted(snapshot: CaseQueueSnapshot) -> CaseQueueSnapshot:
        row = snapshot.items[0]
        local_event = replace(
            row.history[0], recorded_at=row.history[0].recorded_at.astimezone(zone),
        )
        return replace(
            snapshot, generated_at=snapshot.generated_at.astimezone(zone),
            items=(replace(row, history=(local_event,)),),
        )

    reader.change = converted
    response = client.get(endpoint(), headers=bearer())
    assert response.status_code == 200, response.text
    assert response.json()["bank_ranking_approved"] is False
    assert response.json()["enforcement_activated"] is False
