from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Self
from uuid import uuid4

from gasha.journey.events import JourneyEvent, JourneyEventKind
from gasha.journey.postgres_repository import PostgresJourneyEventRepository

BASE = datetime(2026, 3, 15, 10, 0, 0, tzinfo=UTC)


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.row: dict[str, object] | None = None
        self.rows_out: list[dict[str, object]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO journey_events"):
            (
                tenant_id,
                event_id,
                customer_id,
                kind,
                occurred_at,
                event_json,
            ) = params
            key = (str(tenant_id), str(event_id))
            if key in self.connection.rows:
                self.row = None
            else:
                row = {
                    "tenant_id": tenant_id,
                    "customer_id": customer_id,
                    "kind": kind,
                    "occurred_at": occurred_at,
                    "event_json": event_json,
                }
                self.connection.rows[key] = row
                self.row = {"event_id": event_id}
            return
        if normalized.startswith("SELECT event_json FROM journey_events"):
            tenant_id, customer_id, since, as_of = params
            self.rows_out = sorted(
                (
                    row
                    for row in self.connection.rows.values()
                    if row["tenant_id"] == tenant_id
                    and row["customer_id"] == customer_id
                    and since <= row["occurred_at"] <= as_of
                ),
                key=lambda row: row["occurred_at"],
            )
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self) -> dict[str, object] | None:
        return self.row

    def fetchall(self) -> list[dict[str, object]]:
        return self.rows_out

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.commits = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1


def event(
    *,
    tenant_id: str = "tenant-a",
    customer_id: str = "cust-1",
    occurred_at: datetime = BASE,
    event_id=None,
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id=tenant_id,
        event_id=event_id or uuid4(),
        kind=JourneyEventKind.AUTHENTICATION,
        subtype="login_failed",
        occurred_at=occurred_at,
        customer_id=customer_id,
    )


def test_append_inserts_and_commits() -> None:
    repo = PostgresJourneyEventRepository(FakeConnection())
    assert repo.append(event()) is True
    assert repo._connection.commits == 1


def test_duplicate_append_is_noop_and_preserves_original() -> None:
    connection = FakeConnection()
    repo = PostgresJourneyEventRepository(connection)
    original = event()
    assert repo.append(original) is True
    assert repo.append(original) is False
    assert len(connection.rows) == 1


def test_recent_filters_window_tenant_and_customer() -> None:
    connection = FakeConnection()
    repo = PostgresJourneyEventRepository(connection)
    inside = event(occurred_at=BASE - timedelta(minutes=10))
    too_early = event(occurred_at=BASE - timedelta(hours=5))
    other_customer = event(customer_id="cust-2")
    other_tenant = event(tenant_id="tenant-b")
    for candidate in (inside, too_early, other_customer, other_tenant):
        repo.append(candidate)

    recent = repo.recent(
        "tenant-a",
        "cust-1",
        as_of=BASE,
        since=BASE - timedelta(hours=1),
    )
    assert [item.event_id for item in recent] == [inside.event_id]


def test_recent_orders_by_business_time() -> None:
    repo = PostgresJourneyEventRepository(FakeConnection())
    later = event(occurred_at=BASE - timedelta(minutes=1))
    earlier = event(occurred_at=BASE - timedelta(minutes=30))
    repo.append(later)
    repo.append(earlier)

    recent = repo.recent(
        "tenant-a",
        "cust-1",
        as_of=BASE,
        since=BASE - timedelta(hours=1),
    )
    assert [item.event_id for item in recent] == [
        earlier.event_id,
        later.event_id,
    ]


def test_same_customer_in_other_tenant_is_invisible() -> None:
    repo = PostgresJourneyEventRepository(FakeConnection())
    repo.append(event(tenant_id="tenant-b", customer_id="shared"))
    assert (
        repo.recent(
            "tenant-a",
            "shared",
            as_of=BASE,
            since=BASE - timedelta(days=1),
        )
        == ()
    )
