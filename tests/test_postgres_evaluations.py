from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Self
from uuid import uuid4

from gasha.domain.models import DecisionAction, DecisionPolicy, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.postgres_store import (
    PostgresPendingEvaluationStore,
)
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import (
    IngestionService,
    InMemoryDeadLetterSink,
)
from gasha.ingestion.transport import EventBatch
from gasha.ingestion.worker import IngestionWorker
from gasha.orchestration import ShadowOrchestrator
from gasha.postgres_evaluations import (
    PostgresShadowEvaluationRepository,
)

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)

POLICY = DecisionPolicy(
    configuration_version="tenant-config-1",
    policy_version="policy-1",
    rule_version="rules-1",
)


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.row: dict[str, object] | None = None
        self.rows_out: list[dict[str, object]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO shadow_evaluations"):
            tenant_id, event_id, record_json, persisted_at = params
            self.connection.rows.setdefault(
                (str(tenant_id), str(event_id)),
                {"record_json": record_json, "persisted_at": persisted_at},
            )
            return
        if normalized.startswith(
            "SELECT record_json FROM shadow_evaluations WHERE"
        ):
            key = (str(params[0]), str(params[1]))
            self.row = self.connection.rows.get(key)
            return
        if normalized.startswith("INSERT INTO pending_evaluations"):
            tenant_id, event_id = params[0], params[1]
            self.connection.pending_rows.setdefault(
                (str(tenant_id), str(event_id)),
                {"record_json": params[2]},
            )
            return
        if normalized.startswith(
            "SELECT record_json FROM pending_evaluations WHERE tenant_id"
        ):
            key = (str(params[0]), str(params[1]))
            self.row = self.connection.pending_rows.get(key)
            return
        if normalized.startswith(
            "SELECT record_json FROM pending_evaluations WHERE "
            "next_attempt_at"
        ):
            self.rows_out = [
                row
                for row in self.connection.pending_rows.values()
                if datetime.fromisoformat(
                    json.loads(str(row["record_json"]))["next_attempt_at"]
                )
                <= params[0]
            ][: params[1]]
            return
        if normalized.startswith("UPDATE pending_evaluations"):
            key = (str(params[4]), str(params[5]))
            self.connection.pending_rows[key] = {"record_json": params[0]}
            return
        if normalized.startswith("DELETE FROM pending_evaluations"):
            key = (str(params[0]), str(params[1]))
            self.connection.pending_rows.pop(key, None)
            return
        raise AssertionError(f"unexpected query: {normalized}")

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
        self.pending_rows: dict[tuple[str, str], dict[str, object]] = {}
        self.commits = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1


def envelope(tenant_id: str = "tenant-a") -> FraudEventEnvelope:
    payload = {
        "event_id": str(uuid4()),
        "occurred_at": T0.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "50.00",
        "currency": "ETB",
        "sender_customer_id": "c1",
        "sender_account_id": "a1",
        "beneficiary_id": "b1",
        "beneficiary_type": "external",
        "destination_institution_id": "bank-b",
        "correlation_id": "corr-1",
    }
    inbound = InboundBankEvent(
        tenant_id=tenant_id,
        source_system="synthetic-core-banking",
        schema_version="1.0",
        payload=payload,
    )
    return ReferenceJsonAdapter().adapt(inbound)


class TestPostgresShadowEvaluationRepository:
    def test_save_then_get_round_trips(self) -> None:
        connection = FakeConnection()
        repo = PostgresShadowEvaluationRepository(connection)
        env = envelope()
        orchestrator = ShadowOrchestrator({"tenant-a": POLICY}, evaluations=repo)
        orchestrator.evaluate(env)

        persisted = repo.get(env.tenant_id, env.event_id)
        assert persisted is not None
        assert persisted.event.event_id == env.event_id
        assert persisted.evaluation.decision.action == DecisionAction.ALLOW
        assert persisted.evaluation.operating_mode == OperatingMode.SHADOW
        assert connection.commits >= 1

    def test_first_write_wins_on_conflict(self) -> None:
        connection = FakeConnection()
        repo = PostgresShadowEvaluationRepository(connection)
        env = envelope()
        orchestrator = ShadowOrchestrator({"tenant-a": POLICY}, evaluations=repo)
        first = orchestrator.evaluate(env)
        second = orchestrator.evaluate(env)
        # Same event re-evaluated: repository keeps the original record.
        assert second.decision.event_id == first.decision.event_id
        stored = repo.get(env.tenant_id, env.event_id)
        assert stored is not None
        assert stored.evaluation.evaluated_at == first.evaluated_at

    def test_missing_key_returns_none(self) -> None:
        repo = PostgresShadowEvaluationRepository(FakeConnection())
        assert repo.get("tenant-a", uuid4()) is None


class _StubConsumer:
    """Feeds a fixed sequence of InboundBankEvent batches."""

    def __init__(self, batches: list[list[InboundBankEvent]]) -> None:
        self._batches = list(batches)
        self.commits = 0

    def poll_batch(self, *, max_events: int = 1) -> EventBatch:
        events = tuple(self._batches.pop(0)) if self._batches else ()
        return EventBatch(events, len(events))

    def commit(self) -> None:
        self.commits += 1


def inbound_for(env: FraudEventEnvelope) -> InboundBankEvent:
    tx = env.canonical_transaction
    return InboundBankEvent(
        tenant_id=env.tenant_id,
        source_system="synthetic-core-banking",
        schema_version="1.0",
        payload={
            "event_id": str(tx.event_id),
            "occurred_at": tx.occurred_at.isoformat(),
            "channel": tx.channel,
            "transaction_type": tx.transaction_type,
            "amount": str(tx.amount),
            "currency": tx.currency,
            "sender_customer_id": tx.sender_customer_id,
            "sender_account_id": tx.sender_account_id,
            "beneficiary_id": tx.beneficiary_id,
            "beneficiary_type": tx.beneficiary_type.value,
            "destination_institution_id": tx.destination_institution_id,
            "correlation_id": tx.correlation_id,
        },
    )


class TestWorkerRestartDurability:
    """Persistent shadow evaluation survives a worker restart: after a
    crash between ingest and evaluate, a restarted worker (fresh objects,
    same Postgres store) completes the evaluation exactly once."""

    def test_restart_recovers_evaluation(self) -> None:
        connection = FakeConnection()
        repo = PostgresShadowEvaluationRepository(connection)
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()}
        )
        env = envelope()
        event = inbound_for(env)
        dead_letters = InMemoryDeadLetterSink()

        # Worker 1: ingest succeeds, evaluate crashes before persisting.
        consumer1 = _StubConsumer([[event]])
        orchestrator1 = ShadowOrchestrator({"tenant-a": POLICY}, evaluations=repo)
        calls = {"n": 0}

        def flaky(envelope_arg: FraudEventEnvelope) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("worker died mid-evaluation")
            return orchestrator1.evaluate(envelope_arg)

        worker1 = IngestionWorker(
            consumer1,
            ingestion,
            evaluate=flaky,
            evaluation_complete=lambda t, e: repo.get(t, e) is not None,
            dead_letters=dead_letters,
        )
        worker1.run_once(max_events=1)
        assert repo.get(env.tenant_id, env.event_id) is None

        # Worker 2 (restart): redelivers event; DUPLICATE ingest, but the
        # durable check reports no evaluation -> evaluate again, exactly once.
        consumer2 = _StubConsumer([[event]])
        orchestrator2 = ShadowOrchestrator({"tenant-a": POLICY}, evaluations=repo)
        worker2 = IngestionWorker(
            consumer2,
            ingestion,
            evaluate=orchestrator2.evaluate,
            evaluation_complete=lambda t, e: repo.get(t, e) is not None,
            dead_letters=dead_letters,
        )
        worker2.run_once(max_events=1)

        persisted = repo.get(env.tenant_id, env.event_id)
        assert persisted is not None
        assert persisted.evaluation.decision.rule_version == "rules-1"

        # Worker 3: redelivery again — now skipped, still exactly one row.
        consumer3 = _StubConsumer([[event]])
        worker3 = IngestionWorker(
            consumer3,
            ingestion,
            evaluate=orchestrator2.evaluate,
            evaluation_complete=lambda t, e: repo.get(t, e) is not None,
            dead_letters=dead_letters,
        )
        worker3.run_once(max_events=1)
        assert len(connection.rows) == 1

    def test_tenant_isolation(self) -> None:
        connection = FakeConnection()
        repo = PostgresShadowEvaluationRepository(connection)
        env_a = envelope("tenant-a")
        env_b = envelope("tenant-b")
        # env_b shares no rows with tenant-a even if event_ids collided.
        orchestrator = ShadowOrchestrator(
            {"tenant-a": POLICY, "tenant-b": POLICY}, evaluations=repo
        )
        orchestrator.evaluate(env_a)
        assert repo.get(env_b.tenant_id, env_a.event_id) is None
        assert repo.get(env_a.tenant_id, env_a.event_id) is not None
        # Same event_id under another tenant is an independent record.
        forced = env_b.model_copy(update={"event_id": env_a.event_id})
        orchestrator.evaluate(forced)
        assert repo.get("tenant-b", env_a.event_id) is not None


class TestPostgresPendingEvaluationStore:
    """Durable pending ledger: enqueue/due/reschedule/complete round-trip
    and a cross-worker restart recovery through the same connection."""

    def test_enqueue_due_reschedule_complete(self) -> None:
        connection = FakeConnection()
        store = PostgresPendingEvaluationStore(connection)
        env = envelope()

        record = store.enqueue(env, enqueued_at=T0)
        assert record.attempts == 0
        assert store.due(T0) == (record,)

        updated = store.reschedule(
            env.tenant_id,
            env.event_id,
            error="RuntimeError",
            next_attempt_at=T0 + timedelta(seconds=30),
        )
        assert updated.attempts == 1
        assert updated.last_error == "RuntimeError"
        assert store.due(T0) == ()
        assert len(store.due(T0 + timedelta(seconds=31))) == 1

        store.complete(env.tenant_id, env.event_id)
        assert store.due(T0 + timedelta(days=1)) == ()

    def test_enqueue_is_idempotent(self) -> None:
        connection = FakeConnection()
        store = PostgresPendingEvaluationStore(connection)
        env = envelope()
        first = store.enqueue(env, enqueued_at=T0)
        store.reschedule(
            env.tenant_id,
            env.event_id,
            error="x",
            next_attempt_at=T0 + timedelta(seconds=30),
        )
        again = store.enqueue(env, enqueued_at=T0 + timedelta(hours=1))
        assert again.attempts == 1  # first row wins, attempts preserved
        assert again.enqueued_at == first.enqueued_at

    def test_restart_recovery_end_to_end(self) -> None:
        """Committed offset -> restart (new worker objects, same
        Postgres stores, empty consumer) -> exactly one durable
        evaluation."""
        connection = FakeConnection()
        pending = PostgresPendingEvaluationStore(connection)
        repo = PostgresShadowEvaluationRepository(connection)
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()}
        )
        env = envelope()
        event = inbound_for(env)
        dead_letters = InMemoryDeadLetterSink()
        calls = {"n": 0}

        orchestrator = ShadowOrchestrator(
            {"tenant-a": POLICY}, evaluations=repo
        )

        def flaky(envelope_arg: FraudEventEnvelope) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("decision store down")
            return orchestrator.evaluate(envelope_arg)

        consumer1 = _StubConsumer([[event]])
        worker1 = IngestionWorker(
            consumer1,
            ingestion,
            evaluate=flaky,
            evaluation_complete=lambda t, e: repo.get(t, e) is not None,
            pending=pending,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
        )
        worker1.run_once(max_events=1)
        assert consumer1.commits == 1
        assert repo.get(env.tenant_id, env.event_id) is None

        # Restart: new worker over the same Postgres stores, no
        # redelivery — reconcile produces the single durable evaluation.
        consumer2 = _StubConsumer([])
        worker2 = IngestionWorker(
            consumer2,
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=lambda t, e: repo.get(t, e) is not None,
            pending=pending,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
        )
        worker2.run_once(max_events=1)

        persisted = repo.get(env.tenant_id, env.event_id)
        assert persisted is not None
        assert persisted.evaluation.decision.rule_version == "rules-1"
        assert pending.due(datetime.now(UTC) + timedelta(days=1)) == ()
        assert calls["n"] == 1

        # Reconcile again: nothing left, still exactly one row.
        worker2.run_once(max_events=1)
        assert len(connection.rows) == 1
