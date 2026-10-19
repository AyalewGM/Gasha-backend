"""Real-PostgreSQL integration tests for the M2 durable stores.

Skipped unless ``GASHA_TEST_POSTGRES_DSN`` points at a database where the
migrations may be applied — e.g.::

    docker run -d -p 55432:5432 -e POSTGRES_USER=gasha \
        -e POSTGRES_PASSWORD=gasha -e POSTGRES_DB=gasha postgres:16-alpine
    GASHA_TEST_POSTGRES_DSN=postgresql://gasha:gasha@localhost:55432/gasha \
        pytest tests/test_postgres_integration.py

These exercise the actual psycopg row contract (``dict_row``), the
SKIP-LOCKED claim, cross-worker ownership, tenant scoping, and
restart recovery — the parts the in-memory fakes only approximate.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from gasha.decision.postgres_audit import PostgresDecisionAuditRepository
from gasha.domain.models import DecisionPolicy, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.postgres_store import (
    PostgresIngestionStore,
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
    PostgresEvaluationPersistence,
    PostgresShadowEvaluationRepository,
)

DSN = os.environ.get("GASHA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="GASHA_TEST_POSTGRES_DSN not set"
)

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)
MIGRATIONS = Path(__file__).resolve().parent.parent / "db" / "migrations"
TABLES = (
    "pending_evaluations",
    "shadow_evaluations",
    "fraud_decision_audit",
    "ingestion_records",
    "dead_letters",
)

POLICY = DecisionPolicy(
    configuration_version="tenant-config-1",
    policy_version="policy-1",
    rule_version="rules-1",
)


@pytest.fixture
def pg():
    import psycopg
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    for path in sorted(MIGRATIONS.glob("*.sql")):
        connection.execute(path.read_text())
    connection.commit()
    yield connection
    connection.execute(
        "TRUNCATE " + ", ".join(TABLES) + " CASCADE"
    )
    connection.commit()
    connection.close()


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


class TestRealRowContract:
    """Each SELECT result is consumed via row["record_json"] — this only
    works if the connection yields dict_row-shaped rows."""

    def test_dict_row_reads(self, pg) -> None:
        store = PostgresPendingEvaluationStore(pg, worker_id="w1")
        env = envelope()
        store.enqueue(env, enqueued_at=T0)
        due = store.due(T0)
        assert len(due) == 1
        assert due[0].event.event_id == env.event_id


class TestClaimAndOwnership:
    def test_concurrent_claims_are_disjoint(self, pg) -> None:
        writer = PostgresPendingEvaluationStore(pg, worker_id="seed")
        envs = [envelope() for _ in range(10)]
        for env in envs:
            writer.enqueue(env, enqueued_at=T0)
        # Expire the seed lease so both workers compete for all rows.
        pg.execute(
            "UPDATE pending_evaluations SET leased_by = NULL, "
            "leased_until = NULL"
        )
        pg.commit()

        claimed_a: list = []
        claimed_b: list = []
        barrier = threading.Barrier(2)

        def claim(store, out):
            barrier.wait()
            out.extend(store.due(T0, limit=100))

        store_a = PostgresPendingEvaluationStore(pg, worker_id="a")
        store_b = PostgresPendingEvaluationStore(pg, worker_id="b")
        ta = threading.Thread(target=claim, args=(store_a, claimed_a))
        tb = threading.Thread(target=claim, args=(store_b, claimed_b))
        ta.start()
        tb.start()
        ta.join()
        tb.join()

        ids_a = {r.event.event_id for r in claimed_a}
        ids_b = {r.event.event_id for r in claimed_b}
        assert ids_a.isdisjoint(ids_b)
        assert ids_a | ids_b == {e.event_id for e in envs}
        # While leases are held, nobody else can claim.
        store_c = PostgresPendingEvaluationStore(pg, worker_id="c")
        assert store_c.due(T0) == ()

    def test_lease_expiry_allows_takeover(self, pg) -> None:
        store_a = PostgresPendingEvaluationStore(
            pg, worker_id="a", lease_ttl=timedelta(seconds=30)
        )
        store_b = PostgresPendingEvaluationStore(pg, worker_id="b")
        env = envelope()
        store_a.enqueue(env, enqueued_at=T0)

        assert store_b.due(T0) == ()  # A's lease held
        claimed = store_b.due(T0 + timedelta(minutes=1))
        assert [r.event.event_id for r in claimed] == [env.event_id]
        # A can no longer mutate B's row.
        assert (
            store_a.reschedule(
                env.tenant_id,
                env.event_id,
                error="x",
                next_attempt_at=T0 + timedelta(hours=1),
                owner="a",
            )
            is None
        )
        store_a.complete(env.tenant_id, env.event_id, owner="a")
        assert len(store_b.due(T0 + timedelta(minutes=2))) == 1

    def test_tenant_scope_restricts_claims(self, pg) -> None:
        scoped = PostgresPendingEvaluationStore(
            pg, tenant_ids=("tenant-a",), worker_id="a"
        )
        scoped.enqueue(envelope("tenant-a"), enqueued_at=T0)
        scoped.enqueue(envelope("tenant-b"), enqueued_at=T0)
        pg.execute(
            "UPDATE pending_evaluations SET leased_by = NULL, "
            "leased_until = NULL"
        )
        pg.commit()
        claimed = scoped.due(T0)
        assert [r.event.tenant_id for r in claimed] == ["tenant-a"]
        # tenant-b's row is still claimable by a properly scoped worker.
        other = PostgresPendingEvaluationStore(
            pg, tenant_ids=("tenant-b",), worker_id="b"
        )
        assert [r.event.tenant_id for r in other.due(T0)] == ["tenant-b"]


class TestRestartRecoveryRealPostgres:
    """Committed offset -> process restart (new objects, same DB, empty
    consumer) -> exactly one durable evaluation + audit pair under the
    pinned attempt-1 policy versions."""

    def test_recovery_persists_consistent_pair(self, pg) -> None:
        pending = PostgresPendingEvaluationStore(pg, worker_id="w1")
        persistence = PostgresEvaluationPersistence(pg)
        evals = PostgresShadowEvaluationRepository(pg)
        audit = PostgresDecisionAuditRepository(pg)
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()},
            store=PostgresIngestionStore(pg),
        )
        env = envelope()
        event = inbound_for(env)
        policies = {"tenant-a": POLICY}
        orchestrator = ShadowOrchestrator(
            policies,
            evaluations=evals,
            audit=audit,
            persistence=persistence,
        )
        dead_letters = InMemoryDeadLetterSink()
        calls = {"n": 0}

        def flaky(
            envelope_arg: FraudEventEnvelope,
            policy: DecisionPolicy | None = None,
        ) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("store down")
            return orchestrator.evaluate(envelope_arg, policy)

        consumer = _StubConsumer([[event]])
        worker1 = IngestionWorker(
            consumer,
            ingestion,
            evaluate=flaky,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            policy_for=lambda t: policies.get(t),
            pending=pending,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
            worker_id="w1",
        )
        worker1.run_once(max_events=1)
        assert consumer.commits == 1
        assert evals.get(env.tenant_id, env.event_id) is None

        # Restart: fresh objects, empty consumer, policy bumped.
        policies["tenant-a"] = DecisionPolicy(
            configuration_version="tenant-config-2",
            policy_version="policy-2",
            rule_version="rules-2",
        )
        worker2 = IngestionWorker(
            _StubConsumer([]),
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            pending=pending,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
            worker_id="w1",
        )
        worker2.run_once(max_events=1)

        persisted_eval = evals.get(env.tenant_id, env.event_id)
        persisted_audit = audit.get(env.tenant_id, env.event_id)
        assert persisted_eval is not None
        assert persisted_audit is not None
        assert persisted_audit.decision == persisted_eval.evaluation.decision
        decision = persisted_eval.evaluation.decision
        assert decision.policy_version == "policy-1"
        assert decision.rule_version == "rules-1"
        assert persisted_eval.evaluation.operating_mode == (
            OperatingMode.SHADOW
        )
        assert calls["n"] == 1

        # Re-reconcile: nothing left, still exactly one row.
        worker2.run_once(max_events=1)
        row = pg.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()
        assert row is not None
        assert int(row["n"]) == 1


class _StubConsumer:
    def __init__(self, batches: list[list[InboundBankEvent]]) -> None:
        self._batches = list(batches)
        self.commits = 0

    def poll_batch(self, *, max_events: int = 1) -> EventBatch:
        events = tuple(self._batches.pop(0)) if self._batches else ()
        return EventBatch(events, len(events))

    def commit(self) -> None:
        self.commits += 1
