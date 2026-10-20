"""Real-PostgreSQL integration tests for the M2 durable stores.

Skipped unless ``GASHA_TEST_POSTGRES_DSN`` points at a database where the
migrations may be applied   e.g.::

    docker run -d -p 55432:5432 -e POSTGRES_USER=gasha \
        -e POSTGRES_PASSWORD=gasha -e POSTGRES_DB=gasha postgres:16-alpine
    GASHA_TEST_POSTGRES_DSN=postgresql://gasha:gasha@localhost:55432/gasha \
        pytest tests/test_postgres_integration.py

These exercise the actual psycopg row contract (``dict_row``), the
SKIP-LOCKED claim, cross-worker ownership, tenant scoping, and
restart recovery   the parts the in-memory fakes only approximate.
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

T0 = datetime.now(UTC)
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
    """Each SELECT result is consumed via row["record_json"]   this only
    works if the connection yields dict_row-shaped rows."""

    def test_dict_row_reads(self, pg) -> None:
        store = PostgresPendingEvaluationStore(pg, worker_id="w1")
        env = envelope()
        store.enqueue(env, enqueued_at=T0)
        due = store.due(T0 + timedelta(minutes=6))
        assert len(due) == 1
        assert due[0].event.event_id == env.event_id


class TestClaimAndOwnership:
    def test_concurrent_claims_are_disjoint(self, pg) -> None:
        """Two workers on *separate psycopg connections* (as separate
        worker processes would run) claim simultaneously   SKIP-LOCKED
        keeps every row exclusive."""
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

        conn_a = _connect()
        conn_b = _connect()
        assert conn_a.info.backend_pid != conn_b.info.backend_pid
        try:
            errors: list = []
            claimed_a: list = []
            claimed_b: list = []
            barrier = threading.Barrier(2)

            def claim(store, out):
                try:
                    barrier.wait(timeout=10)
                    out.extend(store.due(T0, limit=100))
                except Exception as exc:  # noqa: BLE001 - propagate thread failures
                    errors.append(exc)

            store_a = PostgresPendingEvaluationStore(conn_a, worker_id="a")
            store_b = PostgresPendingEvaluationStore(conn_b, worker_id="b")
            ta = threading.Thread(target=claim, args=(store_a, claimed_a))
            tb = threading.Thread(target=claim, args=(store_b, claimed_b))
            ta.start()
            tb.start()
            ta.join()
            tb.join()

            assert not errors
            ids_a = {r.event.event_id for r in claimed_a}
            ids_b = {r.event.event_id for r in claimed_b}
            assert ids_a.isdisjoint(ids_b)
            assert ids_a | ids_b == {e.event_id for e in envs}
            # Tokens differ per claim   each worker's fencing token is
            # unique to its own claim generation.
            tokens = {r.claim_token for r in claimed_a + claimed_b}
            assert len(tokens) == len(claimed_a) + len(claimed_b)
            # While leases are held, nobody else can claim.
            store_c = PostgresPendingEvaluationStore(pg, worker_id="c")
            assert store_c.due(T0) == ()
        finally:
            conn_a.close()
            conn_b.close()

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
        # A can no longer mutate B's row   its stale lease/token fence it.
        assert (
            store_a.reschedule(
                env.tenant_id,
                env.event_id,
                error="x",
                next_attempt_at=T0 + timedelta(hours=1),
                owner="a",
                claim_token=claimed[0].claim_token,
            )
            is None
        )
        store_a.complete(
            env.tenant_id,
            env.event_id,
            owner="a",
            claim_token=claimed[0].claim_token,
        )
        assert store_b.due(T0 + timedelta(minutes=2)) == ()

    def test_tenant_scope_restricts_claims(self, pg) -> None:
        scoped = PostgresPendingEvaluationStore(
            pg, tenant_ids=("tenant-a",), worker_id="a"
        )
        scoped.enqueue(envelope("tenant-a"), enqueued_at=T0)
        PostgresPendingEvaluationStore(pg).enqueue(envelope("tenant-b"), enqueued_at=T0)
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



def test_takeover_metadata_survives_redelivery(pg):
    a = PostgresPendingEvaluationStore(pg, worker_id="a")
    b = PostgresPendingEvaluationStore(pg, worker_id="b")
    env = envelope()
    a.enqueue(env, enqueued_at=T0)
    now = T0 + timedelta(hours=1)
    claimed = b.due(now)[0]
    assert claimed.leased_by == "b"
    duplicate = a.enqueue(env, enqueued_at=now)
    assert duplicate.leased_by == "b"
    assert duplicate.leased_until == claimed.leased_until
    a.complete(env.tenant_id, env.event_id, owner="a")
    assert a.enqueue(env, enqueued_at=now).leased_by == "b"


def test_delayed_worker_token_fences_stale_writes(pg):
    """The reviewer's scenario on real Postgres with separate
    connections: worker A claims, stalls past its lease; worker B takes
    over, evaluates durably, and completes. When A finishes late it can
    neither reschedule nor delete B's work, and its late evaluation
    cannot overwrite B's durable audit/eval pair (first-write-wins)."""
    conn_a = _connect()
    conn_b = _connect()
    try:
        store_a = PostgresPendingEvaluationStore(
            conn_a, tenant_ids=("tenant-a",), worker_id="a"
        )
        store_b = PostgresPendingEvaluationStore(
            conn_b, tenant_ids=("tenant-a",), worker_id="b"
        )
        env = envelope()
        a_record = store_a.enqueue(env, enqueued_at=T0)
        assert a_record.claim_token is not None

        # A stalls past its lease; B claims with a fresh fencing token.
        b_claim = store_b.due(T0 + timedelta(hours=1))[0]
        assert b_claim.claim_token != a_record.claim_token

        # B evaluates durably and completes its claim.
        evals = PostgresShadowEvaluationRepository(
            conn_b, tenant_ids=("tenant-a",)
        )
        audit = PostgresDecisionAuditRepository(
            conn_b, tenant_ids=("tenant-a",)
        )
        orchestrator_b = ShadowOrchestrator(
            {"tenant-a": POLICY},
            evaluations=evals,
            audit=audit,
            persistence=PostgresEvaluationPersistence(
                conn_b, tenant_ids=("tenant-a",)
            ),
        )
        decision_b = orchestrator_b.evaluate(env, POLICY)
        store_b.complete(
            env.tenant_id,
            env.event_id,
            owner="b",
            claim_token=b_claim.claim_token,
        )
        assert store_b.due(T0 + timedelta(days=1)) == ()

        # A wakes up and finishes late. Its stale token cannot
        # reschedule anything   the row B completed is gone.
        assert store_a.reschedule(
                env.tenant_id,
                env.event_id,
                error="late",
                next_attempt_at=T0 + timedelta(hours=2),
                owner="a",
                claim_token=a_record.claim_token,
            ) is None
        # A's complete is a no-op against whatever row exists now.
        store_a.complete(
            env.tenant_id,
            env.event_id,
            owner="a",
            claim_token=a_record.claim_token,
        )

        # If A's in-flight evaluation lands after B's, first-write-wins
        # keeps B's evidence   exactly one audit + one eval, B's decision.
        evals_a = PostgresShadowEvaluationRepository(
            conn_a, tenant_ids=("tenant-a",)
        )
        orchestrator_a = ShadowOrchestrator(
            {"tenant-a": POLICY},
            evaluations=evals_a,
            audit=PostgresDecisionAuditRepository(
                conn_a, tenant_ids=("tenant-a",)
            ),
            persistence=PostgresEvaluationPersistence(
                conn_a, tenant_ids=("tenant-a",)
            ),
        )
        orchestrator_a.evaluate(env, POLICY)
        row = conn_b.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()
        assert row is not None and int(row["n"]) == 1
        persisted_eval = evals.get(env.tenant_id, env.event_id)
        persisted_audit = audit.get(env.tenant_id, env.event_id)
        assert persisted_eval is not None and persisted_audit is not None
        assert persisted_audit.decision == decision_b.decision
        assert persisted_eval.evaluation.decision == decision_b.decision
    finally:
        conn_a.close()
        conn_b.close()


def test_scoped_repositories_deny_foreign_tenant(pg):
    env = envelope("tenant-b")
    pending = PostgresPendingEvaluationStore(pg, tenant_ids=("tenant-a",))
    for action in (
        lambda: pending.enqueue(env, enqueued_at=T0),
        lambda: pending._get(env.tenant_id, env.event_id),
        lambda: pending.complete(env.tenant_id, env.event_id),
        lambda: PostgresIngestionStore(pg, tenant_ids=("tenant-a",)).get(env.tenant_id, env.event_id),
        lambda: PostgresShadowEvaluationRepository(pg, tenant_ids=("tenant-a",)).get(env.tenant_id, env.event_id),
        lambda: PostgresDecisionAuditRepository(pg, tenant_ids=("tenant-a",)).get(env.tenant_id, env.event_id),
    ):
        with pytest.raises(PermissionError):
            action()


def _connect():
    import psycopg
    from psycopg.rows import dict_row

    connection = psycopg.connect(DSN, row_factory=dict_row)
    for path in sorted(MIGRATIONS.glob("*.sql")):
        connection.execute(path.read_text())
    connection.commit()
    return connection


def test_separate_connections_crash_recovery_and_idempotency(pg):
    """Two real psycopg connections: worker-A writes the pending row and
    crashes mid-evaluation; worker-B on a separate connection claims the
    expired lease and completes exactly once   repeat reconcile is a
    no-op."""
    conn_a = _connect()
    conn_b = _connect()
    try:
        pending_a = PostgresPendingEvaluationStore(
            conn_a, tenant_ids=("tenant-a",), worker_id="a"
        )
        pending_b = PostgresPendingEvaluationStore(
            conn_b, tenant_ids=("tenant-a",), worker_id="b"
        )
        persistence = PostgresEvaluationPersistence(
            conn_b, tenant_ids=("tenant-a",)
        )
        evals = PostgresShadowEvaluationRepository(
            conn_b, tenant_ids=("tenant-a",)
        )
        audit = PostgresDecisionAuditRepository(
            conn_b, tenant_ids=("tenant-a",)
        )
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()},
            store=PostgresIngestionStore(conn_a, tenant_ids=("tenant-a",)),
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

        # Worker A: evaluate explodes -> failure recorded, offset acked.
        def explode(
            envelope_arg: FraudEventEnvelope,
            policy: DecisionPolicy | None = None,
        ) -> object:
            raise RuntimeError("worker A died")

        worker_a = IngestionWorker(
            _StubConsumer([[event]]),
            ingestion,
            evaluate=explode,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            policy_for=lambda t: policies.get(t),
            pending=pending_a,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
            worker_id="a",
            tenant_ids=("tenant-a",),
        )
        worker_a.run_once(max_events=1)
        assert evals.get(env.tenant_id, env.event_id) is None
        conn_a.close()  # simulate process death; lease stays held by "a"

        # Worker B on a separate connection takes over after lease expiry.
        conn_b.execute(
            "UPDATE pending_evaluations SET leased_until = %s",
            (datetime.now(UTC) - timedelta(seconds=1),),
        )
        conn_b.commit()
        worker_b = IngestionWorker(
            _StubConsumer([]),
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            pending=pending_b,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
            worker_id="b",
            tenant_ids=("tenant-a",),
        )
        worker_b.run_once(max_events=1)

        persisted_eval = evals.get(env.tenant_id, env.event_id)
        persisted_audit = audit.get(env.tenant_id, env.event_id)
        assert persisted_eval is not None
        assert persisted_audit is not None
        assert persisted_audit.decision == persisted_eval.evaluation.decision

        # Idempotent: repeated reconciles never add rows.
        worker_b.run_once(max_events=1)
        worker_b.run_once(max_events=1)
        row = conn_b.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()
        assert row is not None
        assert int(row["n"]) == 1
        assert dead_letters.records == ()
    finally:
        conn_b.close()


def test_worker_ingestion_rejects_foreign_tenant(pg):
    """Startup-scoped worker cannot ingest an out-of-scope tenant."""
    conn = _connect()
    try:
        pending = PostgresPendingEvaluationStore(
            conn, tenant_ids=("tenant-a",), worker_id="w"
        )
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()},
            store=PostgresIngestionStore(conn, tenant_ids=("tenant-a",)),
        )
        foreign = inbound_for(envelope("tenant-b"))
        worker = IngestionWorker(
            _StubConsumer([[foreign]]),
            ingestion,
            evaluate=lambda e, p=None: pytest.fail("foreign tenant"),
            pending=pending,
            dead_letters=InMemoryDeadLetterSink(),
            worker_id="w",
            tenant_ids=("tenant-a",),
        )
        with pytest.raises(PermissionError):
            worker.run_once(max_events=1)
        row = conn.execute(
            "SELECT count(*) AS n FROM ingestion_records"
        ).fetchone()
        assert row is not None
        assert int(row["n"]) == 0
    finally:
        conn.close()


def test_claim_and_recovery_performance(pg, capsys):
    """Timing evidence: claim throughput and end-to-end restart
    recovery over real Postgres. Loose bounds only   numbers are
    reported, not asserted tightly."""
    import time

    conn = _connect()
    try:
        writer = PostgresPendingEvaluationStore(
            conn, tenant_ids=("tenant-a",), worker_id="seed"
        )
        envs = [envelope() for _ in range(200)]
        start = time.perf_counter()
        for env in envs:
            writer.enqueue(env, enqueued_at=T0)
        seed_s = time.perf_counter() - start

        conn.execute(
            "UPDATE pending_evaluations SET leased_by = NULL, "
            "leased_until = NULL, next_attempt_at = %s",
            (T0,),
        )
        conn.commit()

        claimant = PostgresPendingEvaluationStore(
            conn,
            tenant_ids=("tenant-a",),
            worker_id="perf",
            lease_ttl=timedelta(minutes=30),
        )
        start = time.perf_counter()
        claimed = claimant.due(T0, limit=500)
        claim_s = time.perf_counter() - start
        assert len(claimed) == 200
        conn.execute("UPDATE pending_evaluations SET leased_until = NULL")
        conn.commit()

        evals = PostgresShadowEvaluationRepository(
            conn, tenant_ids=("tenant-a",)
        )
        audit = PostgresDecisionAuditRepository(conn, tenant_ids=("tenant-a",))
        persistence = PostgresEvaluationPersistence(
            conn, tenant_ids=("tenant-a",)
        )
        orchestrator = ShadowOrchestrator(
            {"tenant-a": POLICY},
            evaluations=evals,
            audit=audit,
            persistence=persistence,
        )
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()},
            store=PostgresIngestionStore(conn, tenant_ids=("tenant-a",)),
        )
        worker = IngestionWorker(
            _StubConsumer([]),
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            pending=claimant,
            dead_letters=InMemoryDeadLetterSink(),
            worker_id="perf",
            tenant_ids=("tenant-a",),
        )
        start = time.perf_counter()
        worker.run_once(max_events=1)  # claim batch 1 (limit 100)
        worker.run_once(max_events=1)  # claim batch 2
        recovery_s = time.perf_counter() - start

        row = conn.execute(
            "SELECT count(*) AS n FROM shadow_evaluations"
        ).fetchone()
        assert row is not None
        assert int(row["n"]) == 200
        with capsys.disabled():
            print(
                f"\nPERF seed_200_enqueues={seed_s:.3f}s "
                f"claim_200_skip_locked={claim_s:.3f}s "
                f"recover_200_evals={recovery_s:.3f}s"
            )
        assert claim_s < 5.0
        assert recovery_s < 60.0
    finally:
        conn.close()

def test_stale_claim_fenced_with_reused_worker_identity(pg):
    from gasha.ingestion.lease import (
        EvaluationLease,
        LeaseLostError,
        current_evaluation_lease,
    )
    conn_a, conn_b = _connect(), _connect()
    try:
        a = PostgresPendingEvaluationStore(conn_a, worker_id='shared-id')
        b = PostgresPendingEvaluationStore(conn_b, worker_id='shared-id')
        env = envelope()
        old = a.enqueue(env, enqueued_at=datetime.now(UTC), policy=POLICY)
        conn_b.execute(
            'UPDATE pending_evaluations SET leased_until = clock_timestamp() - interval \'1 second\''
        )
        conn_b.commit()
        # Expiry alone fences writes, even before anyone takes over.
        assert a.reschedule(env.tenant_id, env.event_id, error='late',
                            next_attempt_at=datetime.now(UTC), owner='shared-id',
                            claim_token=old.claim_token) is None
        a.complete(env.tenant_id, env.event_id, owner='shared-id', claim_token=old.claim_token)
        new = b.due(datetime.now(UTC))[0]
        assert new.claim_token and new.claim_token != old.claim_token
        # Reusing a worker_id cannot authorize an old generation.
        a.complete(env.tenant_id, env.event_id, owner='shared-id', claim_token=old.claim_token)
        assert a.reschedule(env.tenant_id, env.event_id, error='late',
                            next_attempt_at=datetime.now(UTC), owner='shared-id',
                            claim_token=old.claim_token) is None
        orchestrator = ShadowOrchestrator(
            {'tenant-a': POLICY},
            persistence=PostgresEvaluationPersistence(conn_a, require_lease=True),
        )
        context = current_evaluation_lease.set(
            EvaluationLease(env.tenant_id, env.event_id, old.claim_token)
        )
        try:
            with pytest.raises(LeaseLostError):
                orchestrator.evaluate(env, POLICY)
        finally:
            current_evaluation_lease.reset(context)
        assert PostgresShadowEvaluationRepository(conn_b).get(env.tenant_id, env.event_id) is None
        assert PostgresDecisionAuditRepository(conn_b).get(env.tenant_id, env.event_id) is None
        assert b._get(env.tenant_id, env.event_id).claim_token == new.claim_token
        context = current_evaluation_lease.set(
            EvaluationLease(env.tenant_id, env.event_id, new.claim_token)
        )
        try:
            orchestrator.evaluate(env, POLICY)
        finally:
            current_evaluation_lease.reset(context)
        b.complete(env.tenant_id, env.event_id, owner='shared-id', claim_token=new.claim_token)
        assert b._get(env.tenant_id, env.event_id) is None
        audit = PostgresDecisionAuditRepository(conn_b).get(env.tenant_id, env.event_id)
        evaluation = PostgresShadowEvaluationRepository(conn_b).get(env.tenant_id, env.event_id)
        assert audit.decision == evaluation.evaluation.decision
    finally:
        conn_a.close()
        conn_b.close()


@pytest.mark.parametrize('reason_name', ['EVALUATION_FAILURE', 'TENANT_CONFIGURATION_UNAVAILABLE'])
def test_late_terminal_failure_cannot_contradict_success(pg, reason_name):
    from gasha.ingestion.errors import RejectionReason, RejectionRecord
    from gasha.ingestion.lease import EvaluationLease, current_evaluation_lease
    conn_a, conn_b = _connect(), _connect()
    try:
        a = PostgresPendingEvaluationStore(conn_a, worker_id='same-id')
        b = PostgresPendingEvaluationStore(conn_b, worker_id='same-id')
        env = envelope()
        old = a.enqueue(env, enqueued_at=datetime.now(UTC), policy=POLICY)
        conn_b.execute("UPDATE pending_evaluations SET leased_until = clock_timestamp() - interval '1 second'")
        conn_b.commit()
        new = b.due(datetime.now(UTC))[0]
        rejection = RejectionRecord(
            tenant_id=env.tenant_id, event_id=str(env.event_id),
            reason=RejectionReason[reason_name], detail='late synthetic failure',
        )
        context = current_evaluation_lease.set(EvaluationLease(env.tenant_id, env.event_id, new.claim_token))
        try:
            ShadowOrchestrator(
                {'tenant-a': POLICY},
                persistence=PostgresEvaluationPersistence(conn_b, require_lease=True),
            ).evaluate(env, POLICY)
        finally:
            current_evaluation_lease.reset(context)
        # Even the current claim may not emit terminal failure after success.
        assert not b.terminate(new, rejection, dead_letters=InMemoryDeadLetterSink(),
                               owner='same-id', now=datetime.now(UTC))
        assert not a.terminate(old, rejection, dead_letters=InMemoryDeadLetterSink(),
                               owner='same-id', now=datetime.now(UTC))
        b.complete(env.tenant_id, env.event_id, owner='same-id', claim_token=new.claim_token)
        conn_a.close()
        conn_a = _connect()  # restart with a fresh database session
        restarted = PostgresPendingEvaluationStore(conn_a, worker_id='same-id')
        assert not restarted.terminate(old, rejection, dead_letters=InMemoryDeadLetterSink(),
                                      owner='same-id', now=datetime.now(UTC))
        assert conn_a.execute('SELECT count(*) AS n FROM dead_letters').fetchone()['n'] == 0
        audit = PostgresDecisionAuditRepository(conn_a).get(env.tenant_id, env.event_id)
        evaluation = PostgresShadowEvaluationRepository(conn_a).get(env.tenant_id, env.event_id)
        assert audit.decision == evaluation.evaluation.decision
    finally:
        conn_a.close()
        conn_b.close()


def test_terminal_dlq_rollback_and_restart_idempotency(pg):
    import psycopg

    from gasha.ingestion.errors import RejectionReason, RejectionRecord
    store = PostgresPendingEvaluationStore(pg, worker_id='a')
    env = envelope()
    claim = store.enqueue(env, enqueued_at=datetime.now(UTC), policy=POLICY)
    rejection = RejectionRecord(
        tenant_id=env.tenant_id, event_id=str(env.event_id),
        reason=RejectionReason.EVALUATION_FAILURE, detail='synthetic failure',
        policy_version=POLICY.policy_version,
    )
    # Force failure after DLQ insert but before terminal finalization.
    pg.execute('ALTER TABLE pending_evaluations ADD CONSTRAINT synthetic_reject_terminal CHECK (NOT terminal)')
    pg.commit()
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            store.terminate(claim, rejection, dead_letters=InMemoryDeadLetterSink(),
                            owner='a', now=datetime.now(UTC))
        assert pg.execute('SELECT count(*) AS n FROM dead_letters').fetchone()['n'] == 0
        assert not store._get(env.tenant_id, env.event_id).terminal
    finally:
        pg.execute('ALTER TABLE pending_evaluations DROP CONSTRAINT synthetic_reject_terminal')
        pg.commit()
    assert store.terminate(claim, rejection, dead_letters=InMemoryDeadLetterSink(),
                           owner='a', now=datetime.now(UTC))
    fresh = _connect()
    try:
        restarted = PostgresPendingEvaluationStore(fresh, worker_id='a')
        assert not restarted.terminate(claim, rejection, dead_letters=InMemoryDeadLetterSink(),
                                       owner='a', now=datetime.now(UTC))
        recovered = restarted.enqueue(env, enqueued_at=datetime.now(UTC), policy=POLICY)
        assert recovered.terminal and recovered.policy == POLICY
        assert restarted.due(datetime.now(UTC) + timedelta(days=1)) == ()
        assert fresh.execute('SELECT count(*) AS n FROM dead_letters').fetchone()['n'] == 1
    finally:
        fresh.close()
