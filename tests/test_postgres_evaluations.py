from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Self
from uuid import uuid4

from gasha.decision.postgres_audit import PostgresDecisionAuditRepository
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
    PostgresEvaluationPersistence,
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
        self.rowcount = 0

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        normalized = " ".join(query.split())
        prefix = self.connection.fail_on_insert_prefix
        if prefix is not None and normalized.startswith(prefix):
            raise RuntimeError(f"injected failure on {prefix}")
        if normalized.startswith("INSERT INTO fraud_decision_audit"):
            self.connection.staged_audit.setdefault(
                (str(params[0]), str(params[1])),
                {
                    "decision_json": params[2],
                    "signal_policy_versions_json": params[3],
                    "evidence_json": params[4],
                },
            )
            return
        if normalized.startswith("INSERT INTO shadow_evaluations"):
            tenant_id, event_id, record_json, persisted_at = params
            self.connection.staged_rows.setdefault(
                (str(tenant_id), str(event_id)),
                {"record_json": record_json, "persisted_at": persisted_at},
            )
            return
        if normalized.startswith(
            "SELECT decision_json, signal_policy_versions_json, "
            "evidence_json FROM fraud_decision_audit WHERE"
        ):
            key = (str(params[0]), str(params[1]))
            self.row = self.connection.audit_rows.get(key)
            return
        if normalized.startswith(
            "SELECT record_json FROM shadow_evaluations WHERE"
        ):
            key = (str(params[0]), str(params[1]))
            self.row = self.connection.rows.get(key)
            return
        if normalized.startswith("INSERT INTO pending_evaluations"):
            tenant_id, event_id = params[0], params[1]
            self.connection.staged_pending.setdefault(
                (str(tenant_id), str(event_id)),
                {
                    "op": "insert",
                    "row": {
                        "record_json": params[2],
                        "leased_by": params[6],
                        "leased_until": params[7],
                        "lease_token": params[8], "terminal": False,
                    },
                },
            )
            return
        if normalized.startswith(
            "SELECT record_json, leased_by, leased_until, lease_token, terminal "
            "FROM pending_evaluations WHERE tenant_id"
        ):
            key = (str(params[0]), str(params[1]))
            self.row = self.connection.pending_rows.get(key)
            return
        if normalized.startswith(
            "UPDATE pending_evaluations AS pe SET leased_by"
        ):
            # Atomic claim: due + in-scope + unleased rows are leased
            # to this worker in one statement.
            worker_id, leased_until, now = params[0], params[1], params[2]
            tenant_ids = params[3]
            limit = int(str(params[6]))
            claimed: list[dict[str, object]] = []
            for key, row in self.connection.pending_rows.items():
                if len(claimed) >= limit:
                    break
                record = json.loads(str(row["record_json"]))
                if row.get("terminal"):
                    continue
                if (
                    datetime.fromisoformat(record["next_attempt_at"])
                    > now
                ):
                    continue
                if tenant_ids is not None and key[0] not in tenant_ids:
                    continue
                if (
                    row.get("leased_until") is not None
                    and row["leased_until"] > now
                ):
                    continue
                row["leased_by"] = worker_id
                row["leased_until"] = leased_until
                row["lease_token"] = str(uuid4())
                claimed.append(dict(row))
            self.rows_out = claimed
            self.rowcount = len(claimed)
            return
        if normalized.startswith("UPDATE pending_evaluations"):
            key = (str(params[4]), str(params[5]))
            owner, claim_token = params[6], params[7]
            existing = self.connection.pending_rows.get(key)
            if existing is not None and (
                existing.get("leased_by") == owner
                and existing.get("lease_token") == claim_token
            ):
                self.connection.staged_pending[key] = {
                    "op": "update",
                    "row": {**existing, "record_json": params[0], "leased_by": None, "leased_until": None, "lease_token": None},
                }
                self.rowcount = 1
            else:
                self.rowcount = 0
            return
        if normalized.startswith("DELETE FROM pending_evaluations"):
            key = (str(params[0]), str(params[1]))
            owner, claim_token = params[2], params[3]
            existing = self.connection.pending_rows.get(key)
            if existing is not None and (
                existing.get("leased_by") == owner
                and existing.get("lease_token") == claim_token
            ):
                self.connection.staged_pending[key] = {"op": "delete"}
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
    """Transactional fake: execute() stages writes; commit() merges them
    atomically; rollback() discards them   like a real Postgres tx."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.pending_rows: dict[tuple[str, str], dict[str, object]] = {}
        self.audit_rows: dict[tuple[str, str], dict[str, object]] = {}
        self.staged_rows: dict[tuple[str, str], dict[str, object]] = {}
        self.staged_pending: dict[tuple[str, str], dict[str, object]] = {}
        self.staged_audit: dict[tuple[str, str], dict[str, object]] = {}
        self.commits = 0
        self.rollbacks = 0
        self.fail_on_insert_prefix: str | None = None

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        # INSERT ... ON CONFLICT DO NOTHING keeps the first row.
        for key, value in self.staged_rows.items():
            self.rows.setdefault(key, value)
        for key, value in self.staged_audit.items():
            self.audit_rows.setdefault(key, value)
        for key, value in self.staged_pending.items():
            if value["op"] == "delete":
                self.pending_rows.pop(key, None)
            elif value["op"] == "insert":
                self.pending_rows.setdefault(key, value["row"])
            else:
                self.pending_rows[key] = value["row"]
        self.staged_rows.clear()
        self.staged_pending.clear()
        self.staged_audit.clear()
        self.commits += 1

    def rollback(self) -> None:
        self.staged_rows.clear()
        self.staged_pending.clear()
        self.staged_audit.clear()
        self.rollbacks += 1


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

        def flaky(envelope_arg: FraudEventEnvelope, policy: DecisionPolicy | None = None) -> object:
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

        # Worker 3: redelivery again   now skipped, still exactly one row.
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
        store = PostgresPendingEvaluationStore(
            connection, worker_id="w1"
        )
        env = envelope()

        record = store.enqueue(env, enqueued_at=T0)
        assert record.attempts == 0
        assert record.leased_by == "w1"
        assert record.claim_token is not None
        assert store.due(T0) == ()
        claimed = (record,)

        updated = store.reschedule(
            env.tenant_id,
            env.event_id,
            error="RuntimeError",
            next_attempt_at=T0 + timedelta(seconds=30),
            owner="w1",
            claim_token=claimed[0].claim_token,
        )
        assert updated is not None
        assert updated.attempts == 1
        assert updated.last_error == "RuntimeError"
        assert store.due(T0) == ()
        reclaimed = store.due(T0 + timedelta(seconds=31))
        assert len(reclaimed) == 1

        store.complete(
            env.tenant_id,
            env.event_id,
            owner="w1",
            claim_token=reclaimed[0].claim_token,
        )
        assert store.due(T0 + timedelta(days=1)) == ()

    def test_enqueue_is_idempotent(self) -> None:
        connection = FakeConnection()
        store = PostgresPendingEvaluationStore(
            connection, worker_id="w1"
        )
        env = envelope()
        first = store.enqueue(env, enqueued_at=T0)
        store.reschedule(
            env.tenant_id,
            env.event_id,
            error="x",
            next_attempt_at=T0 + timedelta(seconds=30),
            owner="w1",
            claim_token=first.claim_token,
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

        def flaky(envelope_arg: FraudEventEnvelope, policy: DecisionPolicy | None = None) -> object:
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
        # redelivery   reconcile produces the single durable evaluation.
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

    def test_concurrent_workers_claim_disjoint_rows(self) -> None:
        """Two worker instances over the same table can never claim the
        same pending row while the first lease is held."""
        connection = FakeConnection()
        store_a = PostgresPendingEvaluationStore(
            connection, worker_id="worker-a"
        )
        store_b = PostgresPendingEvaluationStore(
            connection, worker_id="worker-b"
        )
        env = envelope()
        store_a.enqueue(env, enqueued_at=T0)

        # Worker A's enqueue lease is held; B cannot claim the row.
        assert store_b.due(T0) == ()
        # After A's lease expires, B takes it over atomically.
        claimed = store_b.due(T0 + timedelta(hours=1))
        assert len(claimed) == 1
        assert claimed[0].event.event_id == env.event_id

        # B's reschedule while owning the lease applies; A's is denied.
        rescheduled = store_b.reschedule(
            env.tenant_id,
            env.event_id,
            error="x",
            next_attempt_at=T0 + timedelta(hours=2),
            owner="worker-b",
            claim_token=claimed[0].claim_token,
        )
        assert rescheduled is not None
        assert rescheduled.attempts == 1
        assert (
            store_a.reschedule(
                env.tenant_id,
                env.event_id,
                error="y",
                next_attempt_at=T0 + timedelta(hours=3),
                owner="worker-a",
                claim_token=claimed[0].claim_token,
            )
            is None
        )
        # A cannot complete B's leased row either.
        store_a.complete(
            env.tenant_id,
            env.event_id,
            owner="worker-a",
            claim_token=claimed[0].claim_token,
        )
        assert len(store_b.due(T0 + timedelta(hours=2))) == 1

    def test_tenant_scope_restricts_claims(self) -> None:
        """A store scoped to tenant-a never claims tenant-b's rows."""
        connection = FakeConnection()
        scoped = PostgresPendingEvaluationStore(
            connection, tenant_ids=("tenant-a",), worker_id="w1"
        )
        env_a = envelope("tenant-a")
        env_b = envelope("tenant-b")
        scoped.enqueue(env_a, enqueued_at=T0)
        PostgresPendingEvaluationStore(connection).enqueue(env_b, enqueued_at=T0)

        claimed = scoped.due(T0 + timedelta(hours=1))
        assert [r.event.tenant_id for r in claimed] == ["tenant-a"]

    def test_stale_claim_token_cannot_fence_new_owner(self) -> None:
        """Worker A's lease expires, B reclaims (new token); delayed A
        can neither reschedule nor complete B's work."""
        connection = FakeConnection()
        store_a = PostgresPendingEvaluationStore(
            connection, worker_id="worker-a"
        )
        store_b = PostgresPendingEvaluationStore(
            connection, worker_id="worker-b"
        )
        env = envelope()
        a_record = store_a.enqueue(env, enqueued_at=T0)

        # Lease expires; B claims and gets a fresh fencing token.
        b_claim = store_b.due(T0 + timedelta(hours=1))[0]
        assert b_claim.claim_token != a_record.claim_token

        # Delayed A finishes late with its superseded token: denied.
        assert (
            store_a.reschedule(
                env.tenant_id,
                env.event_id,
                error="stale",
                next_attempt_at=T0 + timedelta(hours=2),
                owner="worker-a",
                claim_token=a_record.claim_token,
            )
            is None
        )
        store_a.complete(
            env.tenant_id,
            env.event_id,
            owner="worker-a",
            claim_token=a_record.claim_token,
        )
        # B's claim is untouched; it completes with its own token.
        b_reclaim = store_b.due(T0 + timedelta(hours=2))
        assert len(b_reclaim) == 1
        store_b.complete(
            env.tenant_id,
            env.event_id,
            owner="worker-b",
            claim_token=b_reclaim[0].claim_token,
        )
        assert store_b.due(T0 + timedelta(days=1)) == ()


class TestAtomicEvaluationConsistency:
    """Audit-save + eval-save land in one transaction; retries re-decide
    under the pinned attempt-1 policy, so the durable audit and the
    durable evaluation always refer to the same immutable decision."""

    POLICY_V1 = POLICY
    POLICY_V2 = DecisionPolicy(
        configuration_version="tenant-config-2",
        policy_version="policy-2",
        rule_version="rules-2",
    )

    def test_mid_save_failure_then_policy_change_retries_consistently(
        self,
    ) -> None:
        connection = FakeConnection()
        pending = PostgresPendingEvaluationStore(connection)
        persistence = PostgresEvaluationPersistence(connection)
        evals = PostgresShadowEvaluationRepository(connection)
        audit = PostgresDecisionAuditRepository(connection)
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()}
        )
        policies = {"tenant-a": self.POLICY_V1}
        env = envelope()
        event = inbound_for(env)
        dead_letters = InMemoryDeadLetterSink()

        orchestrator = ShadowOrchestrator(
            policies, evaluations=evals, audit=audit, persistence=persistence
        )

        # Attempt 1: audit insert succeeds inside the tx but the
        # shadow_evaluations insert fails -> whole tx rolls back.
        connection.fail_on_insert_prefix = "INSERT INTO shadow_evaluations"
        worker1 = IngestionWorker(
            _StubConsumer([[event]]),
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            policy_for=lambda t: policies.get(t),
            pending=pending,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
        )
        worker1.run_once(max_events=1)
        assert connection.rollbacks == 1
        # Nothing half-persisted: no audit, no evaluation.
        assert connection.audit_rows == {}
        assert connection.rows == {}

        # Tenant policy changes while the event sits pending.
        policies["tenant-a"] = self.POLICY_V2
        connection.fail_on_insert_prefix = None

        # Restart, empty consumer: reconcile re-decides under the
        # pinned V1 policy and persists both artifacts atomically.
        worker2 = IngestionWorker(
            _StubConsumer([]),
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=lambda t, e: evals.get(t, e) is not None,
            policy_for=lambda t: policies.get(t),
            pending=pending,
            retry_backoff=timedelta(seconds=0),
            dead_letters=dead_letters,
        )
        worker2.run_once(max_events=1)

        persisted_eval = evals.get(env.tenant_id, env.event_id)
        persisted_audit = audit.get(env.tenant_id, env.event_id)
        assert persisted_eval is not None
        assert persisted_audit is not None
        # Same immutable decision on both sides: identical FraudDecision
        # (including decided_at) and the attempt-1 version triple   not
        # the currently loaded V2.
        assert (
            persisted_audit.decision
            == persisted_eval.evaluation.decision
        )
        assert persisted_audit.decision.policy_version == "policy-1"
        assert persisted_audit.decision.rule_version == "rules-1"
        assert persisted_audit.decision.configuration_version == (
            "tenant-config-1"
        )
        assert persisted_eval.evaluation.decision.policy_version == (
            "policy-1"
        )
        assert len(connection.audit_rows) == 1
        assert len(connection.rows) == 1

        # Reconcile again   still exactly one consistent pair.
        worker2.run_once(max_events=1)
        assert len(connection.audit_rows) == 1
        assert len(connection.rows) == 1

    def test_postgres_persistence_is_atomic_on_conflict(self) -> None:
        # First-write-wins across the pair: a re-save keeps the original
        # decision and evaluation rather than mixing versions.
        connection = FakeConnection()
        persistence = PostgresEvaluationPersistence(connection)
        env = envelope()
        orchestrator = ShadowOrchestrator(
            {"tenant-a": self.POLICY_V1},
            evaluations=PostgresShadowEvaluationRepository(connection),
            audit=PostgresDecisionAuditRepository(connection),
            persistence=persistence,
        )
        first = orchestrator.evaluate(env)
        orchestrator.evaluate(env, self.POLICY_V2)
        audit = PostgresDecisionAuditRepository(connection).get(
            env.tenant_id, env.event_id
        )
        evals = PostgresShadowEvaluationRepository(connection).get(
            env.tenant_id, env.event_id
        )
        assert audit is not None and evals is not None
        assert audit.decision == first.decision
        assert evals.evaluation.decision == first.decision
        assert audit.decision.policy_version == "policy-1"



def test_takeover_redelivery_reads_authoritative_owner():
    connection = FakeConnection()
    a = PostgresPendingEvaluationStore(connection, worker_id="a")
    b = PostgresPendingEvaluationStore(connection, worker_id="b")
    env = envelope()
    a.enqueue(env, enqueued_at=T0)
    now = T0 + timedelta(hours=1)
    claimed = b.due(now)[0]
    assert claimed.leased_by == "b"
    assert claimed.leased_until == now + timedelta(minutes=5)
    duplicate = a.enqueue(env, enqueued_at=now)
    assert duplicate.leased_by == "b"
    assert duplicate.leased_until == claimed.leased_until
    a.complete(env.tenant_id, env.event_id, owner="a")
    assert a.enqueue(env, enqueued_at=now).leased_by == "b"


def test_pending_scope_rejects_all_direct_access():
    import pytest
    connection = FakeConnection()
    env = envelope("tenant-b")
    scoped = PostgresPendingEvaluationStore(connection, tenant_ids=("tenant-a",))
    for action in (
        lambda: scoped.enqueue(env, enqueued_at=T0),
        lambda: scoped._get(env.tenant_id, env.event_id),
        lambda: scoped.complete(env.tenant_id, env.event_id),
        lambda: scoped.reschedule(env.tenant_id, env.event_id, error="x", next_attempt_at=T0),
        lambda: PostgresShadowEvaluationRepository(connection, tenant_ids=("tenant-a",)).get(env.tenant_id, env.event_id),
    ):
        with pytest.raises(PermissionError):
            action()
    assert not connection.pending_rows


def test_worker_denies_tenant_before_ingestion():
    import pytest

    from gasha.ingestion.transport import EventBatch
    env = envelope("tenant-b")
    class Consumer:
        commits = 0
        def poll_batch(self, *, max_events=1):
            return EventBatch((inbound_for(env),), 1)
        def commit(self):
            self.commits += 1
    class ForbiddenIngestion:
        dead_letter_sink = InMemoryDeadLetterSink()
        def ingest(self, event):
            raise AssertionError("unauthorized event reached ingestion")
    consumer = Consumer()
    worker = IngestionWorker(consumer, ForbiddenIngestion(), tenant_ids=("tenant-a",))
    with pytest.raises(PermissionError):
        worker.run_once()
    assert consumer.commits == 0
