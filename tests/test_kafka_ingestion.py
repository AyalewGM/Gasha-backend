from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from gasha.decision.audit import InMemoryDecisionAuditRepository
from gasha.domain.models import DecisionAction, DecisionPolicy, OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent
from gasha.ingestion.errors import RejectionReason
from gasha.ingestion.kafka_json import JsonEventConsumer
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import (
    IngestionOutcome,
    IngestionService,
    InMemoryDeadLetterSink,
)
from gasha.ingestion.worker import IngestionWorker
from gasha.orchestration import (
    InMemoryShadowEvaluationRepository,
    ShadowOrchestrator,
)
from gasha.poc.historical import MissingTenantPolicyError

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)

POLICY = DecisionPolicy(
    configuration_version="tenant-config-1",
    policy_version="policy-1",
    rule_version="rules-1",
)


class FakeRecord:
    def __init__(self, value: bytes, offset: int, partition: int = 0) -> None:
        self._value = value
        self._offset = offset
        self._partition = partition

    @property
    def value(self) -> bytes:
        return self._value

    @property
    def topic(self) -> str:
        return "gasha.fraud-events"

    @property
    def partition(self) -> int:
        return self._partition

    @property
    def offset(self) -> int:
        return self._offset


class FakeBatchConsumer:
    """Records poll in order; commit marks them acknowledged."""

    def __init__(self, records: list[FakeRecord]) -> None:
        self._records = list(records)
        self._pending: list[FakeRecord] = []
        self.commits = 0

    def poll_batch(self, *, max_records: int) -> tuple[FakeRecord, ...]:
        batch = tuple(self._records[:max_records])
        del self._records[: len(batch)]
        self._pending.extend(batch)
        return batch

    def commit(self) -> None:
        self._pending.clear()
        self.commits += 1


def event_json(**overrides) -> bytes:
    payload = {
        "event_id": str(uuid4()),
        "occurred_at": T0.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "100.00",
        "currency": "ETB",
        "sender_customer_id": "c1",
        "sender_account_id": "a1",
        "beneficiary_id": "b1",
        "beneficiary_type": "external",
        "destination_institution_id": "bank-b",
        "correlation_id": "corr-1",
    }
    body = {
        "tenant_id": "tenant-a",
        "source_system": "synthetic-core-banking",
        "schema_version": "1.0",
        "payload": payload,
    }
    return json.dumps(body | overrides).encode()


def make_consumer(
    records: list[FakeRecord],
) -> tuple[JsonEventConsumer, FakeBatchConsumer, InMemoryDeadLetterSink]:
    batch_consumer = FakeBatchConsumer(records)
    dead_letters = InMemoryDeadLetterSink()
    return (
        JsonEventConsumer(batch_consumer, dead_letters=dead_letters),
        batch_consumer,
        dead_letters,
    )


def make_ingestion() -> IngestionService:
    return IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()}
    )


def make_worker(
    consumer: JsonEventConsumer,
    dead_letters: InMemoryDeadLetterSink,
    ingestion: IngestionService | None = None,
    evaluate=None,
    evaluation_complete=None,
) -> IngestionWorker:
    return IngestionWorker(
        consumer,
        ingestion or make_ingestion(),
        evaluate=evaluate,
        evaluation_complete=evaluation_complete,
        dead_letters=dead_letters,
    )


class TestJsonEventConsumer:
    def test_decodes_valid_records_in_order(self) -> None:
        consumer, _, _ = make_consumer(
            [FakeRecord(event_json(), 0), FakeRecord(event_json(), 1)]
        )
        batch = consumer.poll_batch(max_events=10)
        assert batch.records_consumed == 2
        assert len(batch.events) == 2
        assert all(isinstance(e, InboundBankEvent) for e in batch.events)
        assert batch.events[0].tenant_id == "tenant-a"

    def test_malformed_json_is_dead_lettered_with_coordinates(self) -> None:
        consumer, batch_consumer, dead_letters = make_consumer(
            [
                FakeRecord(b"{not json", 5, partition=2),
                FakeRecord(event_json(), 6, partition=2),
            ]
        )
        batch = consumer.poll_batch(max_events=10)
        assert len(batch.events) == 1
        assert batch.records_consumed == 2
        assert len(dead_letters.records) == 1
        rejection = dead_letters.records[0]
        assert rejection.reason == RejectionReason.INVALID_SCHEMA
        assert rejection.topic == "gasha.fraud-events"
        assert rejection.partition == 2
        assert rejection.offset == 5
        # The poison record did not stall the partition.
        assert batch_consumer._records == []

    def test_non_object_json_is_dead_lettered(self) -> None:
        consumer, _, dead_letters = make_consumer(
            [FakeRecord(b'["a","b"]', 0)]
        )
        assert consumer.poll_batch(max_events=1).events == ()
        assert dead_letters.records[0].reason == RejectionReason.INVALID_SCHEMA

    def test_schema_invalid_event_is_dead_lettered(self) -> None:
        consumer, _, dead_letters = make_consumer(
            [FakeRecord(event_json(tenant_id=""), 0)]
        )
        assert consumer.poll_batch(max_events=1).events == ()
        record = dead_letters.records[0]
        assert record.reason == RejectionReason.INVALID_SCHEMA

    def test_commit_delegates_to_batch_consumer(self) -> None:
        consumer, batch_consumer, _ = make_consumer([FakeRecord(event_json(), 0)])
        consumer.poll_batch(max_events=1)
        consumer.commit()
        assert batch_consumer.commits == 1


class TestIngestionWorker:
    def test_accepted_event_is_evaluated_then_committed(self) -> None:
        evaluated: list[FraudEventEnvelope] = []
        consumer, batch_consumer, dead_letters = make_consumer(
            [FakeRecord(event_json(), 0)]
        )
        worker = make_worker(consumer, dead_letters, evaluate=evaluated.append)

        assert worker.run_once(max_events=10) == 1
        assert len(evaluated) == 1
        assert batch_consumer.commits == 1

    def test_duplicate_delivery_skips_evaluation_when_complete(self) -> None:
        event_id = str(uuid4())
        body = json.loads(event_json())
        body["payload"]["event_id"] = event_id
        records = [
            FakeRecord(json.dumps(body).encode(), 0),
            FakeRecord(json.dumps(body).encode(), 1),
        ]
        evaluated: list[FraudEventEnvelope] = []
        completed: set[tuple[str, object]] = set()

        def evaluate(envelope: FraudEventEnvelope) -> None:
            evaluated.append(envelope)
            completed.add((envelope.tenant_id, envelope.event_id))

        consumer, batch_consumer, dead_letters = make_consumer(records)
        worker = make_worker(
            consumer,
            dead_letters,
            evaluate=evaluate,
            evaluation_complete=lambda t, e: (t, e) in completed,
        )

        worker.run_once(max_events=10)
        assert len(evaluated) == 1
        assert batch_consumer.commits == 1

    def test_malformed_only_batch_commits_once(self) -> None:
        consumer, batch_consumer, dead_letters = make_consumer(
            [FakeRecord(b"garbage", 0), FakeRecord(b"[1,2", 1)]
        )
        worker = make_worker(consumer, dead_letters)

        assert worker.run_once(max_events=10) == 2
        assert batch_consumer.commits == 1
        assert len(dead_letters.records) == 2

        # Simulated restart/redelivery: nothing pending, no re-dead-letter.
        assert worker.run_once(max_events=10) == 0
        assert len(dead_letters.records) == 2

    def test_mixed_valid_invalid_batch_offsets_commit(self) -> None:
        consumer, batch_consumer, dead_letters = make_consumer(
            [
                FakeRecord(b"bad", 10),
                FakeRecord(event_json(), 11),
                FakeRecord(b"worse", 12),
            ]
        )
        worker = make_worker(consumer, dead_letters)
        worker.run_once(max_events=10)
        assert batch_consumer.commits == 1
        assert [r.offset for r in dead_letters.records] == [10, 12]

    def test_missing_policy_is_dead_lettered_not_raised(self) -> None:
        def evaluate(_: FraudEventEnvelope) -> None:
            raise MissingTenantPolicyError("no policy")

        consumer, _, dead_letters = make_consumer([FakeRecord(event_json(), 0)])
        worker = make_worker(consumer, dead_letters, evaluate=evaluate)

        worker.run_once(max_events=1)
        assert (
            dead_letters.records[0].reason
            == RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE
        )

    def test_unexpected_evaluation_error_is_dead_lettered(self) -> None:
        def evaluate(_: FraudEventEnvelope) -> None:
            raise RuntimeError("db down")

        consumer, _, dead_letters = make_consumer([FakeRecord(event_json(), 0)])
        worker = make_worker(consumer, dead_letters, evaluate=evaluate)

        worker.run_once(max_events=1)
        assert dead_letters.records[0].reason == RejectionReason.EVALUATION_FAILURE

    def test_empty_poll_does_not_commit(self) -> None:
        consumer, batch_consumer, dead_letters = make_consumer([])
        worker = make_worker(consumer, dead_letters)
        assert worker.run_once(max_events=10) == 0
        assert batch_consumer.commits == 0

    def test_no_evaluate_callable_still_commits(self) -> None:
        consumer, batch_consumer, dead_letters = make_consumer(
            [FakeRecord(event_json(), 0)]
        )
        worker = make_worker(consumer, dead_letters)
        assert worker.run_once(max_events=1) == 1
        assert batch_consumer.commits == 1


class TestEvaluationRecovery:
    """Failure injection: evaluation fails after durable ingest; redelivery
    must complete the missing evaluation exactly once."""

    def test_redelivery_completes_missing_evaluation(self) -> None:
        body = json.loads(event_json())
        event_id = body["payload"]["event_id"]

        ingestion = make_ingestion()
        evaluated: list[FraudEventEnvelope] = []
        completed: set[tuple[str, object]] = set()
        attempts = {"n": 0}

        def flaky_evaluate(envelope: FraudEventEnvelope) -> None:
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("audit store unavailable")
            evaluated.append(envelope)
            completed.add((envelope.tenant_id, envelope.event_id))

        # First delivery: ingest ACCEPTED, evaluation fails, batch commits.
        consumer1, batch1, dead_letters = make_consumer(
            [FakeRecord(json.dumps(body).encode(), 0)]
        )
        worker1 = make_worker(
            consumer1,
            dead_letters,
            ingestion=ingestion,
            evaluate=flaky_evaluate,
            evaluation_complete=lambda t, e: (t, e) in completed,
        )
        worker1.run_once(max_events=1)
        assert batch1.commits == 1
        assert len(evaluated) == 0
        assert dead_letters.records[0].reason == (
            RejectionReason.EVALUATION_FAILURE
        )

        # Redelivery after restart: DUPLICATE ingest but evaluation was
        # never durable — re-evaluate using the stored original envelope.
        consumer2, batch2, _ = make_consumer(
            [FakeRecord(json.dumps(body).encode(), 1)]
        )
        worker2 = make_worker(
            consumer2,
            dead_letters,
            ingestion=ingestion,
            evaluate=flaky_evaluate,
            evaluation_complete=lambda t, e: (t, e) in completed,
        )
        worker2.run_once(max_events=1)

        assert len(evaluated) == 1
        assert str(evaluated[0].event_id) == event_id
        assert batch2.commits == 1

        # Third delivery: evaluation is durable now — skipped.
        consumer3, _, _ = make_consumer(
            [FakeRecord(json.dumps(body).encode(), 2)]
        )
        worker3 = make_worker(
            consumer3,
            dead_letters,
            ingestion=ingestion,
            evaluate=flaky_evaluate,
            evaluation_complete=lambda t, e: (t, e) in completed,
        )
        worker3.run_once(max_events=1)
        assert len(evaluated) == 1


class TestKafkaToDecisionEndToEnd:
    """Record on the wire -> normalized -> deduplicated -> shadow evaluation."""

    def test_shadow_evaluated_and_audited(self) -> None:
        records = [FakeRecord(event_json(), 0)]
        consumer, _, dead_letters = make_consumer(records)
        ingestion = make_ingestion()
        evaluations = InMemoryShadowEvaluationRepository()
        audit = InMemoryDecisionAuditRepository()
        orchestrator = ShadowOrchestrator(
            {"tenant-a": POLICY},
            evaluations=evaluations,
            audit=audit,
        )
        worker = IngestionWorker(
            consumer,
            ingestion,
            evaluate=orchestrator.evaluate,
            evaluation_complete=(
                lambda t, e: evaluations.get(t, e) is not None
            ),
            dead_letters=dead_letters,
        )

        assert worker.run_once(max_events=1) == 1

        stored = evaluations._records
        assert len(stored) == 1
        record = next(iter(stored.values()))
        assert record.evaluation.operating_mode == OperatingMode.SHADOW
        assert record.evaluation.effective_action == DecisionAction.NO_ACTION_SHADOW
        assert record.evaluation.decision.action == DecisionAction.ALLOW

        audited = next(iter(audit._records.values()))
        assert audited.decision.event_id == record.event.event_id

    def test_crash_between_ingest_and_evaluate_recovers_via_orchestrator(
        self,
    ) -> None:
        body = json.loads(event_json())
        ingestion = make_ingestion()
        evaluations = InMemoryShadowEvaluationRepository()
        audit = InMemoryDecisionAuditRepository()
        orchestrator = ShadowOrchestrator(
            {"tenant-a": POLICY},
            evaluations=evaluations,
            audit=audit,
        )
        dead_letters = InMemoryDeadLetterSink()

        calls = {"n": 0}
        original = orchestrator.evaluate

        def crashing_evaluate(envelope: FraudEventEnvelope) -> object:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated crash")
            return original(envelope)

        consumer1, _, _ = make_consumer(
            [FakeRecord(json.dumps(body).encode(), 0)]
        )
        worker = IngestionWorker(
            consumer1,
            ingestion,
            evaluate=crashing_evaluate,
            evaluation_complete=(
                lambda t, e: evaluations.get(t, e) is not None
            ),
            dead_letters=dead_letters,
        )
        worker.run_once(max_events=1)
        assert len(evaluations._records) == 0

        # Redelivery: completes evaluation + audit exactly once.
        consumer2, _, _ = make_consumer(
            [FakeRecord(json.dumps(body).encode(), 1)]
        )
        worker2 = IngestionWorker(
            consumer2,
            ingestion,
            evaluate=crashing_evaluate,
            evaluation_complete=(
                lambda t, e: evaluations.get(t, e) is not None
            ),
            dead_letters=dead_letters,
        )
        worker2.run_once(max_events=1)

        assert len(evaluations._records) == 1
        assert len(audit._records) == 1
        record = next(iter(evaluations._records.values()))
        assert record.event.adapter.adapter_type == "reference-json"
        assert record.evaluation.decision.rule_version == "rules-1"


def test_pipeline_rejects_then_continues() -> None:
    ingestion = make_ingestion()
    result = ingestion.ingest(
        InboundBankEvent(
            tenant_id="tenant-a",
            source_system="synthetic-core-banking",
            schema_version="9.9",
            payload={"x": 1},
        )
    )
    assert result.outcome == IngestionOutcome.REJECTED


@pytest.mark.parametrize("mode", [OperatingMode.SHADOW, OperatingMode.ENFORCING])
def test_worker_respects_operating_mode(mode: OperatingMode) -> None:
    body = json.loads(event_json())
    body["payload"]["operating_mode"] = mode.value
    records = [FakeRecord(json.dumps(body).encode(), 0)]
    consumer, _, dead_letters = make_consumer(records)
    seen: list[FraudEventEnvelope] = []
    worker = IngestionWorker(
        consumer,
        make_ingestion(),
        evaluate=seen.append,
        dead_letters=dead_letters,
    )
    worker.run_once(max_events=1)
    assert seen[0].operating_mode == mode
