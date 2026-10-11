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
    def __init__(self, value: bytes, offset: int) -> None:
        self._value = value
        self._offset = offset

    @property
    def value(self) -> bytes:
        return self._value

    @property
    def topic(self) -> str:
        return "fraud-events"

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


def make_consumer(records: list[FakeRecord]) -> tuple[JsonEventConsumer, FakeBatchConsumer, InMemoryDeadLetterSink]:
    batch_consumer = FakeBatchConsumer(records)
    dead_letters = InMemoryDeadLetterSink()
    return (
        JsonEventConsumer(batch_consumer, dead_letters=dead_letters),
        batch_consumer,
        dead_letters,
    )


def make_worker(
    consumer: JsonEventConsumer,
    dead_letters: InMemoryDeadLetterSink,
    evaluate=None,
) -> IngestionWorker:
    ingestion = IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()}
    )
    return IngestionWorker(
        consumer,
        ingestion,
        evaluate=evaluate,
        dead_letters=dead_letters,
    )


class TestJsonEventConsumer:
    def test_decodes_valid_records_in_order(self) -> None:
        consumer, _, _ = make_consumer(
            [FakeRecord(event_json(), 0), FakeRecord(event_json(), 1)]
        )
        events = consumer.poll_events(max_events=10)
        assert len(events) == 2
        assert all(isinstance(e, InboundBankEvent) for e in events)
        assert events[0].tenant_id == "tenant-a"

    def test_malformed_json_is_dead_lettered_and_skipped(self) -> None:
        consumer, batch, dead_letters = make_consumer(
            [
                FakeRecord(b"{not json", 0),
                FakeRecord(event_json(), 1),
            ]
        )
        events = consumer.poll_events(max_events=10)
        assert len(events) == 1
        assert len(dead_letters.records) == 1
        assert dead_letters.records[0].reason == RejectionReason.INVALID_SCHEMA
        # The poison record did not stall the partition.
        assert batch._records == []

    def test_non_object_json_is_dead_lettered(self) -> None:
        consumer, _, dead_letters = make_consumer(
            [FakeRecord(b'["a","b"]', 0)]
        )
        assert consumer.poll_events(max_events=1) == ()
        assert dead_letters.records[0].reason == RejectionReason.INVALID_SCHEMA

    def test_schema_invalid_event_is_dead_lettered(self) -> None:
        consumer, _, dead_letters = make_consumer(
            [FakeRecord(event_json(tenant_id=""), 0)]
        )
        assert consumer.poll_events(max_events=1) == ()
        record = dead_letters.records[0]
        assert record.reason == RejectionReason.INVALID_SCHEMA

    def test_commit_delegates_to_batch_consumer(self) -> None:
        consumer, batch, _ = make_consumer([FakeRecord(event_json(), 0)])
        consumer.poll_events(max_events=1)
        consumer.commit()
        assert batch.commits == 1


class TestIngestionWorker:
    def test_accepted_event_is_evaluated_then_committed(self) -> None:
        evaluated: list[FraudEventEnvelope] = []
        consumer, batch, dead_letters = make_consumer(
            [FakeRecord(event_json(), 0)]
        )
        worker = make_worker(consumer, dead_letters, evaluate=evaluated.append)

        assert worker.run_once(max_events=10) == 1
        assert len(evaluated) == 1
        assert batch.commits == 1

    def test_duplicate_delivery_skips_evaluation(self) -> None:
        event_id = str(uuid4())
        raw = event_json()
        # Same event_id re-delivered (e.g. after a pre-commit crash).
        body = json.loads(raw)
        body["payload"]["event_id"] = event_id
        records = [
            FakeRecord(json.dumps(body).encode(), 0),
            FakeRecord(json.dumps(body).encode(), 1),
        ]
        evaluated: list[FraudEventEnvelope] = []
        consumer, batch, dead_letters = make_consumer(records)
        worker = make_worker(consumer, dead_letters, evaluate=evaluated.append)

        worker.run_once(max_events=10)
        assert len(evaluated) == 1
        assert batch.commits == 1

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
        consumer, batch, dead_letters = make_consumer([])
        worker = make_worker(consumer, dead_letters)
        assert worker.run_once(max_events=10) == 0
        assert batch.commits == 0

    def test_no_evaluate_callable_still_commits(self) -> None:
        consumer, batch, dead_letters = make_consumer(
            [FakeRecord(event_json(), 0)]
        )
        worker = make_worker(consumer, dead_letters)
        assert worker.run_once(max_events=1) == 1
        assert batch.commits == 1


class TestKafkaToDecisionEndToEnd:
    """Record on the wire -> normalized -> deduplicated -> shadow evaluation."""

    def test_shadow_evaluated_and_audited(self) -> None:
        records = [FakeRecord(event_json(), 0)]
        consumer, _, dead_letters = make_consumer(records)
        ingestion = IngestionService(
            {"synthetic-core-banking": ReferenceJsonAdapter()}
        )
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


def test_pipeline_rejects_then_continues() -> None:
    ingestion = IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()}
    )
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
    ingestion = IngestionService(
        {"synthetic-core-banking": ReferenceJsonAdapter()}
    )
    seen: list[FraudEventEnvelope] = []
    worker = IngestionWorker(
        consumer, ingestion, evaluate=seen.append, dead_letters=dead_letters
    )
    worker.run_once(max_events=1)
    assert seen[0].operating_mode == mode
