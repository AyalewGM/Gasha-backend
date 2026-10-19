from __future__ import annotations

import json

import pytest

from gasha.domain.models import DecisionPolicy
from gasha.ingestion.kafka_confluent import ConfluentKafkaConsumer
from gasha.ingestion.pending import InMemoryPendingEvaluationStore
from gasha.ingestion.postgres_store import PostgresIngestionStore
from gasha.ingestion.service import (
    InMemoryDeadLetterSink,
    InMemoryIngestionStore,
)
from gasha.worker import (
    WorkerSettings,
    build_adapters,
    build_stores,
    load_policies,
)


class TestWorkerSettings:
    def test_defaults_are_local_dev(self, monkeypatch) -> None:
        for var in (
            "GASHA_KAFKA_BOOTSTRAP_SERVERS",
            "GASHA_ADAPTER_MAP",
            "GASHA_POSTGRES_DSN",
            "GASHA_POLICIES_PATH",
        ):
            monkeypatch.delenv(var, raising=False)
        settings = WorkerSettings()
        assert settings.kafka_bootstrap_servers == "localhost:9092"
        assert settings.kafka_topic == "gasha.fraud-events"
        assert settings.postgres_dsn is None

    def test_adapter_map_parses_json_env(self, monkeypatch) -> None:
        monkeypatch.setenv(
            "GASHA_ADAPTER_MAP",
            '{"core-banking": "reference-json"}',
        )
        settings = WorkerSettings()
        assert settings.adapter_map == {"core-banking": "reference-json"}


class TestLoadPolicies:
    def test_loads_tenant_policy_map(self, tmp_path) -> None:
        path = tmp_path / "policies.json"
        path.write_text(
            json.dumps(
                {
                    "tenant-a": {
                        "configuration_version": "cfg-1",
                        "policy_version": "pol-1",
                        "rule_version": "rules-1",
                        "monitor_threshold": 0.4,
                        "review_threshold": 0.6,
                        "hold_threshold": 0.8,
                        "block_threshold": 0.95,
                    }
                }
            )
        )
        policies = load_policies(str(path))
        assert isinstance(policies["tenant-a"], DecisionPolicy)
        assert policies["tenant-a"].monitor_threshold == 0.4

    def test_missing_path_means_no_policies(self) -> None:
        assert load_policies(None) == {}

    def test_wrapped_policies_key_also_accepted(self, tmp_path) -> None:
        path = tmp_path / "policies.json"
        path.write_text(
            json.dumps(
                {
                    "policies": {
                        "t": {
                            "configuration_version": "c",
                            "policy_version": "p",
                            "rule_version": "r",
                        }
                    }
                }
            )
        )
        assert set(load_policies(str(path))) == {"t"}


class TestBuildAdapters:
    def test_maps_source_systems_to_adapters(self) -> None:
        settings = WorkerSettings(
            adapter_map={
                "synthetic-core-banking": "reference-json",
            }
        )
        adapters = build_adapters(settings)
        assert set(adapters) == {"synthetic-core-banking"}
        assert adapters["synthetic-core-banking"].adapter_type == "reference-json"

    def test_unknown_adapter_type_rejected(self) -> None:
        settings = WorkerSettings(adapter_map={"x": "does-not-exist"})
        with pytest.raises(ValueError, match="unknown adapter_type"):
            build_adapters(settings)


class TestBuildStores:
    def test_in_memory_when_no_dsn(self) -> None:
        ingestion, dead_letters, _, _, pending, persistence = build_stores(
            WorkerSettings()
        )
        assert persistence is None
        assert isinstance(ingestion, InMemoryIngestionStore)
        assert isinstance(dead_letters, InMemoryDeadLetterSink)
        assert isinstance(pending, InMemoryPendingEvaluationStore)


class _FakeError:
    def __init__(self, fatal: bool) -> None:
        self._fatal = fatal

    def fatal(self) -> bool:
        return self._fatal


class _FakeMessage:
    def __init__(self, value: bytes, error=None) -> None:
        self._value = value
        self._error = error

    def value(self) -> bytes:
        return self._value

    def topic(self) -> str:
        return "gasha.fraud-events"

    def partition(self) -> int:
        return 0

    def offset(self) -> int:
        return 7

    def error(self):
        return self._error


class _FakeConsumer:
    def __init__(self, messages: list[_FakeMessage]) -> None:
        self._messages = list(messages)
        self.commits: list[bool] = []
        self.closed = False

    def consume(self, num_messages: int, timeout: float) -> list[_FakeMessage]:
        batch = self._messages[:num_messages]
        del self._messages[:num_messages]
        return batch

    def commit(self, asynchronous: bool = False) -> None:
        self.commits.append(asynchronous)

    def close(self) -> None:
        self.closed = True


class TestConfluentKafkaConsumer:
    def test_poll_batch_wraps_messages_as_records(self) -> None:
        inner = _FakeConsumer([_FakeMessage(b"{}"), _FakeMessage(b"[]")])
        consumer = ConfluentKafkaConsumer(inner)
        batch = consumer.poll_batch(max_records=10)
        assert [r.value for r in batch] == [b"{}", b"[]"]
        assert batch[0].topic == "gasha.fraud-events"
        assert batch[0].offset == 7

    def test_nonfatal_errors_are_skipped(self) -> None:
        inner = _FakeConsumer(
            [
                _FakeMessage(b"", error=_FakeError(fatal=False)),
                _FakeMessage(b"{}"),
            ]
        )
        consumer = ConfluentKafkaConsumer(inner)
        batch = consumer.poll_batch(max_records=10)
        assert len(batch) == 1

    def test_fatal_error_raises(self) -> None:
        inner = _FakeConsumer([_FakeMessage(b"", error=_FakeError(fatal=True))])
        consumer = ConfluentKafkaConsumer(inner)
        with pytest.raises(RuntimeError, match="fatal kafka error"):
            consumer.poll_batch(max_records=10)

    def test_commit_is_synchronous(self) -> None:
        inner = _FakeConsumer([])
        consumer = ConfluentKafkaConsumer(inner)
        consumer.commit()
        assert inner.commits == [False]


def test_postgres_store_import_surface() -> None:
    # Postgres stores are wired by build_stores only when a DSN is set;
    # importing must not require psycopg.
    assert PostgresIngestionStore is not None
