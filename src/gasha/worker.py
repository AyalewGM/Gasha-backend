from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from gasha.decision.audit import (
    DecisionAuditRepository,
    InMemoryDecisionAuditRepository,
)
from gasha.decision.postgres_audit import PostgresDecisionAuditRepository
from gasha.domain.models import DecisionPolicy
from gasha.ingestion.adapter import BankEventAdapter
from gasha.ingestion.kafka_confluent import ConfluentKafkaConsumer
from gasha.ingestion.kafka_json import JsonEventConsumer
from gasha.ingestion.postgres_evaluations import (
    PostgresShadowEvaluationRepository,
)
from gasha.ingestion.postgres_store import (
    PostgresDeadLetterSink,
    PostgresIngestionStore,
)
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import (
    DeadLetterSink,
    IngestionService,
    IngestionStore,
    InMemoryDeadLetterSink,
    InMemoryIngestionStore,
)
from gasha.ingestion.worker import IngestionWorker
from gasha.observability.metrics import InMemoryMetricsRegistry
from gasha.orchestration import (
    InMemoryShadowEvaluationRepository,
    ShadowEvaluationRepository,
    ShadowOrchestrator,
)
from gasha.postgres import Connection

logger = logging.getLogger("gasha.worker")

# Registered adapter types; bank adapters join this map as they are built.
ADAPTER_TYPES: dict[str, Callable[[], BankEventAdapter]] = {
    "reference-json": ReferenceJsonAdapter,
}


class WorkerSettings(BaseSettings):
    """Composition config for the ingestion worker (``GASHA_*`` env vars)."""

    model_config = SettingsConfigDict(env_prefix="GASHA_")

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "gasha.fraud-events"
    kafka_group_id: str = "gasha-ingestion-worker"
    poll_timeout_s: float = 1.0
    batch_size: int = 50

    # {"<source_system>": "<adapter_type>"} — adapter_type in ADAPTER_TYPES.
    adapter_map: dict[str, str] = {"reference-json": "reference-json"}

    # {"<tenant_id>": {<DecisionPolicy fields>}} JSON file path.
    policies_path: str | None = None

    # When set, durable Postgres stores replace the in-memory references.
    postgres_dsn: str | None = None


class PolicyFile(BaseModel):
    policies: dict[str, DecisionPolicy]


def load_policies(path: str | None) -> dict[str, DecisionPolicy]:
    if path is None:
        return {}
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict) and "policies" not in data:
        data = {"policies": data}
    return PolicyFile.model_validate(data).policies


def _postgres_connection(dsn: str) -> Connection:
    import psycopg

    connection: Connection = psycopg.connect(dsn)
    return connection


def build_stores(
    settings: WorkerSettings,
) -> tuple[
    IngestionStore,
    DeadLetterSink,
    DecisionAuditRepository,
    ShadowEvaluationRepository,
]:
    """Durable stores when a DSN is configured, in-memory otherwise."""
    if settings.postgres_dsn is None:
        logger.warning(
            "GASHA_POSTGRES_DSN unset — using in-memory stores "
            "(dev mode; decisions are not durable)"
        )
        return (
            InMemoryIngestionStore(),
            InMemoryDeadLetterSink(),
            InMemoryDecisionAuditRepository(),
            InMemoryShadowEvaluationRepository(),
        )

    connection = _postgres_connection(settings.postgres_dsn)
    return (
        PostgresIngestionStore(connection),
        PostgresDeadLetterSink(connection),
        PostgresDecisionAuditRepository(connection),
        PostgresShadowEvaluationRepository(connection),
    )


def build_adapters(
    settings: WorkerSettings,
) -> dict[str, BankEventAdapter]:
    adapters: dict[str, BankEventAdapter] = {}
    for source_system, adapter_type in settings.adapter_map.items():
        factory = ADAPTER_TYPES.get(adapter_type)
        if factory is None:
            raise ValueError(
                f"unknown adapter_type {adapter_type!r} for source "
                f"{source_system!r}; known: {sorted(ADAPTER_TYPES)}"
            )
        adapters[source_system] = factory()
    return adapters


def build_worker(
    settings: WorkerSettings,
) -> tuple[IngestionWorker, ConfluentKafkaConsumer]:
    metrics = InMemoryMetricsRegistry()
    ingestion_store, dead_letters, audit, evaluations = build_stores(settings)
    ingestion = IngestionService(
        build_adapters(settings),
        store=ingestion_store,
        dead_letters=dead_letters,
        metrics=metrics,
    )
    orchestrator = ShadowOrchestrator(
        load_policies(settings.policies_path),
        evaluations=evaluations,
        audit=audit,
        metrics=metrics,
    )
    consumer = ConfluentKafkaConsumer.build(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_group_id,
        topics=[settings.kafka_topic],
        poll_timeout_s=settings.poll_timeout_s,
    )
    worker = IngestionWorker(
        JsonEventConsumer(consumer, dead_letters=dead_letters),
        ingestion,
        evaluate=orchestrator.evaluate,
        evaluation_complete=lambda tenant_id, event_id: (
            evaluations.get(tenant_id, event_id) is not None
        ),
        dead_letters=dead_letters,
        metrics=metrics,
    )
    return worker, consumer


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = WorkerSettings()
    worker, consumer = build_worker(settings)
    logger.info(
        "gasha ingestion worker consuming %s from %s (group %s)",
        settings.kafka_topic,
        settings.kafka_bootstrap_servers,
        settings.kafka_group_id,
    )
    try:
        while True:
            worker.run_once(max_events=settings.batch_size)
    except KeyboardInterrupt:
        logger.info("worker stopped")
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
