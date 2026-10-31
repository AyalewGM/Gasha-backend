from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import cast

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
from gasha.ingestion.pending import (
    InMemoryPendingEvaluationStore,
    PendingEvaluationStore,
)
from gasha.ingestion.postgres_store import (
    PostgresDeadLetterSink,
    PostgresIngestionStore,
    PostgresPendingEvaluationStore,
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
    EvaluationPersistence,
    InMemoryShadowEvaluationRepository,
    ShadowEvaluationRepository,
    ShadowOrchestrator,
)
from gasha.postgres import Connection
from gasha.postgres_evaluations import (
    PostgresEvaluationPersistence,
    PostgresShadowEvaluationRepository,
)

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

    # {"<source_system>": "<adapter_type>"}   adapter_type in ADAPTER_TYPES.
    adapter_map: dict[str, str] = {"reference-json": "reference-json"}

    # {"<tenant_id>": {<DecisionPolicy fields>}} JSON file path.
    policies_path: str | None = None

    # When set, durable Postgres stores replace the in-memory references.
    postgres_dsn: str | None = None

    # Trusted tenant authorization for ingestion and durable repositories.
    # REQUIRED (non-empty) whenever postgres_dsn is set   a durable/
    # production worker must not run unscoped. Only the in-memory dev
    # path may run without a scope.
    tenant_ids: list[str] | None = None

    # Stable identity stamped on claimed pending-evaluation leases.
    # Defaults to "<hostname>-<pid>" when unset.
    worker_id: str | None = None

    # Seconds a claimed pending evaluation stays leased to this worker
    # before another worker may take it over (crash recovery window).
    lease_ttl_s: float = 300.0


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
    from psycopg.rows import dict_row

    # dict_row: every repository indexes result rows by column name  
    # psycopg's default tuple rows would raise TypeError/KeyError.
    return cast(
        Connection, psycopg.connect(dsn, row_factory=dict_row)
    )


def _require_durable_tenant_scope(tenant_ids: list[str] | None) -> tuple[str, ...]:
    """Reject ambiguous worker tenant configuration before opening PostgreSQL.

    This is configuration shape validation, not proof of Bank authorization
    or matching database/broker identity privileges.
    """
    if not tenant_ids:
        raise ValueError(
            "GASHA_TENANT_IDS is required when GASHA_POSTGRES_DSN is set"
        )
    if any(
        type(value) is not str
        or not value
        or value != value.strip()
        or not value.isprintable()
        for value in tenant_ids
    ):
        raise ValueError(
            "GASHA_TENANT_IDS must contain nonblank canonical printable tenant IDs"
        )
    if len(set(tenant_ids)) != len(tenant_ids):
        raise ValueError("GASHA_TENANT_IDS must not contain duplicate tenant IDs")
    return tuple(tenant_ids)


def build_stores(
    settings: WorkerSettings,
) -> tuple[
    IngestionStore,
    DeadLetterSink,
    DecisionAuditRepository,
    ShadowEvaluationRepository,
    PendingEvaluationStore,
    EvaluationPersistence | None,
]:
    """Durable stores when a DSN is configured, in-memory otherwise."""
    if settings.postgres_dsn is None:
        logger.warning(
            "GASHA_POSTGRES_DSN unset   using in-memory stores "
            "(dev mode; decisions are not durable)"
        )
        return (
            InMemoryIngestionStore(),
            InMemoryDeadLetterSink(),
            InMemoryDecisionAuditRepository(),
            InMemoryShadowEvaluationRepository(),
            InMemoryPendingEvaluationStore(
                tenant_ids=(
                    tuple(settings.tenant_ids)
                    if settings.tenant_ids is not None
                    else None
                ),
                worker_id=settings.worker_id,
                lease_ttl=timedelta(seconds=settings.lease_ttl_s),
            ),
            None,  # in-memory dev mode keeps the sequential save path
        )

    # Reject malformed deployment scopes before opening any database connection.
    # These configured names do not attest to Bank authorization or DB/Kafka ACLs.
    tenant_ids = _require_durable_tenant_scope(settings.tenant_ids)
    connection = _postgres_connection(settings.postgres_dsn)
    return (
        PostgresIngestionStore(connection, tenant_ids=tenant_ids),
        PostgresDeadLetterSink(connection, tenant_ids=tenant_ids),
        PostgresDecisionAuditRepository(connection, tenant_ids=tenant_ids),
        PostgresShadowEvaluationRepository(connection, tenant_ids=tenant_ids),
        PostgresPendingEvaluationStore(
            connection,
            tenant_ids=tenant_ids,
            worker_id=settings.worker_id,
            lease_ttl=timedelta(seconds=settings.lease_ttl_s),
        ),
        PostgresEvaluationPersistence(connection, tenant_ids=tenant_ids, require_lease=True),
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
    (
        ingestion_store,
        dead_letters,
        audit,
        evaluations,
        pending,
        persistence,
    ) = build_stores(settings)
    ingestion = IngestionService(
        build_adapters(settings),
        store=ingestion_store,
        dead_letters=dead_letters,
        metrics=metrics,
    )
    policies = load_policies(settings.policies_path)
    orchestrator = ShadowOrchestrator(
        policies,
        evaluations=evaluations,
        audit=audit,
        metrics=metrics,
        persistence=persistence,
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
        pending=pending,
        policy_for=lambda tenant_id: policies.get(tenant_id),
        dead_letters=dead_letters,
        metrics=metrics,
        worker_id=settings.worker_id,
        tenant_ids=tuple(settings.tenant_ids) if settings.tenant_ids is not None else None,
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

