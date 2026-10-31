# Issue #43 — POC state and event-port durability inventory

**Source snapshot:** backend main at 32f20f0c44b598db445d47ab3270b6da6d403340 (2026-10-31 review). This document inventories existing code; it does not certify a bank deployment or change the merged #50/#52/#53 worker. Reconcile again when draft #55 (protected API) or other integration PRs land.

## Worker composition and actual selection

The runnable worker in [src/gasha/worker.py](../src/gasha/worker.py) calls build_stores and builds the Confluent Kafka batch consumer + JSON decoder, ingestion service, pending-evaluation worker, and ShadowOrchestrator. **With GASHA_POSTGRES_DSN absent it deliberately selects in-memory stores**, even though its event transport can still be Kafka. With a DSN, it requires a nonempty GASHA_TENANT_IDS and constructs the scoped PostgreSQL stores below. This is an application configuration constraint, **not** proof of bank-granted database roles, row-level security, Kafka ACLs, or tenant identity. See [worker-provisioning](worker-provisioning.md).

| Runtime port / state | Development/default implementation | Durable adapter in repository | Migration(s) | Configured production-worker status |
| --- | --- | --- | --- | --- |
| IngestionStore / idempotency by tenant and event | InMemoryIngestionStore (ingestion/service.py) | PostgresIngestionStore (ingestion/postgres_store.py) | 004 | Wired by build_stores with DSN and tenant scope |
| DeadLetterSink / malformed or terminal event record | InMemoryDeadLetterSink (ingestion/service.py) | PostgresDeadLetterSink (ingestion/postgres_store.py) | 005, 009 for atomic pending terminal state | Wired to ingestion and JSON decoding with DSN |
| DecisionAuditRepository / immutable decision history | InMemoryDecisionAuditRepository (decision/audit.py) | PostgresDecisionAuditRepository (decision/postgres_audit.py) | 001 | Wired with DSN; atomic paired write through EvaluationPersistence |
| ShadowEvaluationRepository / evaluated envelopes | InMemoryShadowEvaluationRepository (orchestration.py) | PostgresShadowEvaluationRepository (postgres_evaluations.py) | 003 | Wired with DSN; same tenant-scoped evaluation path |
| EvaluationPersistence / audit + evaluation pair | None in in-memory worker (sequential writes) | PostgresEvaluationPersistence (postgres_evaluations.py) | 001, 003, 008, 009 | Wired with DSN and require_lease=True; no independent bank fault-injection proof |
| PendingEvaluationStore / retry, lease and terminal ledger | InMemoryPendingEvaluationStore (ingestion/pending.py) | PostgresPendingEvaluationStore (ingestion/postgres_store.py) | 007, 008, 009 | Wired with DSN, worker ID, lease TTL and tenant scope; merged worker recovery must not be rewritten |
| JourneyEventRepository / authentication and behavior journey | InMemoryJourneyEventRepository (journey/repository.py) | PostgresJourneyEventRepository (journey/postgres_repository.py) | 002 | **Adapter exists; build_worker does not wire a JourneyIngestionService or journey repository into its orchestrator** |
| OutcomeStore / confirmed and incumbent outcomes | InMemoryOutcomeStore (ingestion/outcome_ingestion.py) | PostgresOutcomeStore (ingestion/postgres_store.py) | 006 | **Adapter exists but default main API constructs OutcomeIngestionService without it**; draft #55 keeps protected outcome mutation disabled |
| Runtime decision policies / approved config | WorkerSettings environment + policy file loader | No worker-selected PostgreSQL policy/config authority in this snapshot | Not established | **External bank-authorized policy/config and historical version authority not wired** |
| MetricsRegistry / counters and latency | InMemoryMetricsRegistry (observability/metrics.py) | No durable metrics exporter composed by the worker here | Not applicable | Process-local telemetry; not a bank evidence register |

Migration filenames and order are in [db/migrations](../db/migrations): 001 decision audit, 002 journey events, 003 shadow evaluations, 004 ingestion, 005 dead letters, 006 outcome records, 007 pending evaluations, 008 lease fencing, and 009 pending terminal state. Bank deployment must apply and verify required migration versions before starting the matching worker binary. The existing lease-fencing/mixed-version warnings remain authoritative in [worker-provisioning](worker-provisioning.md).

## Event transport: consumer and publisher must not be conflated

- [ingestion/bus.py](../src/gasha/ingestion/bus.py) defines FraudEventPublisher and FraudEventConsumer ports, plus InMemoryEventBus for deterministic tests.
- The configured worker uses ConfluentKafkaConsumer from [ingestion/kafka_confluent.py](../src/gasha/ingestion/kafka_confluent.py) as a BatchConsumer, wrapped by JsonEventConsumer from [ingestion/kafka_json.py](../src/gasha/ingestion/kafka_json.py), then IngestionWorker from [ingestion/worker.py](../src/gasha/ingestion/worker.py). Consumption, poisoned-message dead lettering, explicit commit and durable recovery are the accepted bounded #52/#53 path.
- **No production FraudEventPublisher adapter is composed into this worker in the reviewed tree.** A working Kafka consumer is not proof of the issue's full publisher-and-consumer transport requirement. Architecture must decide whether bank producer integration is external to Gasha or requires a new adapter; do not invent bank broker selection or ACLs.

## API, synthetic and deployment boundaries

The default main API at [api/main.py](../src/gasha/api/main.py) uses a process-local default outcome service and accepts request-supplied policy/intelligence; it is **not** an authenticated bank integration. Draft PR #55 proposes the protected API and disables its outcome mutations rather than claiming an atomic audited bank write. Synthetic replay and load baselines use in-memory ports by design. None supplies bank-approved identity, protected image/proxy integration, durable outcome submission, historical dataset/source-time lineage, or evidence approval authority.

**Known incomplete or conditional connections** (issue owners remain separate):
1. #43: declare the complete intended production port graph (including journey events, outcomes and publisher), test actual configured composition, and document any deliberate external producer.
2. #42/#46: bank-approved service identity, DB/Kafka least-privilege grants, image digest/migrations, secrets/rotation, ingress, authenticated negative tests and rollback.
3. #43/#47: real PostgreSQL + broker outage/recovery, process kill/rebalance, duplicate and DLQ accounting, and representative load evidence pinned to image/SHA/config.
4. #48/#49: dataset/policy/signal versions and trusted approval/evidence source binding; never equate an in-memory/synthetic green test with CBE readiness.

## Evidence classification

The repo already includes deterministic tests for ingestion, pending-lease fencing, Kafka decoding, worker entrypoint, PostgreSQL adapters/integration, and shadow orchestration (see tests/). The merged #52/#53 CI evidence is bounded worker durability **only**. This inventory is a static **source-inspection deliverable**; no broker outage, process-kill, configured bank image/proxy, runtime credential/ACL, or live bank test has been run as part of this document. It makes no merge, readiness, SLA, or enforcement claim.
