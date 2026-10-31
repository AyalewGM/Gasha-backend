# Issue #45 — stacked durable case/audit transaction candidate

This is a **draft internal integration slice**. Its parent PR #64
(https://github.com/AyalewGM/Gasha-backend/pull/64) was integrated internally
as main commit `5c05a8c1`. PR #65 is retargeted to `main`; its scope remains
migration 011, this adapter, PostgreSQL tests and this document.
It is **not activated** in a protected HTTP route, worker, analyst UI,
bank case system, or stage/readiness evaluator. It does not touch merged
#52/#53, or merge/repurpose merged #54. The Security & Architecture contract
is on Issue #45 (https://github.com/AyalewGM/Gasha-backend/issues/45#issuecomment-6547290823).

## Implemented (opt-in only)

- Migration 011 creates an append-only-oriented tenant/case/revision history table.
  Tenant/case/revision uniqueness plus tenant/idempotency-hash uniqueness enforce
  revisions and actor-scoped retry-key uniqueness **across cases**. Reuse of the
  same retry key with a different logical command is a conflict.
- PostgresCaseTimelineService.apply() authorizes against the supplied trusted
  principal **before SQL or replay**, checks expiry against a trusted clock,
  obtains a PostgreSQL transaction advisory lock keyed by tenant/case,
  reads all relational history columns, rejects mismatched JSON and
  noncanonical types, verifies contiguous revisions, tenant/case/source/context,
  actor, time, idempotency, command, disposition and transition lineage,
  then calls existing #64 immutable kernel and appends one event. Corrupt
  history fails before case or audit writes. Identical replay does not
  re-append or re-audit.
- Redacted security audit is inserted on the **same PostgreSQL connection and
  transaction**, followed by exactly one commit. The independently committing
  PostgresSecurityAuditSink must not be used in this path. Database failure
  rolls back event and audit together; uniqueness violations are conflicts.
- Actual PostgreSQL 16 CI tests use isolated schemas with both migrations:
  six-stage journey, tenant/capability/revision failure, cross-case key
  conflict, exact retry, concurrent initial CAS, redacted audit contents,
  missing audit table, and injected audit failure with rollback and retry.
  Additional real-PG negatives mutate case JSON and metadata in synthetic
  administrator tests, remove a revision, and simulate a lost commit reply
  followed by exact and conflicting retries on a new connection.

## Mandatory remaining dependencies

1. This adapter receives a typed principal, tenant, case UUID, source and
   assignee lookup, and clock from its caller. A dataclass shape does **not**
   authenticate identity. Installed #42 ingress must verify credentials and
   revocation, and resolve event/case/assignee/tenant from server-owned records.
   Never accept these as authority from browser JSON.
2. Migration DDL creates objects only. A **synthetic real-PostgreSQL role test**
   provisions isolated non-superuser migrator, case writer, case reader,
   audit reader and outsider roles, then exercises allowed and forbidden
   operations and cross-installation denial. It does not provision Bank roles,
   row-level security across tenants in one schema, retention, attested
   tamper protection, backup/restore or operational performance. Case writers
   need SELECT for read/compare and INSERT for atomic append; they must not
   be described as INSERT-only. No protected case endpoint is exposed.
3. Independent QA/Security must examine connection pooling/transaction
   isolation, bank-provisioned SQL permissions, global idempotency under
   credential rotation, bank provenance, provider failure and negative attack
   paths. JSON-to-row checks detect local inconsistencies but **cannot**
   detect a privileged attacker coherently rewriting both JSON and columns,
   or prove independent bank event/audit provenance. A lost reply test
   simulates unknown acknowledgment *after* commit; it does not inject a real
   network partition at the COMMIT boundary.
   Real bank IdP, Kafka/DB failover, P95/P99 and case UAT remain untested.
4. #49 readiness remains a non-authoritative internal evaluator. Neither an
   analyst disposition nor this service authorizes payment enforcement,
   bank-executed HOLD/BLOCK, avoided loss or stage advancement. The persisted
   bank_execution field is database-constrained to unknown.

PO -> Security & Architecture -> Independent QA -> Unified Engineering Lead
must inspect the **exact changed head**. Do not merge this PR until exact-current-head and current-base CI and independent
reviews establish its limited gates; retargeting alone is not acceptance. No bank deployment or enforcement activation.
