# Issue #45 — stacked durable case/audit transaction candidate

This is a **draft internal integration slice** stacked on independently reviewed
PR #64 (https://github.com/AyalewGM/Gasha-backend/pull/64).
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
  rehydrates stored history, calls existing #64 immutable kernel and appends
  one event. Identical replay does not re-append or re-audit.
- Redacted security audit is inserted on the **same PostgreSQL connection and
  transaction**, followed by exactly one commit. The independently committing
  PostgresSecurityAuditSink must not be used in this path. Database failure
  rolls back event and audit together; uniqueness violations are conflicts.
- Actual PostgreSQL 16 CI tests use isolated schemas with both migrations:
  six-stage journey, tenant/capability/revision failure, cross-case key
  conflict, exact retry, concurrent initial CAS, redacted audit contents,
  missing audit table, and injected audit failure with rollback and retry.

## Mandatory remaining dependencies

1. This adapter receives a typed principal, tenant, case UUID, source and
   assignee lookup, and clock from its caller. A dataclass shape does **not**
   authenticate identity. Installed #42 ingress must verify credentials and
   revocation, and resolve event/case/assignee/tenant from server-owned records.
   Never accept these as authority from browser JSON.
2. Migration DDL creates objects only. Distinct migrator, append-only runtime,
   case-history reader and security-audit roles, per-environment schemas,
   retention, tamper controls, backup/restore and operational performance
   are not configured or attested. No protected case endpoint is exposed.
3. Independent QA/Security must examine connection pooling/transaction
   isolation, installed SQL permissions, global idempotency under credential
   rotation, bank provenance, provider failure and negative attack paths.
   Real bank IdP, Kafka/DB failover, P95/P99 and case UAT remain untested.
4. #49 readiness remains a non-authoritative internal evaluator. Neither an
   analyst disposition nor this service authorizes payment enforcement,
   bank-executed HOLD/BLOCK, avoided loss or stage advancement. The persisted
   bank_execution field is database-constrained to unknown.

PO -> Security & Architecture -> Independent QA -> Unified Engineering Lead
must inspect the **exact changed head**. Do not merge this stacked PR until
its parent has a separate integration decision and this slice independently
passes its gates. No bank deployment or enforcement activation.
