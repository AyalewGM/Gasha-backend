# Issue #45 — opt-in protected analyst case writer bridge

This bounded addition connects the existing protected FastAPI `TrustedCaseTransitionWriter` protocol to the already-accepted **opt-in** `PostgresCaseTimelineService` append-only case and terminal-audit transaction. It follows the Product Owner case workflow and the [Security/Architecture case-operations contract](https://github.com/AyalewGM/Gasha-backend/issues/45#issuecomment-6547290823). It reuses the existing #42 authentication and #45 case kernel, migration 011, and transactional audit. It does not replace or redo merged #52/#53/#54.

## What the bridge proves (synthetic test scope only)

- An explicitly supplied `ExplicitPostgresCaseTransitionWriter` maps a protected request proposal to the canonical `CaseCommand` and `PostgresCaseTimelineService.apply`, and holds an isolated accepted identity through the transaction. Evaluation and assignee callbacks receive separate detached principals; callback mutation of subject/issuer is rejected before event and terminal-audit commit.
- Each write requests a separate PostgreSQL connection/context; no shared mutable connection or non-atomic terminal HTTP success audit is added.
- A server-owned evaluation-directory interface supplies the immutable tenant/event/context reference during the transaction. A separately resolved assignment directory supplies a tenant-authorized pseudonymous assignee only on ASSIGN. Foreign-tenant references fail closed.
- Existing PostgreSQL transaction semantics serialize revisions, preserve exact idempotent replay, reject conflicting keys and co-commit the case event and redacted audit. The request never selects the database, policy, role or enforcement action.
- `tests/test_postgres_case_writer_bridge.py` executes the real PostgreSQL 16 migrations and the actual protected FastAPI HTTP route with synthetic test credentials/registries. It covers the six-stage case lifecycle, idempotency/stale revision, forbidden tenant and capability, rejected directory results and audit failure rollback.

## Required before ANY Bank installation

This is **not** a trusted evaluation registry, attested Bank source, IdP, assignee authority, or deployed case-system integration. The directory protocols do not prove their implementations are trustworthy; only independently reviewed, Bank-authorized, server-side adapters may supply them. The connection factory must be a restricted tenant-scoped pool/role with verified migrator grants, audit integrity, retention and safe lifecycle under failures. The protected app deliberately defaults to `case_transition_writer=None` and never enables this module automatically. Review credential expiry/revocation, proxy path, connection exhaustion, concurrent retries, uncertain COMMIT outcome, real Bank provider/tenant boundaries, and tested role/RLS restrictions before installing a writer.

The HTTP output `bank_execution=unknown` and `enforcement_activated=false` do not establish Bank intervention, payment prevention or avoided loss. The #49 readiness evaluator remains advisory/caller-asserted. Separate Product Owner → Security/Architecture → Independent QA exact-head verdicts and a Unified Engineering Lead integration decision are required; bank deployment, real-time action and CBE acceptance remain prohibited without explicit approval.


## Callback principal integrity correction (2026-11-04)

The writer snapshots the accepted typed principal before invoking directories and never shares the case-kernel principal with directory callbacks. Both resolver paths compare their detached arguments to the accepted copy immediately after return; mutations reject within the PostgreSQL transaction, before append or COMMIT. The writer rechecks tenant, capability and UTC expiry before entering the case kernel. Real PostgreSQL plus protected HTTP tests deliberately use `object.__setattr__` to mutate callback subject or issuer and assert no new durable case/terminal-success audit entries, with unchanged actor attribution. These synthetic tests are not independent Bank IdP, audit durability or deployed-integration acceptance.
