# Issue #45 — analyst case transition kernel (internal only)

This bounded implementation follows the Product Owner handoff and Security & Architecture contract on [Issue #45](https://github.com/AyalewGM/Gasha-backend/issues/45#issuecomment-6547290823). It is a **side-effect-free transition oracle**, not a case API or bank case service. No schema, persistence, HTTP endpoint, broker, bank connection, audit wiring, outcome mutation, inline enforcement, or case-system integration is activated.

## Trusted scope and lifecycle

The installed protected #42 ingress must authenticate and supply an actual TrustedPrincipal and a **server-owned** EvaluationLookup that resolves a tenant-scoped immutable evaluation/event with source context. The VerifiedEvaluation record is just a typed lookup result, **not a proof of authentic provenance by itself**. A backend service must select the case UUID; never accept a browser-supplied case ID, tenant, source context, role, or assignee as authority. AuthorizedAssignee similarly requires an independently trusted, tenant-aware directory lookup before invocation.

This kernel extends the existing capability enum with case.read, case.create, case.triage, case.assign, case.disposition, case.correct, and case.feedback. Each transition uses a distinct capability, checked with the existing tenant/principal authorize. Read requires later implementation; it is not exposed here. Admin status does not imply analyst permission.

State sequence: create → triage → assign → dispose → [correct ...] → reconcile. Disposition is exactly fraud, legitimate, or unresolved. Corrections append a new event and retain original dispositions. Reason values are a finite enum, not free-form notes. Every transition is linked to the tenant, case UUID, immutable evaluation UUID/context hash, pseudonymous actor hash, trusted UTC timestamp, revision and previous revision, typed operation/reason, optional server-resolved assignee, and domain-separated idempotency and command references. Exact duplicate requests return the existing immutable event from trusted history. A conflicting payload/key, invalid prior state, stale revision, changed evaluation, unauthorized capability, wrong tenant, bad source, or regressing time fails closed.

**Bank execution remains unknown for every transition.** A fraud label, Gasha recommendation, or feedback reconciliation cannot assert a bank-executed block, stopped payment, settlement, prevented losses, policy update, or model change.

## Required integration before any case-route activation

1. Build real tenant-scoped evaluation and assignee lookup adapters, not from user-provided objects. Verify non-synthetic source lineage and server-owned case ID allocation.
2. Implement a durable case-history repository with conditional tenant/case/expected-revision append and globally persistent tenant/actor/idempotency-hash uniqueness. This pure function is **not** a concurrency, database, or global idempotency boundary. Never deserialize untrusted client history into the kernel.
3. Commit each transition and required redacted audit **atomically** in the same transaction, or use an independently reviewed transactional outbox. PR #63's opt-in PostgreSQL audit sink commits independently, so calling it before/after a case write is *not* atomicity. Define migrator/runtime/reader roles, bank-controlled ACLs, retention, migration, and unavailable-audit rollback.
4. Only then add protected API routes and independently execute installed tests for expired/revoked credentials, issuer/provider failures, tenant/role/proxy spoofing, foreign case/source/assignee access, audit failure, duplicate conflicts, stale and concurrent writes, denied mutation, and absence of bank-execution claims.
5. Implement reproducible alert backlog/age/turnaround/unresolved metrics with explicit denominators, approved Bank case-system adapter or minimal view, and outcome feedback reconciliation. #49 evidence verification/approval remains a separate authority plane.

The new synthetic tests cover a six-step case journey, correction immutability, per-operation capability denial, tenant/source mismatch, lookup outage, duplicate and stale revision handling, invalid transitions, malformed commands, and clock regression. They **do not** test PostgreSQL, a running protected API, CBE acceptance, installed proxy, concurrency, or bank execution. Exact-head CI and independent review remain required.
