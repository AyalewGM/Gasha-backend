# Issue #45 — Protected ranked analyst queue read seam (bounded)

**Engineering-only contract, default disabled.** This is a read-only entry point
for the PO-prioritized authenticated ranked multi-scenario analyst workspace,
not a Bank-approved prioritization engine, scenario detection, live alert feed,
trusted source adapter, operational case-management installation, stage grant or
payment action.

## Endpoint

`GET /v1/tenants/{tenant_id}/cases/queue?limit=25`

The existing protected API requires a server-verified bearer principal with
`case.read` for the path tenant. A wrong tenant returns 404, insufficient
capability 403, invalid/expired credential 401, unavailable IdP/audit/reader
503, and malformed `limit` (must be 1–100) 422. Authentication happens at
ingress before route/query parsing; spoofed tenant, role and proxy headers
cannot grant access. The route audits redacted authorization and read
success/failure, and does not issue case transitions or change fraud scores.

The read port `TrustedCaseQueueReader.read(principal, tenant_id, limit, at)`
is **not installed** in `gasha.api.main:app`. Merely setting its attribute
from a test or composition is not a Bank approval. The externally installed
reader must reverify identity/expiry, use least-privilege tenant-scoped durable
case and evaluation stores, enforce authorized source/assignee access, bind
scenario membership to immutable evidence and use a versioned, Bank-approved
ranking policy. This PR does not implement those authorities, scoring,
reviewer sign-off, freshness SLAs or pagination.

## Response / fail-closed invariants

The reader returns an immutable `CaseQueueSnapshot` whose full contents
are checked before *any* items are serialized:

- Snapshot tenant matches authorized path tenant; policy version is canonical;
  snapshot time is aware and not in the future.
- The item tuple is bounded by limit; rankings are contiguous from 1.
  **Ranking is supplied by the trusted reader**, not calculated here or
  accepted from browser query/body. No implicit numeric risk weight is used.
- Each item is uniquely identified by case UUID and source-event UUID. This
  provides a conservative one-source/one-case reference and prevents repeated
  queue entries; it does not consolidate multiple *different* event IDs.
- Each nonempty scenario-id tuple contains only the eight PO-selected
  synthetic scenario IDs in canonical unique order; all mutable/wrong-type
  projections fail closed.
- Complete case history is verified with the shared #45 lifecycle validator.
  Only currently open CREATE/TRIAGE/ASSIGN cases appear. Disposed, corrected,
  reconciled, future, wrong-tenant, duplicate or inconsistent histories fail
  the entire read rather than partially returning untrusted items.
- Response contains rank, UUID references, digest-only source context,
  scenario IDs, lifecycle operation/revision and UTC timestamps. It omits
  credentials, free-text customer information, risk payloads and internal
  idempotency/command hashes. It always says
  `bank_ranking_approved=false`, `bank_execution=unknown` and
  `enforcement_activated=false`.

The reader's policy version and hash references are **labels, not provenance
attestation**; no verified customer dataset, Bank-confirmed ranking,
multi-event case consolidation, executed HOLD/BLOCK, prevented loss, UC-04/05
performance, or authoritative PR #54/Issue #49 evidence can be inferred.
Frontend integration must not use synthetic data as a Bank queue or treat
`case.read` as authority to perform case mutations. #45's existing
append-only PostgreSQL writer, case history endpoint and per-operation
capabilities remain unchanged.

## Validation and handoff

`pytest -q tests/test_api_case_queue.py` exercises authenticated success,
multi-scenario ordering, credential and tenant/role/proxy denial, missing
reader and audit failures, malformed scope/clock/identities, duplicates,
closed cases, future/cross-tenant history and limit validation. CI must pass
Ruff, strict mypy, the repository pytest suite, protected API negatives,
PostgreSQL integration and Docker isolation at the **exact PR head**.

Product Owner should confirm read-only semantics and that Bank ranking
policy is still external; Security/Architecture must assess tenant/rank/source
trust and audit; Independent QA should reproduce default-disabled and
cross-tenant/partial-result denials. Separate Unified Engineering Lead
decides internal integration only. Issue #45 and #49 Bank-facing acceptance
remain open. No merge, self-approval, deployment or enforcement is authorized.
