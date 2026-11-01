# Issue #44 — inert match-only risk-list reference

**Status:** Synthetic-only, non-authoritative. Product Owner and Security & Architecture required removal of global BLOCK > WATCH > ALLOW precedence. The kernel now returns **all active matches**, not a winning kind, payment action or readiness verdict.

## Match table and reason provenance

| Active list classes | Returned matches | Authority |
|---|---|---|
| None | Empty tuple and RISK_LIST_NO_MATCH | Never permission to pay |
| Allow | All matching ALLOW entries, per-entry RISK_LIST_ALLOW_MATCH | Never an allow override |
| Watch | All matching WATCH entries, per-entry RISK_LIST_WATCH_MATCH | Not an action |
| Block | All matching BLOCK entries, per-entry RISK_LIST_BLOCK_MATCH | Never an executed HOLD/BLOCK |
| Any pair or all three | Complete, UUID-ordered match set, each with entry ID, kind and reason | **No** winning class or precedence |

The `policy_version` field remains a scope *label*, not the definition or authority of a conflict policy. Future integration must bind Bank-approved, immutable policy content/digest to its version and select it server-side for the authorized tenant, installation and event time. No browser/request/worker assertion grants policy selection.

## Time, scope and replay contract

- UTC-normalized validity uses inclusive start, exclusive end, and inclusive revocation. Revocation before effective start is invalid even across DST fall-back folds; revocation exactly at start makes an entry never active.
- Repeated entry IDs **and** duplicate logical (subject kind, token, list kind) entries with different IDs are rejected. Distinct subjects and distinct list classes remain separate matches.
- Pinned tenant, list version, policy label, publication and every entry are bound to an order-independent snapshot digest. A content digest is **not** trusted source provenance. Future-published snapshots are rejected for historical events. Repeat synthetic replay yields identical complete provenance.
- Typed BANK/CUSTOMER/ACCOUNT/BENEFICIARY identifiers use 64 lowercase hex placeholder tokens. Shape validation does **not** prove Bank-keyed pseudonymization; real installations must attest the token namespace/key version, avoiding raw or merely unsalted-hashed PII. Outputs omit tokens and transaction IDs.

## Excluded scope

No Bank-authenticated snapshot reader, privileged admin/RBAC, durable versioned list registry, append-only mutation/audit, idempotency, version-bound policy resolver, historical replay adapter, production decision/worker integration, or #49 readiness authority is implemented. The reference must not be imported into protected routes, scoring, worker or readiness evaluator. Independent Product Owner, Security & Architecture and QA exact-head reviews plus Unified Lead approval are required before even inactive internal integration. No bank deployment or payment enforcement.
