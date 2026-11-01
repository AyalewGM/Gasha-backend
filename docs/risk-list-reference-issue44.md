# Issue #44 — provisional, non-authoritative versioned risk-list match semantics

**Status:** Synthetic-only bounded reference, not an integrated risk-list system. Subject to Product Owner and Security/Architecture approval before reuse. Does **not** change bank decision scoring, execute BLOCK/HOLD, establish trusted list provenance, or activate stage gates. Existing #42 authenticated authorization and #49 trusted approval contracts remain required.

## Explicit proposed precedence and explainability

When multiple *currently effective* list entries match any supplied bank-tokenized subject of the exact kind, the reference match kind is the strongest matching class by the **provisional ranking BLOCK > WATCH > ALLOW**. The returned *list-match class*, not a transaction action, has precisely one explanatory code:

| Matching classes present | Reference result | Reason code |
|---|---|---|
| none | no match | RISK_LIST_NO_MATCH |
| allow only | allow match | RISK_LIST_ALLOW_MATCH |
| watch only | watch match | RISK_LIST_WATCH_MATCH |
| block only | block match | RISK_LIST_BLOCK_MATCH |
| allow + watch | watch match | RISK_LIST_WATCH_MATCH |
| allow + block | block match | RISK_LIST_BLOCK_MATCH |
| watch + block | block match | RISK_LIST_BLOCK_MATCH |
| allow + watch + block | block match | RISK_LIST_BLOCK_MATCH |

No match is **not** permission to allow a transaction. An allow match is **not** a risk override. Proposed precedence is not bank policy; the Product Owner/Bank must explicitly approve or replace it before integration. There is no caller-controlled runtime precedence override.

## Temporal and scope invariants

- A match requires a caller-provided snapshot pinned to the exact tenant, list version and policy version. The matcher rejects different versions/tenants and snapshots with published_at later than the original event time.
- Each entry's active interval is inclusive start/exclusive end; a revocation is effective at revoked_at inclusively. All times are UTC-normalized to handle repeated DST hours correctly.
- Snapshot content fingerprints are canonical and order-insensitive, bound to tenant/version/policy/publication time and every entry's ID, kind, subject-token, effective bounds and revocation. Hashes attest **byte identity only**, not authority/source. Immutable older snapshots can reproduce synthetic historical matches without retroactive changes from later snapshots.
- Subjects are typed BANK/CUSTOMER/ACCOUNT/BENEFICIARY references with 64 lowercase hex characters, **not** raw IDs. Real installations must create these using Bank-controlled keyed tokenization; an unsalted SHA-256 of PII is not sufficient privacy protection.
- Output contains only matched entry UUIDs, a reference reason code, pinned list/policy versions and content digest. There are no transaction identifiers, raw subject tokens, or bank-data values in output.

## Missing acceptance criteria and rollout prohibition

This module **does not implement** authorized administration, append-only mutation/audit, idempotent mutation IDs, PostgreSQL persistence, certificate/identity-backed list artifact validation, trusted snapshot selection, policy-approved conflict behavior, cross-tenant read/write enforcement, outcome/decision wiring, bank replay, or rollback/migration. A caller can construct an arbitrary snapshot: it is never authoritative. Do not import this module from protected routes, decision service, worker or readiness evaluator. Separate Product Owner → Security & Architecture → Independent QA exact-SHA review is required before even inactive internal integration.
