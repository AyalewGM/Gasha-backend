# Issue #147 — tenant configuration repository contract

**Status:** Design contract, internal only. Nothing in this document authorizes a bank deployment, enforcement, or activation of any route, worker or provider. Implementation requires independent Product Owner, Security & Architecture and QA review, consistent with existing #42/#45 gated-boundary practice.

## Purpose and boundary

The protected decision path must select tenant policy **server-side from durable storage**, never from a request seam. The architecture document already marks the caller-supplied `DecisionPolicy` as a temporary contract seam; `tenant_scope.require_tenant` is a 7-line allowlist, not a configuration authority.

This contract defines a **durable, versioned, tenant-scoped configuration repository**:

- Immutable content rows with an explicit lifecycle (`DRAFT → ACTIVE → RETIRED`).
- Exactly one `ACTIVE` version per `(tenant_id, config_kind)`; activation atomically retires the predecessor.
- Content digests bind each version to its payload so a recorded `policy_version` is a verifiable reference, not a label.
- Trusted server-side readers resolve the `ACTIVE` version at decision time; a missing, inactive or inconsistent configuration **fails closed** — no silent default policy in the protected path.

This document is a boundary contract, not a bank configuration authority, secrets store, RBAC system or tenant self-service portal.

## Configuration kinds (v1)

| Kind | Content | Consumer |
|---|---|---|
| `DECISION_POLICY` | `configuration_version`, `policy_version`, `rule_version`, `model_version`, ordered decision thresholds (`DecisionPolicy` fields) | `TrustedDecisionContextProvider` for `/v1/decisions` and `/v1/evaluations` |
| `DETECTOR_POLICY_BUNDLE` | Versioned per-detector policy payloads (social engineering, behavioral session, internal graph, journey risk policies) | Server-side intelligence assembly only |

Deferred, explicitly out of v1 scope: capability/role grants, scenario enablement vocabulary, data-retention settings, risk-list content (#44 owns its own store and precedence contract), model artifacts, and notification/channel settings.

## Data model

Proposed durable shape (migration numbering follows `db/migrations`):

- `tenant_configurations(tenant_id, config_kind, version, lifecycle, content_json, content_digest, created_at, created_by_ref, activated_at, retired_at, supersedes_version)`
- Primary key `(tenant_id, config_kind, version)`; a partial unique index enforces one `ACTIVE` row per `(tenant_id, config_kind)`.
- Lifecycle transitions are the only permitted mutation. `content_json` is write-once.

## Invariants

- `version` is strictly increasing per `(tenant_id, config_kind)` and is never reused, including after retirement.
- `DRAFT → ACTIVE → RETIRED` only. No `RETIRED` resurrection, no `ACTIVE` edit, no `DRAFT` skip-level activation into the past.
- Activation is **atomic**: retiring the incumbent and activating the candidate commit in one transaction (or a reviewed outbox). A crashed activation must never leave zero or two `ACTIVE` rows.
- `content_digest` is SHA-256 over canonical JSON with a domain/schema tag (same discipline as `TrustedDecisionContext.context_ref` — NUL/hostile-delimiter and type-ambiguous preimages are rejected).
- Trusted UTC clocks only, consistent with the #42/#45/#48/#49 clock-hardening line: `activated_at >= created_at`, no future activation, and callback-capable or forged clock objects are rejected before any lookup or persistence hook runs.
- Tenant identifiers are opaque references; the store records no raw PII or bank key material.

## Trust boundary

- **Writers:** a dedicated provisioning/migrator identity. Runtime API principals, request payloads and workers **must not** write configuration. Schema migration runs under the migrator role with separately provisioned runtime privileges, matching the audit-sink precedent (migration `010`).
- **Readers:** server-side trusted providers only — `TrustedDecisionContextProvider` and detector signal assembly. Every issued decision context records `(tenant_id, config_kind, version, content_digest)` so `context_ref` provenance binds the resolved configuration, not merely its version label.
- **Fail closed:** unavailable repository, no `ACTIVE` row, digest mismatch or lifecycle inconsistency denies the decision context. The protected app must not fall back to a packaged or caller-selected default.

## Request-seam removal

- `gasha.api.main:app` already rejects caller-asserted policy; this store becomes the only source its provider may resolve.
- `gasha.api.synthetic:app` retains caller-selected values **by design** for loopback deterministic tests and must remain unimportable in bank images (existing Dockerfile deletion stays unchanged).
- Worker paths resolve configuration through the same trusted readers under `require_tenant` worker scope — never through a second, weaker lookup.

## Audit

Every lifecycle event (draft create, activate, retire) emits a redacted `security_audit_events` row bound to the acting provisioning principal, tenant reference, and content digest. The audit row commits **atomically** with the lifecycle transition or via a reviewed transactional outbox — the same atomicity requirement as the #45 case writer; an audit outage fails the transition.

## Excluded scope

No protected management/admin routes, no UI, no tenant self-service or provisioning API, no capability or role grants, no scenario vocabulary changes, no risk-list registry, no secrets or key material storage, no payment enforcement, no bank execution claims, no changes to decision semantics (thresholds still mean exactly what `DecisionService` defines). This store selects configuration; it does not create new authority.

## Required integration before any activation

1. Provisioned migrator, runtime-reader and provisioning-writer roles with bank-controlled ACLs, separate from existing service identities.
2. `TrustedDecisionContextProvider` wired to the repository and verified to deny on store outage — dependency overrides must not escalate or substitute configuration (the existing ingress-principal boundary applies unchanged).
3. Tests covering: cross-tenant resolution denial, atomic activation under concurrency, stale/forged clocks, digest tampering, version reuse, incomplete lifecycle transitions, audit-outage failure, and replay determinism (identical resolved config for a pinned historical instant).
4. Independent Product Owner, Security & Architecture and QA exact-head reviews before merge; separate Unified Lead authorization before any protected-route dependency is switched to this repository.

## Implementation sequence (proposed bounded slices)

1. Migration + inert repository reader/writer kernel (no protected wiring).
2. Provider adapter resolving `DECISION_POLICY` from the store with fail-closed tests, still uninstalled.
3. Detector-bundle resolution for `DETECTOR_POLICY_BUNDLE`.
4. Only after the above and independent acceptance: install behind the protected provider, keeping synthetic-app seams untouched.
