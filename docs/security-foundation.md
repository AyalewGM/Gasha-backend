# Issue #42 — protected API foundation (bounded)

This branch introduces a **fail-closed default bank-facing ASGI app** at
`gasha.api.main:app`. Untrusted client policy, risk scores, mode, role and
tenant headers are not accepted as decision authority. The request's tenant
identifier must match the verifier's trusted tenant scope. Evaluation mode is
always **SHADOW** and carries no bank intervention execution.

The old caller-asserted policy/risk interface is retained in the *source tree*
as `gasha.api.synthetic:app` for deterministic tests and loopback-only
synthetic development. The default bank-targeted `Dockerfile` **deletes that
module before installing the package**, so even an overridden container
entrypoint cannot import the synthetic ASGI application. CI builds the actual
image and asserts that the synthetic module is unimportable while the
protected `gasha.api.main:app` remains importable and unwired by default.
Do not build a bank deployment from a different Dockerfile or the source
checkout.
The protected application authenticates `/v1/` requests in ingress middleware
before FastAPI parses any JSON. Protection is classified from the effective
Starlette ASGI route path (server-controlled `scope["path"]` and `scope["root_path"]`),
not `request.url.path` or any caller-supplied `X-Forwarded-Prefix` header.
Deployment ingress must configure and record the trusted ASGI `root_path` or
mount prefix at the server/proxy boundary; unsupported external prefix mappings
are not treated as authorization grants. Synthetic HTTP regression tests cover
direct paths, `/bank`, nested `/gateway/bank`, prefixed/unprefixed ASGI paths,
spoofed forwarded headers, auth/audit outages, and shadow-only operation. An invalid JSON body with no/invalid credential
returns a redacted audited 401 (or 503 on identity/audit outage), not an
unauthenticated 422 exposing validation details. Endpoint dependencies reuse
the exact ingress principal; a dependency override cannot escalate it.
The protected application disables FastAPI's otherwise public `/docs`,
`/redoc`, `/openapi.json` and Swagger OAuth redirect routes. Only the narrowly
scoped health routes intentionally remain unauthenticated; protected API
metadata must not be exposed through the bank application. Bank image signing, registry provenance and deployment approval
remain separately gated under #46/#49. A developer choosing the synthetic
app explicitly is not an identity or authorization mechanism.

## Trusted deployment dependencies

The protected decision routes require three trusted dependencies, all absent
by default. Protected outcome mutation is disabled unconditionally until an
atomic outcome-and-terminal-audit persistence adapter is independently accepted:

- `identity_verifier`: provider-neutral `CredentialVerifier` validates
  credential signature/issuer/audience, expiry, rotation and revocation;
  there is deliberately **no** built-in bank token issuer or self-verification.
- `security_audit`: append-only durable `SecurityAuditSink`; failure to
  append authentication/authorization evidence rejects the request.
- `decision_context_provider`: server-selected tenant-bound
  `TrustedDecisionContextProvider` supplying versioned policy and authoritative
  intelligence signals, not caller-selected thresholds. Contexts are tied to
  the exact tenant/event, carry signal source and signal version, an immutable
  serialized policy/signal snapshot and SHA-256 context reference, plus a
  provider-declared collection/expiry window checked against service time.
  The reference now binds both timestamps as canonical UTC instants: a
  collection/expiry claim change produces a different reference even if the
  event, policy and signals are identical. This closes an internal lineage
  ambiguity but **does not** authenticate or attest the provider's timestamps,
  satisfy historical point-in-time feature validation, or authorize bank evidence.
  Provider trust/attestation and actual bank signal ingestion remain separate
  integration controls.
- The legacy `outcome_ingestion` field is deliberately ignored by protected
  outcome routes. A mutable/in-memory `OutcomeIngestionService` cannot prove
  that the outcome and correlated terminal audit commit atomically, and no
  temporary injected service can enable bank writes. `/health/ready` reports
  `outcome_atomic_commit=false` and HTTP 503 until an independently verified
  durable transactional port and tenant-scoped idempotent retry contract exist.

The provider controls are typed *interfaces*, not an actual Bank-approved
identity service or provisioning record. The Bank must select identity,
certificate and key-rotation mechanisms, DB/broker ACLs, transport security,
retention, monitoring, incident procedures and deployment approval.

## Endpoint authorization matrix

| Path | Capability | Tenant source |
| --- | --- | --- |
| POST /v1/decisions | decision.submit | trusted principal + canonical transaction |
| POST /v1/evaluations | decision.submit | trusted principal + canonical transaction |
| POST /v1/outcomes | outcome.submit (writes disabled; HTTP 503) | trusted principal + outcome record |
| POST /v1/incumbent-outcomes | incumbent_outcome.submit (writes disabled; HTTP 503) | trusted principal + incumbent record |
| GET /health/live | none | no sensitive response |
| GET /health/ready | none | wiring presence only, not deep dependency verification |

Other capabilities are reserved for separately reviewed read, analyst,
evidence verification/revocation and privileged administration endpoints.
Their mere presence in an enum creates **no** accessible admin operation.
All missing or invalid credentials, mismatched tenants, insufficient
capabilities, identity-provider outages, missing context and audit
write failures are denied. Audit actor and tenant references are hashed;
tokens, request bodies, raw PII and secrets are never included in audit events.
Each protected request receives a server-generated attempt reference; action
authorization and terminal outcome use distinct result labels and share a
hashed tenant/event reference. Successful evaluations include a server-chosen
policy/signal context digest. Provider errors append a redacted terminal failure event before HTTP 503.
For both protected outcome routes, valid principal+tenant+capability still
returns 503 with a redacted `transactional_outcome_unavailable` failure event
and **no outcome state change**. Missing/broken audit blocks these attempts;
legacy store injection cannot bypass the fail-closed route. Synthetic-only
in-memory outcomes continue in the separately isolated dev application.
Successful protected idempotent replay and transactional audit/outcome
persistence are **not yet implemented**: they need a tenant-scoped durable
adapter with atomic commit, concurrency/idempotency tests and independent
Security/QA acceptance. A 503 is never represented as an accepted outcome.

## Remaining acceptance gates

This bounded change is **not completion of #42**. Independent Security and
QA must verify exact-head HTTP negative tests, privileged operations, audit
durability, credential rotation/revocation, concurrency and tenant scopes.
#46 still requires real readiness probes and bank-controlled deployment.
#49's trusted evidence/approval registry and all CBE readiness gates are
separate. No bank activation, inline enforcement, or production approval.
