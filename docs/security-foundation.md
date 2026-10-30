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
checkout. Bank image signing, registry provenance and deployment approval
remain separately gated under #46/#49. A developer choosing the synthetic
app explicitly is not an identity or authorization mechanism.

## Trusted deployment dependencies

All four dependencies are absent by default, so the protected app cannot
serve decision or outcome mutations without deliberate wiring:

- `identity_verifier`: provider-neutral `CredentialVerifier` validates
  credential signature/issuer/audience, expiry, rotation and revocation;
  there is deliberately **no** built-in bank token issuer or self-verification.
- `security_audit`: append-only durable `SecurityAuditSink`; failure to
  append authentication/authorization evidence rejects the request.
- `decision_context_provider`: server-selected tenant-bound
  `TrustedDecisionContextProvider` supplying versioned policy and authoritative
  intelligence signals, not caller-selected thresholds.
- `outcome_ingestion`: explicitly provisioned `OutcomeIngestionService`
  with a bank-approved durable and tenant-scoped store. The old in-memory
  default is not silently mounted in the protected app.

The provider controls are typed *interfaces*, not an actual Bank-approved
identity service or provisioning record. The Bank must select identity,
certificate and key-rotation mechanisms, DB/broker ACLs, transport security,
retention, monitoring, incident procedures and deployment approval.

## Endpoint authorization matrix

| Path | Capability | Tenant source |
| --- | --- | --- |
| POST /v1/decisions | decision.submit | trusted principal + canonical transaction |
| POST /v1/evaluations | decision.submit | trusted principal + canonical transaction |
| POST /v1/outcomes | outcome.submit | trusted principal + outcome record |
| POST /v1/incumbent-outcomes | incumbent_outcome.submit | trusted principal + incumbent record |
| GET /health/live | none | no sensitive response |
| GET /health/ready | none | wiring presence only, not deep dependency verification |

Other capabilities are reserved for separately reviewed read, analyst,
evidence verification/revocation and privileged administration endpoints.
Their mere presence in an enum creates **no** accessible admin operation.
All missing or invalid credentials, mismatched tenants, insufficient
capabilities, identity-provider outages, missing context and audit
write failures are denied. Audit actor and tenant references are hashed;
tokens, request bodies, raw PII and secrets are never included in audit events.

## Remaining acceptance gates

This bounded change is **not completion of #42**. Independent Security and
QA must verify exact-head HTTP negative tests, privileged operations, audit
durability, credential rotation/revocation, concurrency and tenant scopes.
#46 still requires real readiness probes and bank-controlled deployment.
#49's trusted evidence/approval registry and all CBE readiness gates are
separate. No bank activation, inline enforcement, or production approval.
