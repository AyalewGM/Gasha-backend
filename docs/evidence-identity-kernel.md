# Issue #49 — immutable evidence identity kernel (internal candidate)

This document describes the **non-authoritative** two-file code/test foundation
introduced on the draft evidence-identity PR. The implementation follows the
[Product Owner #49 contract](https://github.com/AyalewGM/Gasha-backend/issues/49)
and [Security/Architecture contract comment 6546537956](https://github.com/AyalewGM/Gasha-backend/issues/49#issuecomment-6546537956).
It is **not** a trusted registry, a signed evidence service, a second readiness
evaluator, a verified Bank packet or an enforcement authorization.

## Implemented identity semantics

- `EvidenceBinding` fixes tenant, Bank installation/environment, historical /
  shadow / inline-preparation stage, UC-01/02/03, source commit, installed image
  digest, dataset fingerprint, config/policy/rule/signal/adapter versions and
  observation window. No arbitrary caller-controlled stage promotion occurs.
- `EvidenceRecord` fixes UUID, evidence area, bounded opaque artifact reference
  and SHA-256 digest, pseudonymous collector reference, source, collection time
  and expiry. Every timezone-aware timestamp is normalized to a stored UTC
  instant during frozen construction, before dataclass scope comparisons and
  hashing; the two repeated New York fall-back 01:30 times remain distinct.
- `EvidencePacket` is a frozen, immutable collection; it rejects duplicate IDs,
  mixed scopes and mutable input collections. Its deterministic, domain-tagged
  content digest includes the policy evaluator version and every record identity.
  Reordering records is harmless; changing a single bound field changes the digest.
- `assert_packet_current(..., expected=..., now=...)` rejects scope/version
  substitutions, future-collected or expired evidence. The clock is injected; at
  exactly the expiry instant the record is expired. Collection must occur no earlier
  than the bound observation window end. DST-fold wrong-expected and mixed-record
  windows are rejected; equivalent UTC instants in other zones retain one identity.

These are **local structural/freshness checks**, not evidence verification.
Any untrusted caller can construct the same well-shaped data and compute a hash.
Neither a complete packet nor a matching digest proves the referenced artifact
exists, is authentic, has passed a security test or was independently reviewed.

## Not provided / required before any authority

The Bank-controlled, tenant/environment-scoped append-only PostgreSQL registry,
write-once evidence events, actual artifact reading and provenance verification,
independently authorized collector/verifier/approver/revoker, approval-to-packet
binding, expiry/revocation transactions, audit/record atomicity, lease/concurrent
revoke versus evaluate, identity-provider integration, least-privilege database
roles, and immutable signed release provenance are **not implemented** here.

The approved next integration must use existing `TrustedPrincipal` / capability
checks from #42, the durable audit boundary from #63 and the exact #49
Security/Architecture contract. Only a trusted server-side registry may supply
verified evidence and distinct approval decisions to the already-merged
`readiness.py` pure evaluator. Do **not** accept user-submitted packets, booleans,
digests or this module's freshness results as proof of authority.

The merged PR #54 remains caller-asserted and non-authoritative;
`enforcement_activated` stays false. There is no endpoint, worker hook, Bank
connection, database migration, case API, deployment or payment intervention in
this candidate. Bank identity, provenance, mandatory security/privacy/compliance
vetoes, Bank KPI approval, independent validation and CBE acceptance remain open.

## Validation and bounded review

Run:

```sh
python -m pytest -q tests/test_poc_evidence_identity.py
ruff check src/gasha/poc/evidence_identity.py tests/test_poc_evidence_identity.py
mypy --strict src/gasha
python -m pytest -q
```

Use current exact-head CI (including installed protected API, PostgreSQL and
Docker) to assess compatibility, then request **Product Owner → independent
Security/Architecture → independent QA → Unified Engineering Lead**.
A passing test suite does not establish Bank installation, artifact authenticity,
approval authority, audit persistence, CBE readiness or live authorization.
No independent implementation author should self-approve or merge this draft.
