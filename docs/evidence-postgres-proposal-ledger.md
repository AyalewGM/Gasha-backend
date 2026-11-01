# Issue #49 — opt-in PostgreSQL evidence proposal ledger (not Bank authority)

This bounded engineering adapter builds on merged immutable evidence identity and
proposal lifecycle kernels (#67/#68). It does **not** change the side-effect-free,
caller-asserted, **non-authoritative** readiness evaluator from merged PR #54.
Previously merged #52/#53 are unchanged. Nothing here is wired into the protected
HTTP API, worker, frontend, readiness evaluator, bank adapter, or payment path.

## Implemented (synthetic / installation candidate only)

- Migration `012_poc_evidence_proposal_ledger.sql` creates tenant- and installation-
  scoped immutable packet snapshots and append-only proposal transitions. SQL
  UPDATE/DELETE triggers prevent accidental mutation; a privileged DBA could
  disable them, so they do not establish independently attested provenance.
- `PostgresEvidenceProposalLedger.apply()` authorizes a caller-supplied
  **already-verified** `TrustedPrincipal` against tenant and action **before**
  DB access; it is not itself an IdP. A deliberately injected artifact reader
  is required to propose verification. The reader is not bank-approved here.
- A parent packet unique key resolves competing first writers. Later writers
  use **optimistic unique-index compare-and-swap** on the immutable event key
  `(tenant_id, installation_id, packet_digest, revision)`. A competing insert
  that loses SQLSTATE 23505 becomes a stale-revision rejection and rolls back
  its entire transaction. This needs SELECT/INSERT, **not UPDATE or SELECT
  FOR UPDATE** on immutable tables; no advisory locks can be commandeered
  across installation schemas. All readers replay exact contiguous SQL/JSON
  history and enforce current `expected_revision`, immutable packet/version
  binding and separation of duties. Changed packets have independent history.
- Successful transitions append a redacted security audit record (actor/tenant/
  packet/attempt digest refs only) **in the same transaction**. Audit failure
  rolls back both proposal event and initial packet. No standalone audit-sink
  commit is called within that transaction.
- Real PostgreSQL tests cover lifecycle, scope/capability denials, stale
  revisions, corrupt packet history, independent race winners, and atomic
  audit rollback. Additional tests authenticate via dedicated **non-superuser
  writer and reader credentials** rather than running as the schema migrator:
  INSERT/SELECT-only evidence writer, audit INSERT-only, reader SELECT-only,
  blocked UPDATE/DELETE/TRUNCATE/ALTER/CREATE/trigger and function ownership,
  cross-installation schema access and lock denial, and malicious search_path
  and temporary-table shadowing. Fixtures remain synthetic; this is not CBE.

## Scope and limitations

This is **not** a trusted registry and grants **no readiness or Bank approval**.
A caller able to construct a packet or a `TrustedPrincipal` in Python can still
submit fabricated origin claims unless a future Bank-installed trust boundary
binds them to credentials, authorized source records and verified immutable
artifacts. A matching digest does not authenticate the referenced source.
Readiness must never consume this ledger until independently accepted Bank
identity, artifact access, policy/packet issuance, stage approval and evaluation
bindings exist. A successful transaction creates proposal history only.

## Installation, transactional SQL and least-privilege contract

The adapter **requires** `installation_schema`, `tenant_id` and
`installation_id` from trusted deployment composition. It rejects packets
outside the configured scope *before SQL/artifact access*. It validates the
schema as a short ASCII SQL identifier and **schema-qualifies every evidence
and audit query**: connection `search_path` changes, even pg_temp shadow tables,
cannot redirect writes. The runtime connection must have `autocommit=False`.
A dedicated connection is required per concurrent operation. Use READ COMMITTED
(default); PostgreSQL's parent/event unique constraints make the commit atomic
and allow **at most one** append at a given revision. A concurrent loser fails
closed with stale revision. Deadlock, transaction timeout and SERIALIZABLE
failure are propagated and rolled back; **no automatic replay/retry** is safe
for privileged approval or revocation. An authorized caller must re-read the
packet and re-establish intent before any bounded retry.

A bank-installed PostgreSQL topology must provision an **independent schema
and narrowly scoped credentials per Bank installation**, no common role with
USAGE/ownership/CREATE in other installation schemas. The separate migrator
owns the schema, tables, immutable triggers/functions and migrations. Grant
the runtime writer only schema USAGE; SELECT+INSERT on
`poc_evidence_packets`/`poc_evidence_events`; and INSERT on
`security_audit_events` (with only identity sequence access, if explicitly
needed by a chosen installation). Grant independent audit/evidence readers
schema USAGE and SELECT, **not INSERT or UPDATE**. Neither runtime role may own
tables/functions, create objects in the protected schema, change triggers or
have UPDATE/DELETE/TRUNCATE/DDL authority. Deny other installations' schema
USAGE. Schema-level scoping requires independent credential provisioning
and install validation; this source does not create Bank credentials or
implement row-level SQL isolation within a shared schema. **Do not multiplex
multiple Bank installations through one shared, broadly privileged role.**

The proposal writer still does not own connection pooling, PKI, clock trust,
Bank migrations/privilege provisioning, backup/retention/replication, independent
human accreditation, break-glass, or external ledger attestation. The synthetic
CI role tests demonstrate the stated PostgreSQL privilege **mechanics**, not
Bank installation/certification. Approval/verification provenance cannot be
established by a role, constructed packet or digest alone.

This adapter **never** evaluates the #54 `ready` field, authorizes inline mode,
activates enforcement, or approves CBE acceptance. Remaining Issue #49 gates:
independent human review and authorization, trusted collector/reader and
evidence-source lineage, authoritative verified registry lookup, atomic
readiness+revocation race control, stage-specific Bank approvals, mandatory
privacy/compliance veto, credential revocation and adversarial installed-image
validation. PO → Security/Architecture → Independent QA must independently
review the exact implementation commit before any internal integration.
