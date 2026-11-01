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
- An insert-first parent packet key and `SELECT ... FOR UPDATE` serialize
  competing first and later writers for the same exact packet digest. Every
  caller supplies `expected_revision`; stale revisions reject. Event rows
  are replayed and checked against metadata, canonical JSON, packet versions,
  permissions and separation-of-duties rules. A changed packet creates a
  different identity; no approval or revocation carries over.
- Successful transitions append a redacted security audit record (actor/tenant/
  packet/attempt digest refs only) **in the same transaction**. Audit failure
  rolls back both proposal event and initial packet. No standalone audit-sink
  commit is called within that transaction.
- Real PostgreSQL integration tests cover lifecycle, cross-tenant/capability
  denials, stale revisions, unavailable/mismatched artifact reading, dropped
  audit availability, append-only triggers, corrupted packet history and two
  independent racing PostgreSQL connections. The test fixtures are synthetic.

## Scope and limitations

This is **not** a trusted registry and grants **no readiness or Bank approval**.
A caller able to construct a packet or a `TrustedPrincipal` in Python can still
submit fabricated origin claims unless a future Bank-installed trust boundary
binds them to credentials, authorized source records and verified immutable
artifacts. A matching digest does not authenticate the referenced source.
Readiness must never consume this ledger until independently accepted Bank
identity, artifact access, policy/packet issuance, stage approval and evaluation
bindings exist. A successful transaction creates proposal history only.

The code takes a **dedicated connection per concurrent operation**. It does not
own connection pooling, PKI, clock trust, migrations, DB privilege provisioning,
backup/retention/replication, independent human accreditation, break-glass, or
external ledger attestation. Bank-specific installation must separately provide
runtime roles with schema-scoped INSERT/SELECT and audit INSERT, no UPDATE/DELETE,
and a distinct migrator role. Triggers/SQL constraints alone are not tenancy
isolation: runtime Bank DB credentials and scoped access controls still must
be independently verified. A bank-selected trust service, no shared cross-bank
store, and approved deletion/retention policy remain external requirements.

This adapter **never** evaluates the #54 `ready` field, authorizes inline mode,
activates enforcement, or approves CBE acceptance. Remaining Issue #49 gates:
independent human review and authorization, trusted collector/reader and
evidence-source lineage, authoritative verified registry lookup, atomic
readiness+revocation race control, stage-specific Bank approvals, mandatory
privacy/compliance veto, credential revocation and adversarial installed-image
validation. PO → Security/Architecture → Independent QA must independently
review the exact implementation commit before any internal integration.
