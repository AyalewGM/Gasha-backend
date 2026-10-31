# Issue #42: optional PostgreSQL security-audit port (internal POC)

`PostgresSecurityAuditSink` is an **inert, opt-in implementation** of the
existing `SecurityAuditSink` contract integrated through PR #55.
It is not configured by `gasha.api.main:app` or any bank deployment; protected API state remains explicitly unwired by default. Merely installing this adapter or configuring a DSN must never grant a banking service audit authority.
It inserts redacted action/result/reason codes, pseudonymous actor and tenant
references, a server-generated attempt reference, optional event/context
hashes and a timezone-aware timestamp. No raw token, issuer, subject,
customer or transaction identifier column is introduced.

Apply `db/migrations/010_security_audit_events.sql` through a separately
authorized migrator before provisioning a sink. The adapter accepts an
existing `gasha.postgres.Connection` and commits every appended event;
insert/commit failures propagate (with attempted rollback) so protected
requests can fail closed. It has no update/delete API. This is **not** a
database permission or tamper-proof ledger: a bank-owned provisioning
procedure must grant the runtime identity INSERT-only access, constrain
SELECT/UPDATE/DELETE/DDL and backup/retention privileges, and independently
verify them with negative tests. Supply a dedicated connection and a
bank-approved lifecycle/concurrency strategy; a shared test connection is
not an operational pool.

Validation accepts only code-shaped action/result/reason, a SHA-256 tenant
reference, a SHA-256 actor reference or `anonymous`, a 32-character generated
attempt reference, and optional SHA-256 event/context references. Malformed
or raw identifiers fail before SQL. This validates *shape*, not authentic
actor attribution or source provenance. Authentication, IdP revocation,
service tenant/role scope, row privileges, immutable provenance, a trusted
evidence registry and authorized bank approvals remain separate gates.

Tests: `tests/test_security_postgres_audit.py` uses synthetic SQL spies
for redaction and rollback; `tests/test_postgres_security_audit.py` uses
actual PostgreSQL only when `GASHA_TEST_POSTGRES_DSN` is configured and
must run with zero skips in the dedicated integration job. Do not treat
green CI as installed bank audit, Bank acceptance or inline authorization.
