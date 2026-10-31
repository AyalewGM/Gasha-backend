# Worker provisioning gate

Bank-facing deployment is **blocked** until the bank's authorized infrastructure/security owner and Gasha PO/Architecture approve a provisioning record for the exact deployment. A tenant list in an environment variable is configuration, not proof of bank authorization. The development compose stack and its credentials are synthetic local development only.

In durable PostgreSQL mode, `GASHA_TENANT_IDS` must be a JSON list of
**unique, nonblank, printable tenant identifiers without surrounding
whitespace**. Empty/missing lists, duplicates, control/invisible-character
entries, and padded identifiers fail startup before opening a database
connection. This is configuration shape validation, **not Bank approval** of
the named tenants or proof of matching DB/Kafka privileges.

The worker also rejects an invalid `GASHA_LEASE_TTL_S` (nonfinite, zero,
negative, sub-microsecond values that round to a zero `timedelta`, or
unrepresentably large values) before opening PostgreSQL. This setting
controls the pending-evaluation ownership lease; an ineffective lease
prevents the accepted worker from evaluating or recovering pending events.
Syntactically valid values still require an operator-selected lease long
enough for actual evaluation persistence and recovery, verified under the
Bank-approved workload. This startup check is **not** proof of those
performance or failure-recovery budgets.

The approved record must identify:

- The service identity, authorized tenant IDs, environment, Kafka topic/group and database role; record the approver and approval/change reference.
- Who may provision or change GASHA_TENANT_IDS, topic/group, policies and secrets. Restrict these through deployment RBAC; the application runtime must not edit its own authorization/configuration or grant roles.
- Kafka credentials and ACLs restricted to approved topics/groups; restrict producers as well as consumers so foreign tenants cannot inject events into an authorized feed. Avoid wildcard grants. Bind adapters and tenant provenance to the approved source integration.
- Separate migration and runtime database identities. Runtime credentials must have only required table operations, no schema/role administration or superuser/BYPASSRLS privileges. The infrastructure owner must validate database tenant restrictions (for example approved RLS policies or dedicated scoped credentials/database) against the approved tenant set. Application repository checks alone do not constrain arbitrary SQL issued with stolen credentials.
- Secret/certificate injection and rotation, network controls, revocation and audit evidence for scope changes. Never put credentials or customer records in GitHub or fixtures.

Deployment release evidence must reference this approved record and include negative Kafka ACL and database permission tests using the actual runtime identities. Missing approval, credential scope, or negative-test evidence keeps bank-facing deployment blocked; no calendar date or passing synthetic test waives this gate. This PR does not supply bank provisioning, grant authorization, or permit enforcement.

Apply migration 008 before starting the updated worker. Existing pending rows with no claim token must be reclaimed after their lease expires. Roll out with old workers stopped: old binaries do not implement generation fencing. Never run mixed old/new workers. Worker leases must exceed expected evaluation persistence time; a worker that misses the lease window leaves work for recovery rather than persisting a stale decision.

Apply migration 009 before starting workers with atomic terminal handling. Terminal pending rows are retained as idempotency tombstones, with the original envelope and pinned policy. They are excluded from claims and prevent Kafka redelivery from restarting failed work. Do not delete these rows independently of an approved replay/retention procedure; deletion would remove that replay fence. Terminal DLQ insertion and tombstone finalization share one PostgreSQL transaction and the same row lock used by successful evidence persistence.
