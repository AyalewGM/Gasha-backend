-- Issue #42: redacted security events for an explicitly wired audit sink.
-- Schema migration runs under a dedicated migrator identity. Bank runtime roles
-- require separately provisioned INSERT-only privileges; this migration does
-- not grant them or establish an authoritative bank audit service.
CREATE TABLE IF NOT EXISTS security_audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    actor_ref TEXT NOT NULL,
    tenant_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    attempt_ref TEXT NOT NULL,
    event_ref TEXT NOT NULL,
    context_ref TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS security_audit_events_tenant_time_idx
    ON security_audit_events (tenant_ref, occurred_at DESC, id DESC);
