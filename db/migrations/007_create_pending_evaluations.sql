-- Pending-evaluation ledger (M2 event-driven worker).
-- Rows survive process restarts; an acknowledged-but-unevaluated event
-- is recovered autonomously without transport redelivery.
-- leased_by/leased_until implement atomic multi-worker ownership:
-- due() claims rows with FOR UPDATE SKIP LOCKED and reschedule/
-- complete are conditional on the lease owner.

CREATE TABLE IF NOT EXISTS pending_evaluations (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    record_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    enqueued_at TIMESTAMPTZ NOT NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_error TEXT,
    leased_by TEXT,
    leased_until TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_pending_evaluations_due
    ON pending_evaluations (next_attempt_at)
    WHERE leased_until IS NULL;
