-- Append-only outcome history (Epic #3/#4 outcome reconciliation).
-- Late outcomes are separate rows; the T0 decision is never mutated.
-- Ordering column preserves append order per (tenant_id, event_id).

CREATE TABLE IF NOT EXISTS outcome_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    record_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_outcome_records_tenant_event
    ON outcome_records (tenant_id, event_id, id);

CREATE TABLE IF NOT EXISTS incumbent_outcome_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    record_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_incumbent_outcome_records_tenant_event
    ON incumbent_outcome_records (tenant_id, event_id, id);
