-- Production shadow-evaluation persistence (Epic #4 + UC-03).
-- First write wins: the persisted record is the auditable T0 evaluation.

CREATE TABLE IF NOT EXISTS shadow_evaluations (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    record_json TEXT NOT NULL,
    persisted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_shadow_evaluations_tenant_persisted
    ON shadow_evaluations (tenant_id, persisted_at DESC);
