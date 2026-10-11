-- Append-only dead-letter sink for rejected inbound events.
-- RejectionRecord already carries minimized evidence — no raw payloads.

CREATE TABLE IF NOT EXISTS dead_letters (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT,
    event_id TEXT,
    record_json TEXT NOT NULL,
    rejected_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dead_letters_tenant
    ON dead_letters (tenant_id, rejected_at DESC);
