-- Production ingestion idempotency store (Epic #4).
-- (tenant_id, event_id) is the deduplication anchor; first write wins.

CREATE TABLE IF NOT EXISTS ingestion_records (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    envelope_json TEXT NOT NULL,
    payload_fingerprint TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);
