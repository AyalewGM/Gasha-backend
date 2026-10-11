-- Production journey-event persistence for UC-03.
-- Tenant-scoped; queried by (tenant_id, customer_id, occurred_at window).

CREATE TABLE IF NOT EXISTS journey_events (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    customer_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    event_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_journey_events_tenant_customer_time
    ON journey_events (tenant_id, customer_id, occurred_at);
