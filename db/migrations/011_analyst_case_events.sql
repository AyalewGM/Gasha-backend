-- Issue #45: tenant-scoped, append-only analyst transition events.
-- Applied only by a migrator. No grants or bank integration are implied here.
CREATE TABLE IF NOT EXISTS analyst_case_events (
    tenant_id TEXT NOT NULL,
    case_id UUID NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    previous_revision INTEGER,
    source_event_id UUID NOT NULL,
    source_context_ref TEXT NOT NULL CHECK (source_context_ref ~ '^[0-9a-f]{64}$'),
    actor_ref TEXT NOT NULL CHECK (actor_ref ~ '^[0-9a-f]{64}$'),
    occurred_at TIMESTAMPTZ NOT NULL,
    idempotency_ref TEXT NOT NULL CHECK (idempotency_ref ~ '^[0-9a-f]{64}$'),
    command_ref TEXT NOT NULL CHECK (command_ref ~ '^[0-9a-f]{64}$'),
    event_json JSONB NOT NULL,
    bank_execution TEXT NOT NULL DEFAULT 'unknown'
        CHECK (bank_execution = 'unknown'),
    PRIMARY KEY (tenant_id, case_id, revision),
    UNIQUE (tenant_id, idempotency_ref),
    CHECK (
        (revision = 1 AND previous_revision IS NULL)
        OR (revision > 1 AND previous_revision = revision - 1)
    )
);
CREATE INDEX IF NOT EXISTS analyst_case_events_tenant_case_idx
    ON analyst_case_events (tenant_id, case_id, revision DESC);
