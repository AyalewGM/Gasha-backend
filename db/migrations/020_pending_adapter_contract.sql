-- #43: Authoritative pending-row adapter policy, separate from mutable record_json.
-- Old rows remain NULL/unverified; do not auto-backfill from self-reported JSON.
-- All SQL is re-entrant for isolated PostgreSQL fixture migration/replay.
ALTER TABLE pending_evaluations
    ADD COLUMN IF NOT EXISTS adapter_type TEXT,
    ADD COLUMN IF NOT EXISTS adapter_schema_version TEXT;

DO $gasha$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'pending_evaluations'::regclass
          AND conname = 'pending_adapter_contract_pair'
    ) THEN
        ALTER TABLE pending_evaluations
            ADD CONSTRAINT pending_adapter_contract_pair CHECK (
                (adapter_type IS NULL AND adapter_schema_version IS NULL) OR
                (adapter_type IS NOT NULL AND adapter_schema_version IS NOT NULL)
            );
    END IF;
END;
$gasha$;
