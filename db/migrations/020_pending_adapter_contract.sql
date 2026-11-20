-- #43: Authoritative pending-row adapter contract, separate from mutable record_json.
-- Historical rows remain NULL/unverified rather than trusting adapter claims from JSON.
-- Recovery quarantines unbound legacy rows; re-enqueue from authenticated inputs
-- after an operator-reviewed migration plan. Never auto-backfill from record_json.
ALTER TABLE pending_evaluations
    ADD COLUMN adapter_type TEXT,
    ADD COLUMN adapter_schema_version TEXT;

ALTER TABLE pending_evaluations
    ADD CONSTRAINT pending_adapter_contract_pair CHECK (
        (adapter_type IS NULL AND adapter_schema_version IS NULL) OR
        (adapter_type IS NOT NULL AND adapter_schema_version IS NOT NULL)
    );
