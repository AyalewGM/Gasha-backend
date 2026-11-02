-- #42/#43: inactive per-installation atomic outcome/audit composition.
-- Apply as a separate migrator; runtime credentials are provisioned by the Bank.
-- This table is not wired to protected API, not Bank outcome provenance, and
-- must not be read as authorization to execute a payment intervention.
-- Required migrator contract: run in ONE explicit transaction, using a
-- dedicated schema-owner identity. The trusted provisioner must first execute:
--   SELECT set_config('gasha.installation_schema', <trusted schema name>, true);
-- Do not accept the schema name from the API, tenant request or search_path.
-- Runtime roles need separately restricted, non-owner grants; this migration
-- does NOT provision Bank identities, DB roles or row-level security.
-- Pin the DDL target before any unqualified CREATE/trigger name resolution.
DO $gasha_schema_scope$
DECLARE
    expected_schema text;
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', true);
    expected_schema := pg_catalog.current_setting('gasha.installation_schema', true);
    IF expected_schema IS NULL
       OR expected_schema !~ '^[a-z_][a-z0-9_]{0,62}$'
       OR expected_schema IN ('public', 'information_schema')
       OR pg_catalog.left(expected_schema, 3) = 'pg_'
    THEN
        RAISE EXCEPTION 'trusted installation schema configuration required';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace
        WHERE nspname = expected_schema
    ) OR NOT pg_catalog.has_schema_privilege(expected_schema, 'CREATE')
    THEN
        RAISE EXCEPTION 'installation schema unavailable to migrator';
    END IF;
    PERFORM pg_catalog.set_config(
        'search_path', pg_catalog.format('%I, pg_catalog', expected_schema), true
    );
END;
$gasha_schema_scope$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS poc_atomic_outcomes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('gasha', 'incumbent')),
    record_digest TEXT NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
    record_json JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, event_id, outcome_kind, record_digest)
);
CREATE INDEX IF NOT EXISTS poc_atomic_outcomes_history_idx
    ON poc_atomic_outcomes (tenant_id, event_id, outcome_kind, id);

-- Application writes are INSERT-only and every successful terminal transition
-- shares a transaction with the existing redacted security_audit_events table.
-- This trigger protects against accidental mutation, not a malicious DBA.
CREATE OR REPLACE FUNCTION reject_poc_atomic_outcome_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'atomic outcome history is append-only';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'poc_atomic_outcomes'::regclass
          AND tgname = 'poc_atomic_outcomes_immutable'
    ) THEN
        CREATE TRIGGER poc_atomic_outcomes_immutable
        BEFORE UPDATE OR DELETE ON poc_atomic_outcomes
        FOR EACH ROW EXECUTE FUNCTION reject_poc_atomic_outcome_mutation();
    END IF;
END;
$$;
