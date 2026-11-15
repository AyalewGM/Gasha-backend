-- Issue #147: versioned tenant configuration with explicit lifecycle.
-- Migrator applies this schema; provisioning-writer and runtime-reader roles
-- are separately bank-authorized. No grants or bank integration are implied.
CREATE TABLE IF NOT EXISTS tenant_configurations (
    tenant_id TEXT NOT NULL,
    config_kind TEXT NOT NULL CHECK (
        config_kind IN ('decision_policy', 'detector_policy_bundle')
    ),
    version INTEGER NOT NULL CHECK (version > 0),
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('draft', 'active', 'retired')),
    content_json JSONB NOT NULL,
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    created_by_ref TEXT NOT NULL CHECK (created_by_ref ~ '^[0-9a-f]{64}$'),
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    supersedes_version INTEGER CHECK (
        supersedes_version IS NULL OR supersedes_version < version
    ),
    PRIMARY KEY (tenant_id, config_kind, version),
    CHECK (
        (lifecycle = 'draft' AND activated_at IS NULL AND retired_at IS NULL
            AND supersedes_version IS NULL)
        OR (lifecycle = 'active' AND activated_at IS NOT NULL
            AND activated_at >= created_at AND retired_at IS NULL)
        OR (lifecycle = 'retired' AND activated_at IS NOT NULL
            AND retired_at IS NOT NULL AND retired_at >= activated_at)
    )
);

-- Exactly one ACTIVE row per (tenant, kind).
CREATE UNIQUE INDEX IF NOT EXISTS tenant_configurations_single_active_idx
    ON tenant_configurations (tenant_id, config_kind)
    WHERE lifecycle = 'active';

-- Identity and content columns are write-once; only lifecycle fields may change.
CREATE OR REPLACE FUNCTION reject_tenant_config_content_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant configuration identity and content are write-once';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'tenant_configurations_content_immutable'
    ) THEN
        CREATE TRIGGER tenant_configurations_content_immutable
        BEFORE UPDATE OF tenant_id, config_kind, version, content_json,
            content_digest, created_at, created_by_ref
        ON tenant_configurations
        FOR EACH ROW EXECUTE FUNCTION reject_tenant_config_content_mutation();
    END IF;
END $$;
