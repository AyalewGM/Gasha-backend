-- #148 corrective scope: provenance for EVERY opt-in shadow evaluation,
-- including ALLOW/MONITOR events which do not create an alert.
-- The tenant policy installation table is a separately provisioned trust
-- boundary. Application runtime identities MUST have SELECT only; the
-- authorized provisioning role alone may INSERT into installations. This
-- migration neither provisions a policy nor grants execution authority.
CREATE TABLE IF NOT EXISTS tenant_alert_policy_installations (
    tenant_id TEXT NOT NULL,
    policy_id TEXT NOT NULL CHECK (length(trim(policy_id)) > 0),
    policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) > 0),
    digest_schema TEXT NOT NULL CHECK (length(trim(digest_schema)) > 0),
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    content_json JSONB NOT NULL CHECK (jsonb_typeof(content_json) = 'object'),
    installation_ref TEXT NOT NULL CHECK (installation_ref ~ '^[0-9a-f]{64}$'),
    installed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, policy_id, policy_version),
    UNIQUE (tenant_id, installation_ref)
);

-- The installer's immutable policy row is not created or derived from
-- evaluation requests. A new version requires a separate provisioning act.
CREATE TABLE IF NOT EXISTS evaluation_alert_policy_provenance (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    digest_schema TEXT NOT NULL,
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    installation_ref TEXT NOT NULL CHECK (installation_ref ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES shadow_evaluations (tenant_id, event_id),
    FOREIGN KEY (tenant_id, policy_id, policy_version)
        REFERENCES tenant_alert_policy_installations (tenant_id, policy_id, policy_version)
);

CREATE OR REPLACE FUNCTION reject_alert_policy_provenance_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'alert policy installation and provenance are immutable';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'tenant_alert_policy_installations_immutable'
          AND tgrelid = 'tenant_alert_policy_installations'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER tenant_alert_policy_installations_immutable
            BEFORE UPDATE OR DELETE ON tenant_alert_policy_installations
            FOR EACH ROW EXECUTE FUNCTION reject_alert_policy_provenance_mutation();
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'evaluation_alert_policy_provenance_immutable'
          AND tgrelid = 'evaluation_alert_policy_provenance'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER evaluation_alert_policy_provenance_immutable
            BEFORE UPDATE OR DELETE ON evaluation_alert_policy_provenance
            FOR EACH ROW EXECUTE FUNCTION reject_alert_policy_provenance_mutation();
    END IF;
END $$;

-- A runtime INSERT must not be able to attach policy provenance to a
-- previously committed (pre-migration) shadow evaluation. The new shadow row
-- and provenance are inserted in the *same transaction* by the atomic writer.
-- Check the shadow row's creating transaction ID, not caller-controlled event
-- time or a claimed version string. XIDs are 32-bit; txid_current() is 64-bit.
--
-- SECURITY DEFINER reads only the trusted table in the trigger's own schema,
-- not a shadow_evaluations relation injected via the runtime search_path.
-- The runtime role must not own the function/schema or be able to disable
-- the trigger. Legacy repair requires a separately privileged, audited
-- migration; this function deliberately does not provide a repair escape.
CREATE OR REPLACE FUNCTION enforce_initial_alert_policy_provenance()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    is_new_evaluation BOOLEAN;
BEGIN
    EXECUTE format(
        'SELECT EXISTS (SELECT 1 FROM %I.shadow_evaluations '
        'WHERE tenant_id = $1 AND event_id = $2 '
        'AND xmin::text = ($3 %% 4294967296)::text)',
        TG_TABLE_SCHEMA
    )
    INTO is_new_evaluation
    USING NEW.tenant_id, NEW.event_id, txid_current();

    IF NOT is_new_evaluation THEN
        RAISE EXCEPTION
            'alert policy provenance requires same-transaction evaluation creation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'evaluation_alert_policy_provenance_initial_only'
          AND tgrelid = 'evaluation_alert_policy_provenance'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER evaluation_alert_policy_provenance_initial_only
            BEFORE INSERT ON evaluation_alert_policy_provenance
            FOR EACH ROW EXECUTE FUNCTION enforce_initial_alert_policy_provenance();
    END IF;
END $$;

-- Legacy evaluations have no provenance row. Their duplicate replay MUST
-- fail closed, not be inferred from a version label. A controlled migration
-- needs original trusted policy bytes and separate review/authorization.
