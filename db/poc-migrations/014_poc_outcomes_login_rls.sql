-- OPT-IN ONLY, after 013_poc_atomic_outcomes.sql; never part of worker bootstrap.
-- Issue #42/#43: synthetic same-schema PostgreSQL tenant-isolation candidate.
-- A Bank DBA must independently provision a non-owner, NOBYPASSRLS LOGIN
-- runtime role, tightly scoped grants, and a trusted role-OID -> tenant binding.
-- No HTTP input, policy assertion, tenant GUC or search_path controls identity.
-- This migration does NOT provision Bank credentials, make outcomes authoritative,
-- wire protected endpoints, or authorize any payment intervention.
-- Apply in ONE explicit trusted migrator transaction with:
--   SELECT set_config('gasha.installation_schema', <trusted schema>, true);
DO $installation$
DECLARE
    target text;
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog', true);
    target := pg_catalog.current_setting('gasha.installation_schema', true);
    IF target IS NULL
       OR target !~ '^[a-z_][a-z0-9_]{0,62}$'
       OR target IN ('public', 'information_schema')
       OR pg_catalog.left(target, 3) = 'pg_'
    THEN
        RAISE EXCEPTION 'trusted installation schema configuration required';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = target
    ) OR NOT pg_catalog.has_schema_privilege(target, 'CREATE')
    THEN
        RAISE EXCEPTION 'installation schema unavailable to migrator';
    END IF;
    IF pg_catalog.to_regclass(pg_catalog.format('%I.poc_atomic_outcomes', target))
       IS NULL
    THEN
        RAISE EXCEPTION 'opt-in outcome migration 013 required before RLS';
    END IF;
    PERFORM pg_catalog.set_config(
        'search_path', pg_catalog.format('%I, pg_catalog', target), true
    );
END;
$installation$ LANGUAGE plpgsql;

-- The login ROLE OID (not its name) prevents silent reauthorization after
-- DROP ROLE / CREATE ROLE using the same name. Only the trusted migrator/owner
-- may edit bindings; runtime logins must never receive privileges on this table.
CREATE TABLE IF NOT EXISTS poc_outcome_runtime_tenants (
    login_role_oid OID PRIMARY KEY,
    tenant_id TEXT NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
);
REVOKE ALL ON TABLE poc_outcome_runtime_tenants FROM PUBLIC;

-- Resolve the session's authenticated database LOGIN rather than CURRENT_USER
-- (which changes inside SECURITY DEFINER), and prohibit superuser/BYPASSRLS.
-- Schema is embedded as a quoted identifier after the trusted guard; do not
-- resolve any runtime-controlled schema or object via the session search_path.
DO $function$
DECLARE
    target text := pg_catalog.current_setting('gasha.installation_schema', true);
BEGIN
    EXECUTE pg_catalog.format(
        'CREATE OR REPLACE FUNCTION %I.poc_outcome_bound_tenant()
         RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
         SET search_path = pg_catalog AS $bound$
           SELECT b.tenant_id
           FROM %I.poc_outcome_runtime_tenants AS b
           JOIN pg_catalog.pg_roles AS r ON r.oid = b.login_role_oid
           WHERE r.rolname = SESSION_USER
             AND r.rolcanlogin
             AND NOT r.rolsuper
             AND NOT r.rolbypassrls
         $bound$', target, target
    );
END;
$function$ LANGUAGE plpgsql;

REVOKE ALL ON FUNCTION poc_outcome_bound_tenant() FROM PUBLIC;
REVOKE ALL ON TABLE poc_atomic_outcomes FROM PUBLIC;

-- Owners/roles with BYPASSRLS can bypass row policies. An installed deployment
-- MUST use a separately provisioned non-owner, NOBYPASSRLS runtime LOGIN.
ALTER TABLE poc_atomic_outcomes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS poc_atomic_outcome_login_scope ON poc_atomic_outcomes;
CREATE POLICY poc_atomic_outcome_login_scope ON poc_atomic_outcomes
    FOR ALL
    USING (tenant_id = poc_outcome_bound_tenant())
    WITH CHECK (tenant_id = poc_outcome_bound_tenant());

-- Provisioning is deliberately external: Bank owner binds login role OID to
-- one tenant, then grants schema USAGE, outcome SELECT/INSERT, audit INSERT,
-- and EXECUTE on poc_outcome_bound_tenant() to that role only. Verify actual
-- session_user/current_user, ACLs, membership, revoked-login sessions and
-- same-schema/cross-installation attempts independently before any wiring.
