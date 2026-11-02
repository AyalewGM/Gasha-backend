-- OPT-IN ONLY: synthetic database-authenticated outcome audit proof (#42/#43).
-- Apply separately after 013 and 014, under the trusted schema-owner migrator
-- in ONE transaction with gasha.installation_schema set by the provisioner.
-- Never part of the worker migration glob. This is NOT Bank-approved auditing:
-- it binds PostgreSQL LOGIN identity, not the Bank end-user or source-of-truth
-- adjudicator. No protected endpoint, payment decision or readiness activation.
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
       OR pg_catalog.to_regclass(
           pg_catalog.format('%I.poc_outcome_runtime_tenants', target)
       ) IS NULL
       OR pg_catalog.to_regclass(
           pg_catalog.format('%I.security_audit_events', target)
       ) IS NULL
       OR pg_catalog.to_regprocedure(
           pg_catalog.format('%I.poc_outcome_bound_tenant()', target)
       ) IS NULL
    THEN
        RAISE EXCEPTION 'opt-in migrations 013 and 014 and audit schema required';
    END IF;
    PERFORM pg_catalog.set_config(
        'search_path', pg_catalog.format('%I, pg_catalog', target), true
    );
END;
$installation$ LANGUAGE plpgsql;

-- Single-use synthetic claim ledger: the same outcome cannot be anchored twice,
-- and an attempt token cannot be reused for another outcome. The unique
-- constraints serialize concurrent callers; a failed claim INSERT rolls back
-- the audit INSERT in the same transaction. Existing pre-upgrade anchors are
-- NOT retrospectively authenticated or deduplicated by this prototype.
CREATE TABLE IF NOT EXISTS poc_outcome_audit_claims (
    outcome_id BIGINT PRIMARY KEY REFERENCES poc_atomic_outcomes(id),
    attempt_ref TEXT NOT NULL UNIQUE
        CHECK (attempt_ref ~ '^[0-9a-f]{32}$'),
    audit_id BIGINT NOT NULL UNIQUE REFERENCES security_audit_events(id)
);
REVOKE ALL ON TABLE poc_outcome_audit_claims FROM PUBLIC;

-- No caller-supplied actor, tenant, event, clock, action, result or reason.
-- The trusted PostgreSQL LOGIN OID must have a live approved tenant binding,
-- and the referenced outcome must belong to that bound tenant. SECURITY
-- DEFINER bypasses row policies, hence the explicit tenant equality below.
-- The caller supplies an attempt correlation string only. The result is
-- 'observed', NEVER terminal 'succeeded': no Bank actor or real attempt is
-- authenticated and no source-of-truth adjudication is established.
DO $function$
DECLARE
    target text := pg_catalog.current_setting('gasha.installation_schema', true);
BEGIN
    EXECUTE pg_catalog.format(
        $ddl$
        CREATE OR REPLACE FUNCTION %I.poc_append_db_outcome_audit(
            p_outcome_id bigint, p_attempt_ref text
        ) RETURNS bigint
        LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        DECLARE
            bound_tenant text;
            login_oid oid;
            outcome_tenant text;
            outcome_event uuid;
            outcome_kind text;
            audit_id bigint;
        BEGIN
            IF p_outcome_id IS NULL OR p_outcome_id <= 0
               OR p_attempt_ref IS NULL
               OR p_attempt_ref !~ '^[0-9a-f]{32}$'
            THEN
                RAISE EXCEPTION 'invalid database-audit invocation';
            END IF;
            SELECT b.tenant_id, r.oid INTO bound_tenant, login_oid
            FROM %I.poc_outcome_runtime_tenants AS b
            JOIN pg_catalog.pg_roles AS r ON r.oid = b.login_role_oid
            WHERE r.rolname = SESSION_USER
              AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls;
            IF bound_tenant IS NULL THEN
                RAISE EXCEPTION 'trusted login tenant binding required';
            END IF;
            SELECT o.tenant_id, o.event_id, o.outcome_kind
            INTO outcome_tenant, outcome_event, outcome_kind
            FROM %I.poc_atomic_outcomes AS o
            WHERE o.id = p_outcome_id AND o.tenant_id = bound_tenant;
            IF outcome_tenant IS NULL THEN
                RAISE EXCEPTION 'tenant-scoped persisted outcome required';
            END IF;
            INSERT INTO %I.security_audit_events (
                occurred_at, action, result, actor_ref, tenant_ref,
                reason, attempt_ref, event_ref, context_ref
            ) VALUES (
                pg_catalog.clock_timestamp(),
                CASE WHEN outcome_kind = 'gasha'
                    THEN 'outcome.audit_anchor'
                    ELSE 'incumbent_outcome.audit_anchor' END,
                'observed',
                'db-login-oid-sha256:' || pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to('gasha-db-login-audit-v1:' ||
                        login_oid::text, 'UTF8')), 'hex'),
                pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(bound_tenant, 'UTF8')), 'hex'),
                'persisted_outcome_exists', p_attempt_ref,
                pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(bound_tenant, 'UTF8') ||
                    pg_catalog.decode('00', 'hex') ||
                    pg_catalog.convert_to(outcome_event::text, 'UTF8')
                ), 'hex'), ''
            ) RETURNING id INTO audit_id;
            INSERT INTO %I.poc_outcome_audit_claims (
                outcome_id, attempt_ref, audit_id
            ) VALUES (p_outcome_id, p_attempt_ref, audit_id);
            RETURN audit_id;
        END;
        $body$;
        $ddl$,
        target, target, target, target, target
    );
END;
$function$ LANGUAGE plpgsql;

-- PostgreSQL grants are intentionally not installed by migrations. The DBA
-- MUST REVOKE any preexisting direct audit INSERT from runtime roles before
-- granting narrowly scoped EXECUTE on this function. This prototype does not
-- replace the current writer's raw INSERT path; the protected outcome routes
-- remain disabled until a reviewed, atomic writer/audit composition exists.
REVOKE ALL ON FUNCTION poc_append_db_outcome_audit(bigint, text) FROM PUBLIC;
