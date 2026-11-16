-- #148 defense-in-depth: immutable shadow evaluations are first-writer-wins.
-- Migration 018 uses xmin to check that evaluation and policy provenance were
-- inserted in the same transaction. xmin also changes on UPDATE, including a
-- no-op UPDATE; without this control a runtime identity holding UPDATE plus
-- provenance INSERT could refresh a committed legacy row and forge provenance.
--
-- The runtime may need a narrow UPDATE *privilege* for SELECT ... FOR UPDATE;
-- PostgreSQL row-locking does not fire this UPDATE trigger. Actual UPDATE or
-- DELETE is rejected, even for a no-op update, under that runtime privilege.
-- Grant schema/table/function ownership and ALTER TRIGGER only to a distinct
-- trusted migration/DB owner. No runtime TRIGGER, CREATE, or table ownership.
--
-- Forward migration: apply after 018 in every installation. If 018 was
-- deployed before 019, independently audit old evaluation/provenance rows;
-- neither their insertion time nor trusted provenance can be reconstructed
-- merely from xmin. Unverifiable legacy rows remain blocked from replay.
-- This migration neither backfills provenance nor authorizes Bank operation.
CREATE OR REPLACE FUNCTION reject_shadow_evaluation_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'shadow evaluations are immutable after insertion'
        USING ERRCODE = '23514';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'shadow_evaluations_immutable'
          AND tgrelid = 'shadow_evaluations'::regclass
          AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER shadow_evaluations_immutable
            BEFORE UPDATE OR DELETE ON shadow_evaluations
            FOR EACH ROW EXECUTE FUNCTION reject_shadow_evaluation_mutation();
    END IF;
END $$;
