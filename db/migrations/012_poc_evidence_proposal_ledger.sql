-- Issue #49: opt-in tenant/installation-scoped evidence proposal persistence.
-- NOT an authoritative Bank verifier, identity plane, or readiness approval.
-- Migrator applies this schema; Bank installation must provision scoped DB roles.
CREATE TABLE IF NOT EXISTS poc_evidence_packets (
    tenant_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    packet_digest TEXT NOT NULL CHECK (packet_digest ~ '^sha256:[0-9a-f]{64}$'),
    packet_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, installation_id, packet_digest)
);

CREATE TABLE IF NOT EXISTS poc_evidence_events (
    tenant_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    packet_digest TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    action TEXT NOT NULL CHECK (
        action IN ('submit', 'verify', 'approve', 'revoke_evidence', 'revoke_approval')
    ),
    actor_ref TEXT NOT NULL CHECK (actor_ref ~ '^[0-9a-f]{64}$'),
    occurred_at TIMESTAMPTZ NOT NULL,
    evidence_id UUID,
    event_json JSONB NOT NULL,
    PRIMARY KEY (tenant_id, installation_id, packet_digest, revision),
    FOREIGN KEY (tenant_id, installation_id, packet_digest)
        REFERENCES poc_evidence_packets (tenant_id, installation_id, packet_digest)
);

-- Application code exposes INSERT-only writes; these triggers also prevent
-- accidental UPDATE/DELETE even if application privileges are overbroad.
-- They are not a defense against a malicious database administrator.
CREATE OR REPLACE FUNCTION reject_poc_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'evidence proposal history is append-only';
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'poc_evidence_packets'::regclass
                   AND tgname = 'poc_evidence_packet_immutable') THEN
        CREATE TRIGGER poc_evidence_packet_immutable
        BEFORE UPDATE OR DELETE ON poc_evidence_packets
        FOR EACH ROW EXECUTE FUNCTION reject_poc_evidence_mutation();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'poc_evidence_events'::regclass
                   AND tgname = 'poc_evidence_event_immutable') THEN
        CREATE TRIGGER poc_evidence_event_immutable
        BEFORE UPDATE OR DELETE ON poc_evidence_events
        FOR EACH ROW EXECUTE FUNCTION reject_poc_evidence_mutation();
    END IF;
END;
$$;