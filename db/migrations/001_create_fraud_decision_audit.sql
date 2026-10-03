-- Production decision-audit persistence contract for Epic #2.
-- Apply through the bank/environment migration mechanism; do not embed tenant names.

CREATE TABLE IF NOT EXISTS fraud_decision_audit (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    decision_json TEXT NOT NULL,
    signal_policy_versions_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_fraud_decision_audit_tenant_decided_at
    ON fraud_decision_audit (tenant_id, decided_at DESC);
