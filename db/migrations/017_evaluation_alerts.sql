-- #148: immutable, tenant-scoped evaluation evidence attached to a case.
CREATE TABLE IF NOT EXISTS evaluation_alerts (
    tenant_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    case_id UUID NOT NULL,
    case_revision INTEGER NOT NULL DEFAULT 1 CHECK (case_revision = 1),
    group_ref TEXT NOT NULL CHECK (group_ref ~ '^[0-9a-f]{64}$'),
    context_ref TEXT NOT NULL CHECK (context_ref ~ '^[0-9a-f]{64}$'),
    policy_version TEXT NOT NULL,
    decision_action TEXT NOT NULL CHECK (decision_action IN ('review', 'hold', 'block')),
    risk_score DOUBLE PRECISION NOT NULL CHECK (risk_score BETWEEN 0 AND 1),
    priority_seed INTEGER NOT NULL CHECK (priority_seed BETWEEN 1 AND 3),
    scenario_ids JSONB NOT NULL CHECK (jsonb_typeof(scenario_ids) = 'array'),
    generated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES shadow_evaluations (tenant_id, event_id),
    FOREIGN KEY (tenant_id, case_id, case_revision)
        REFERENCES analyst_case_events (tenant_id, case_id, revision)
);

CREATE INDEX IF NOT EXISTS evaluation_alerts_group_idx
    ON evaluation_alerts (tenant_id, group_ref, generated_at DESC, event_id);
