-- Retained terminal tombstones prevent redelivery from recreating failed work.
ALTER TABLE pending_evaluations ADD COLUMN IF NOT EXISTS terminal BOOLEAN NOT NULL DEFAULT FALSE;
