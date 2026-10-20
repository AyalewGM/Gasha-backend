-- Existing claims receive no token and must be reclaimed before mutation.
ALTER TABLE pending_evaluations ADD COLUMN IF NOT EXISTS lease_token UUID;
