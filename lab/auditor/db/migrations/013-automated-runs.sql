-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- "Fully Automated Run" - a single action that drives Discovery through
-- NCA sign-off with no human clicks, per device or the whole fleet. The
-- worker orchestrator (automated_run_runner.py) is the sole executor,
-- exactly like every other job in this schema - auditor-api only ever
-- manages this row, never runs anything itself.
-- ===================================================================

CREATE TABLE IF NOT EXISTS automated_runs (
    id             SERIAL PRIMARY KEY,
    status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    device_ids     JSONB,  -- null/absent = whole fleet, including a fresh Discovery sweep
    current_stage  TEXT,
    summary        JSONB NOT NULL DEFAULT '{}',
    error          TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

-- ===================================================================
-- Marks a compliance_assessments row as system-recorded with no human
-- review, distinct from attestation_confirmed (which the runner also sets
-- true, honestly representing "the system confirmed this data exists" -
-- auto_recorded is the flag that actually says "no person looked at it
-- yet"). The dashboard badges these differently and offers a "Review &
-- confirm" action that supersedes an auto-recorded row with a real
-- human-signed one via the existing retest mechanism - the original row is
-- never deleted, both stay in the audit trail.
-- ===================================================================

ALTER TABLE compliance_assessments
    ADD COLUMN IF NOT EXISTS auto_recorded BOOLEAN NOT NULL DEFAULT false;
