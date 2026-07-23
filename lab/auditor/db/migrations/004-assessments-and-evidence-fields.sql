-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Week 1 gap-analysis closure: a real Assessment entity grouping a batch of
-- scan_jobs, plus evidence/verdict fields the mentor brief asked for
-- (source_type, confidence_reason, error_state, policy_version, conflict
-- detection). Additive to the existing evidence/verdicts/scan_jobs tables -
-- old rows keep working with assessment_id = NULL.
-- ===================================================================

CREATE TABLE IF NOT EXISTS assessments (
    id               TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'running', 'partially_completed', 'completed', 'failed', 'cancelled')),
    policy_version   TEXT,
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    error            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assessments_device_id ON assessments(device_id);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);

ALTER TABLE evidence ADD COLUMN IF NOT EXISTS assessment_id TEXT REFERENCES assessments(id) ON DELETE SET NULL;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'automated';
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS confidence_reason TEXT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS error_state TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'evidence_source_type_check'
    ) THEN
        ALTER TABLE evidence ADD CONSTRAINT evidence_source_type_check
            CHECK (source_type IN ('automated', 'manual', 'document'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_evidence_assessment_id ON evidence(assessment_id);

ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS assessment_id TEXT REFERENCES assessments(id) ON DELETE SET NULL;
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS policy_version TEXT;
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS conflict_detected BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS conflict_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_verdicts_assessment_id ON verdicts(assessment_id);

ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS assessment_id TEXT REFERENCES assessments(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_scan_jobs_assessment_id ON scan_jobs(assessment_id);
