-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Compliance-assessment robustness pass: a real REVIEW_REQUIRED status
-- (distinct from NOT_TESTED - something WAS assessed, e.g. conflicting
-- evidence, and needs a human to look at it) and a per-control `blocking`
-- flag (see policies/nca/build_catalog.py's BLOCKING_GUIDELINES and
-- policies/nca/evaluator.py::overall_classification) so a small set of
-- severe, well-known device weaknesses (default credentials, unencrypted
-- sensitive data, unnecessary/insecure exposed services) can force an
-- overall device readiness classification to FAILED regardless of score.
-- Additive: both defaults preserve every existing row's current meaning.
-- ===================================================================

ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS blocking BOOLEAN NOT NULL DEFAULT false;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'compliance_assessments_status_check'
    ) THEN
        ALTER TABLE compliance_assessments DROP CONSTRAINT compliance_assessments_status_check;
    END IF;
    ALTER TABLE compliance_assessments ADD CONSTRAINT compliance_assessments_status_check
        CHECK (status IN ('pass', 'partial', 'fail', 'not_tested', 'review_required'));
END $$;
