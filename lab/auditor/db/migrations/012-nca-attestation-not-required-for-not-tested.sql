-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Corrects 011's attestation_confirmed CHECK: it required attestation on
-- EVERY row, but /nca/assessments/recompute inserts real 'not_tested'
-- placeholder rows (assessed_by = 'system:recompute') with no human
-- attestation at all - that is the correct, honest shape for "nothing has
-- been asserted yet", not a bug to work around. Attestation is only
-- meaningful for a real human verdict (pass/partial/fail/review_required).
-- ===================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'compliance_assessments_attestation_confirmed_check'
    ) THEN
        ALTER TABLE compliance_assessments
            DROP CONSTRAINT compliance_assessments_attestation_confirmed_check;
    END IF;
    ALTER TABLE compliance_assessments
        ADD CONSTRAINT compliance_assessments_attestation_confirmed_check
        CHECK (status = 'not_tested' OR attestation_confirmed = true);
END $$;
