-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Guided checklist support for organizational-scope NCA guidelines (no scan
-- can ever produce evidence for "was this policy approved" or "were staff
-- trained" - see policies/nca/checklists.py). One row per guideline that
-- has a checklist; a guideline with no row here simply has no guided flow
-- yet (an expected, honest partial-rollout state - see
-- GET /nca/controls/{id}/checklist's 404 case).
--
-- `questions` is an ordered JSONB array of
-- {key, label, type: "yes_no"|"text"|"date", required}. `suggestion_rule`
-- is a JSONB array of {when: [{field, op, value}, ...], suggested_status},
-- evaluated top-to-bottom, first match wins, reusing the exact
-- {field, op, value} predicate shape policies/engine/policy_engine.py's
-- condition_matches() already implements against evidence observations -
-- the same evaluation vocabulary, not a second DSL for this table.
-- ===================================================================

CREATE TABLE IF NOT EXISTS compliance_control_checklists (
    control_id       TEXT PRIMARY KEY REFERENCES compliance_controls(id),
    questions        JSONB NOT NULL,
    suggestion_rule  JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===================================================================
-- Stronger sign-off on every assessment, not just checklist-driven ones.
-- attestation_confirmed must be true going forward - the one point this
-- whole feature is actually enforced server-side (see
-- _validate_assessment_payload in nca_routes.py), not just a UI nicety.
-- Historical rows predate this requirement and are backfilled true below
-- (grandfathered, never retroactively invalidated - same precedent as
-- 007-nca-finding-mapping-verdict-hint.sql's own backfill).
-- ===================================================================

ALTER TABLE compliance_assessments
    ADD COLUMN IF NOT EXISTS attested_role TEXT,
    ADD COLUMN IF NOT EXISTS attestation_confirmed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS attestation_statement TEXT;

UPDATE compliance_assessments SET attestation_confirmed = true
    WHERE attestation_confirmed = false;

-- Every row now satisfies this (historical rows backfilled above), so a
-- flat CHECK is safe: it only ever blocks a *new* insert from skipping
-- attestation, matching this table's real shape (an assessment is only
-- ever inserted once fully filled in by RecordAssessmentDialog's submit -
-- there is no partial/draft row state to protect here).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'compliance_assessments_attestation_confirmed_check'
    ) THEN
        ALTER TABLE compliance_assessments
            ADD CONSTRAINT compliance_assessments_attestation_confirmed_check
            CHECK (attestation_confirmed = true);
    END IF;
END $$;
