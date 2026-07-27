-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Auto-verdict support for the per-device assessment workspace.
-- A finding mapping already links a piece of automated scan evidence to
-- the NCA control it is relevant to (compliance_finding_mappings). Every
-- existing mapping fires precisely when an *insecure* condition is present
-- (default_creds == true, mqtt_tls == false, Telnet open, weak_cipher ==
-- true, ...), so a match cleanly implies a suggested FAIL. A small set of
-- mappings instead only surface "relevant evidence for a manual review"
-- (an update script / component manifest is present, a Server banner
-- discloses a framework) - those cannot imply pass or fail on their own.
--
-- verdict_hint makes that polarity explicit and configurable in the same
-- table, rather than hardcoding a list of finding_keys in the API. The
-- GET /nca/devices/{id}/suggestions endpoint reads it to pre-fill a
-- suggested status the auditor confirms or overrides - the verdict is
-- still recorded by a human ("AI-assisted, not AI-decided"). Absence of a
-- matching mapping never implies a pass: a test may simply not have run.
--
-- Additive: the 'fail' default preserves every existing row's meaning.
-- ===================================================================

ALTER TABLE compliance_finding_mappings
    ADD COLUMN IF NOT EXISTS verdict_hint TEXT NOT NULL DEFAULT 'fail';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'compliance_finding_mappings_verdict_hint_check'
    ) THEN
        ALTER TABLE compliance_finding_mappings
            DROP CONSTRAINT compliance_finding_mappings_verdict_hint_check;
    END IF;
    ALTER TABLE compliance_finding_mappings
        ADD CONSTRAINT compliance_finding_mappings_verdict_hint_check
        CHECK (verdict_hint IN ('fail', 'review_required'));
END $$;

-- The three mappings that only surface evidence for manual review, not a
-- failing condition (see seed_finding_mappings.py). Keyed by finding_key,
-- which is stable and unique per finding.
UPDATE compliance_finding_mappings
    SET verdict_hint = 'review_required'
    WHERE finding_key IN (
        'firmware-update-script-present',
        'firmware-manifest-present',
        'http-banner-discloses-framework'
    );
