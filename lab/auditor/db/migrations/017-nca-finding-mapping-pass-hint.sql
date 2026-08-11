-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Allow verdict_hint = 'pass'.
--
-- Migration 007 introduced verdict_hint with CHECK (fail, review_required)
-- because at the time every mapping fired on an insecure condition, so no
-- mapping could ever imply a pass. That is no longer true: a clean signal
-- from a collector that genuinely ran (mqtt_tls == true, default_creds ==
-- false, Telnet not in open_ports) is real positive evidence, and leaving
-- it unrepresentable meant a device with genuinely clean evidence sat at
-- not_tested forever with no suggestion to act on.
--
-- The rule the API applies is deliberately SYMMETRIC WITH FAIL, chosen by
-- the project owner over a stricter alternative: one matching pass-condition
-- mapping is enough to suggest pass for that control, exactly as one
-- matching fail-condition mapping is enough to suggest fail. Precedence
-- still resolves fail > review_required > pass, so a control with both a
-- clean signal on one aspect and a failing signal on another correctly
-- suggests fail - a single real problem outweighs any number of clean
-- checks.
--
-- The known trade-off, recorded here rather than left implicit: a control
-- with several independent fail-mappings (2-4-3 has six - mqtt_tls,
-- plaintext capture, weak_cipher, tls_version, Modbus, UPnP) can suggest
-- pass on the strength of one clean aspect while the other five were never
-- checked. The suggestion therefore carries `checked_aspects`, so the
-- auditor who signs it sees which collectors actually ran rather than the
-- bare word "pass". A suggestion is still never an assessment: a human
-- records it, and the Fully Automated Run deliberately does NOT auto-record
-- a suggested pass (it does auto-record fail/review_required) - a machine
-- may flag a problem unattended, but only a person certifies compliance.
--
-- Additive: no existing row changes: 'fail' remains the column default and
-- every seeded row keeps the hint it already had.
-- ===================================================================

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
        CHECK (verdict_hint IN ('fail', 'review_required', 'pass'));
END $$;
