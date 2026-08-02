-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- AI-Assisted Remediation (IoTGuard Stage 07). One row per generated
-- blueprint, append-only exactly like compliance_assessments - a
-- re-generate for the same finding supersedes the prior row rather than
-- overwriting it, so a prior AI response is never silently lost.
--
-- finding_type/finding_id are deliberately polymorphic (no FK): a finding
-- is either a `verdicts.verdict_id` (SA-IOT pilot) or a
-- `compliance_assessments.id` (NCA CGIoT-1:2024) - two different tables,
-- so a single real foreign key can't span both. control_id is likewise
-- unconstrained (an SA-IOT control_id or an NCA guideline id).
--
-- Never treated as authoritative until a human reviews it (reviewed/
-- reviewed_by/reviewed_at - same free-text reviewer-identity convention as
-- compliance_exceptions, this app has no login system to build real auth
-- for). Purely additive display: it never mutates verdicts.remediation or
-- compliance_assessments.remediation, so neither of those append-only
-- tables needed any change.
-- ===================================================================

CREATE TABLE IF NOT EXISTS remediation_blueprints (
    id                 TEXT PRIMARY KEY,
    finding_type       TEXT NOT NULL CHECK (finding_type IN ('sa_iot_verdict', 'nca_assessment')),
    finding_id         TEXT NOT NULL,
    device_id          TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    control_id         TEXT NOT NULL,
    model              TEXT NOT NULL,
    root_cause         TEXT NOT NULL,
    remediation_steps  JSONB NOT NULL,
    priority           TEXT NOT NULL CHECK (priority IN ('immediate', 'short_term', 'long_term')),
    estimated_effort   TEXT,
    caveats            TEXT,
    generated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed           BOOLEAN NOT NULL DEFAULT false,
    reviewed_by        TEXT,
    reviewed_at        TIMESTAMPTZ,
    superseded_by      TEXT REFERENCES remediation_blueprints(id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_blueprints_finding
    ON remediation_blueprints (finding_type, finding_id);
