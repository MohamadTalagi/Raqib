-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Week 1 gap-closure: the brief's storage list names "Report records" as
-- its own stored entity. Report *content* is deliberately never persisted
-- (it's always assembled fresh from live DB state by report.py's
-- build_report_model - the same "never cache a derived computation" rule
-- this codebase already applies to risk scores, compliance percentages,
-- and NCA domain summaries, so a stored report could never silently
-- disagree with the real, current data). What genuinely needs storing is
-- the append-only fact that a report was generated - an audit trail
-- directly analogous to the existing compliance_audit_events table, not a
-- snapshot of what the report said.
-- ===================================================================

CREATE TABLE IF NOT EXISTS report_records (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    format       TEXT NOT NULL CHECK (format IN ('pdf', 'html', 'json')),
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_report_records_device_id ON report_records(device_id);
