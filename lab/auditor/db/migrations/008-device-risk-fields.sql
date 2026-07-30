-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Dynamic Risk Assessment (IoTGuard Stage 06): two new device-level inputs
-- to the risk-scoring engine (policies/risk/risk_engine.py) that no scan
-- can determine on its own - a device's business criticality and whether
-- it's reachable from the internet. Auditor-set, with a sensible computed
-- default applied at registration time (see main.py's create_device) so a
-- device's risk score is never blocked pending manual data entry, but
-- always reviewable/overridable via the existing PATCH /devices/{id}.
-- Existing rows simply pick up these DEFAULTs - an honest, neutral
-- starting point, never a fabricated per-device guess.
-- ===================================================================

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS criticality TEXT NOT NULL DEFAULT 'medium'
        CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN IF NOT EXISTS exposure TEXT NOT NULL DEFAULT 'internal_only'
        CHECK (exposure IN ('none', 'internal_only', 'internet_facing'));
