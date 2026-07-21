-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS firmware_filename TEXT,
    ADD COLUMN IF NOT EXISTS firmware_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS firmware_uploaded_at TIMESTAMPTZ;
