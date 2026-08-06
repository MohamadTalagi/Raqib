-- Device identity auto-detection (TEST-DEVICE-ID).
--
-- devices.vendor/model have been 100% self-reported since Day 1 - a human
-- types them at registration or via PATCH. TEST-DEVICE-ID finally gives them
-- an automated source (a device's own unauthenticated GET /api/device/info),
-- which needs two new columns:
--
--   firmware_version  the device's self-reported firmware string. Distinct
--                     from the existing firmware_filename/firmware_sha256/
--                     firmware_uploaded_at trio, which is upload metadata for
--                     an archive an auditor supplied - not a version the
--                     device itself claims to be running.
--
--   identity_source   provenance for vendor/model/firmware_version as a set.
--                     'auto_detected' means every one of the three was filled
--                     in by the auto-populate hook in record_scan_job_evidence
--                     and no human has since edited any of them; the dashboard
--                     shows an "auto-detected, not auditor-verified" badge on
--                     that basis. Deliberately NOT in PATCHABLE_DEVICE_FIELDS:
--                     it is only ever system-set, or the badge becomes
--                     lie-able. Editing any of the three fields through PATCH
--                     flips it back to 'manual' in the same statement.
--
-- Idempotent, same as every prior migration in this directory. Mirrored into
-- init.sql's devices DDL for fresh volumes.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS firmware_version TEXT;

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS identity_source TEXT NOT NULL DEFAULT 'manual'
        CHECK (identity_source IN ('manual', 'auto_detected'));
