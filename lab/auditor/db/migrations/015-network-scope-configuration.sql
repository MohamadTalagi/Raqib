-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Configurable scan-target boundary ("Network Scope"). Replaces the
-- previously hardcoded 172.30.0.0/24 constant (device_validation.ALLOWED_NETWORK,
-- scan_tests.AUDIT_NETWORK_CIDR) with a real, user-editable allowlist -
-- both modules stay DB-free on purpose (see device_validation.py's own
-- module docstring) and are reconfigured in-process from this table by
-- auditor-api (directly) and auditor-worker (via periodic HTTP poll, since
-- the worker has no direct DB access).
--
-- Never hard-deleted, matching every other append-only table in this
-- project (compliance_assessments, remediation_blueprints, ...):
-- deactivating a scope sets is_active = false plus deactivated_at/by,
-- which *is* the audit trail for who removed a range and why - no separate
-- audit-event table needed.
--
-- The lab's own 172.30.0.0/24 stays seeded as an explicit, named,
-- always-visible preset (kind = 'lab_preset') rather than disappearing -
-- it can be deactivated/reactivated like any other row, just never
-- hard-deleted, so "go back to lab-only scanning" is always one click away.
-- ===================================================================

CREATE TABLE IF NOT EXISTS network_scopes (
    id              SERIAL PRIMARY KEY,
    label           TEXT NOT NULL,
    cidr            TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'custom' CHECK (kind IN ('lab_preset', 'custom')),
    source          TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'detected')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    added_by        TEXT NOT NULL,
    reason          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at  TIMESTAMPTZ,
    deactivated_by  TEXT
);

-- A CIDR can be re-added after being deactivated (reactivate the existing
-- row), but never duplicated while active.
CREATE UNIQUE INDEX IF NOT EXISTS network_scopes_active_cidr_idx
    ON network_scopes (cidr) WHERE is_active;

INSERT INTO network_scopes (label, cidr, kind, source, is_active, added_by)
VALUES ('Lab environment (Docker audit-network)', '172.30.0.0/24', 'lab_preset', 'manual', true, 'system:migration')
ON CONFLICT (cidr) WHERE is_active DO NOTHING;

-- Lets the async network_scans job table (previously only ever a subnet
-- sweep) also carry a one-shot "inspect the worker's own network
-- interfaces and suggest candidate subnets" job, reusing the exact same
-- pending/running/completed machinery and the same `observations` column
-- rather than a second table.
ALTER TABLE network_scans ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'subnet_sweep'
    CHECK (kind IN ('subnet_sweep', 'interface_detect'));
