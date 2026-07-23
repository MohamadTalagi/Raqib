-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- Discovery-first device onboarding: scan the audit-network subnet and
-- register whichever hosts turn out to matter, instead of typing every
-- field in by hand. Not tied to any device row - see network_scans'
-- own comment in init.sql.
-- ===================================================================

CREATE TABLE IF NOT EXISTS network_scans (
    id               SERIAL PRIMARY KEY,
    status           TEXT NOT NULL DEFAULT 'pending',
    tool             TEXT,
    tool_version     TEXT,
    command          TEXT,
    raw_output       TEXT,
    observations     JSONB,
    error            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
