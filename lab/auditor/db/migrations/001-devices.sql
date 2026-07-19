-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    tier             TEXT NOT NULL CHECK (tier IN ('insecure', 'partial', 'hardened', 'unknown')),
    host             TEXT NOT NULL,
    vendor           TEXT,
    model            TEXT,
    location         TEXT,
    owner            TEXT,
    notes            TEXT,
    source           TEXT NOT NULL CHECK (source IN ('seeded', 'manual')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_services (
    id               SERIAL PRIMARY KEY,
    device_id        TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    service_type     TEXT NOT NULL CHECK (service_type IN ('http', 'https', 'mqtt', 'mqtts', 'telnet', 'ssh')),
    port             INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    published_port   INTEGER CHECK (published_port BETWEEN 1 AND 65535),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (device_id, service_type, port)
);

CREATE INDEX IF NOT EXISTS idx_device_services_device_id ON device_services(device_id);
