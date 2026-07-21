CREATE TABLE evidence (
    evidence_id      TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    test_id          TEXT NOT NULL,
    tool             TEXT NOT NULL,
    tool_version     TEXT NOT NULL,
    command          TEXT NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL,
    finding          TEXT NOT NULL,
    observations     JSONB NOT NULL,
    raw_output_path  TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    sha256           TEXT NOT NULL
);

CREATE TABLE verdicts (
    verdict_id       TEXT PRIMARY KEY,
    control_id       TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    status           TEXT NOT NULL,
    severity         TEXT NOT NULL,
    evidence_ids     JSONB NOT NULL,
    matched          JSONB,
    reason           TEXT NOT NULL,
    saudi_source     JSONB NOT NULL,
    remediation      TEXT NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL
);

CREATE TABLE scan_jobs (
    id               SERIAL PRIMARY KEY,
    device_id        TEXT NOT NULL,
    test_id          TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    tool             TEXT,
    tool_version     TEXT,
    command          TEXT,
    raw_output       TEXT,
    observations     JSONB,
    error            TEXT,
    evidence_id      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidence_device_id ON evidence(device_id);
CREATE INDEX idx_evidence_test_id ON evidence(test_id);
CREATE INDEX idx_verdicts_control_id ON verdicts(control_id);
CREATE INDEX idx_verdicts_device_id ON verdicts(device_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);

CREATE TABLE devices (
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
    firmware_filename     TEXT,
    firmware_sha256       TEXT,
    firmware_uploaded_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_services (
    id               SERIAL PRIMARY KEY,
    device_id        TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    service_type     TEXT NOT NULL CHECK (service_type IN ('http', 'https', 'mqtt', 'mqtts', 'telnet', 'ssh')),
    port             INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    published_port   INTEGER CHECK (published_port BETWEEN 1 AND 65535),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (device_id, service_type, port)
);

CREATE INDEX idx_device_services_device_id ON device_services(device_id);
