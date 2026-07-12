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
