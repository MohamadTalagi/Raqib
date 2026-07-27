-- assessments groups a batch of scan_jobs launched together (e.g. Run Scan's
-- "Run selected") under one id with an aggregate status computed by
-- policies/engine/assessment_status.py - never hand-set beyond queued/cancelled.
-- No FK to devices(device_id): evidence/verdicts already store device_id as a
-- loose reference rather than a FK (deregistering a device must not touch
-- these immutable audit rows), and assessments follows the same precedent.
CREATE TABLE assessments (
    id               TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'running', 'partially_completed', 'completed', 'failed', 'cancelled')),
    policy_version   TEXT,
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    error            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence (
    evidence_id       TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL,
    test_id           TEXT NOT NULL,
    tool              TEXT NOT NULL,
    tool_version      TEXT NOT NULL,
    command           TEXT NOT NULL,
    timestamp         TIMESTAMPTZ NOT NULL,
    finding           TEXT NOT NULL,
    observations      JSONB NOT NULL,
    raw_output_path   TEXT NOT NULL,
    confidence        TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    assessment_id     TEXT REFERENCES assessments(id) ON DELETE SET NULL,
    source_type       TEXT NOT NULL DEFAULT 'automated' CHECK (source_type IN ('automated', 'manual', 'document')),
    confidence_reason TEXT,
    error_state       TEXT
);

CREATE TABLE verdicts (
    verdict_id        TEXT PRIMARY KEY,
    control_id        TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    status            TEXT NOT NULL,
    severity          TEXT NOT NULL,
    evidence_ids      JSONB NOT NULL,
    matched           JSONB,
    reason            TEXT NOT NULL,
    saudi_source      JSONB NOT NULL,
    remediation       TEXT NOT NULL,
    timestamp         TIMESTAMPTZ NOT NULL,
    assessment_id     TEXT REFERENCES assessments(id) ON DELETE SET NULL,
    policy_version    TEXT,
    conflict_detected BOOLEAN NOT NULL DEFAULT false,
    conflict_reason   TEXT
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
    assessment_id    TEXT REFERENCES assessments(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Not tied to any device row on purpose: this is the discovery-first
-- onboarding path (scan the subnet, then register whichever hosts turn out
-- to matter), not a per-device test - see TEST-NET-DISCOVERY in
-- policies/catalog/scan_tests.py for the shared nmap command/parser this
-- reuses.
CREATE TABLE network_scans (
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

CREATE INDEX idx_assessments_device_id ON assessments(device_id);
CREATE INDEX idx_assessments_status ON assessments(status);
CREATE INDEX idx_evidence_device_id ON evidence(device_id);
CREATE INDEX idx_evidence_test_id ON evidence(test_id);
CREATE INDEX idx_evidence_assessment_id ON evidence(assessment_id);
CREATE INDEX idx_verdicts_control_id ON verdicts(control_id);
CREATE INDEX idx_verdicts_device_id ON verdicts(device_id);
CREATE INDEX idx_verdicts_assessment_id ON verdicts(assessment_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_assessment_id ON scan_jobs(assessment_id);

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

-- ===================================================================
-- NCA CGIoT-1:2024 compliance module (additive - the SA-IOT-* controls,
-- evidence, and verdicts tables above are untouched and keep driving the
-- existing Run Scan / verdict pipeline).
-- ===================================================================

CREATE TABLE compliance_controls (
    id                      TEXT PRIMARY KEY,
    framework               TEXT NOT NULL DEFAULT 'NCA-CGIoT',
    framework_version       TEXT NOT NULL DEFAULT '1:2024',
    domain_id               TEXT NOT NULL,
    domain_name             TEXT NOT NULL,
    subdomain_id            TEXT NOT NULL,
    subdomain_name          TEXT NOT NULL,
    guideline_id            TEXT NOT NULL,
    canonical_requirement   TEXT NOT NULL,
    implementation_summary  TEXT NOT NULL,
    source_page             TEXT,
    scope_type              TEXT NOT NULL CHECK (scope_type IN ('organization', 'device', 'mobile', 'supplier', 'cloud')),
    assessment_type         TEXT NOT NULL CHECK (assessment_type IN ('automated', 'manual', 'hybrid')),
    required                BOOLEAN NOT NULL DEFAULT true,
    severity                TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    blocking                BOOLEAN NOT NULL DEFAULT false,
    evidence_requirements   JSONB NOT NULL DEFAULT '[]',
    remediation_guidance    TEXT NOT NULL DEFAULT '',
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (framework, framework_version, guideline_id)
);

CREATE INDEX idx_compliance_controls_domain ON compliance_controls(domain_id);
CREATE INDEX idx_compliance_controls_scope ON compliance_controls(scope_type);

CREATE TABLE compliance_finding_mappings (
    id                      SERIAL PRIMARY KEY,
    finding_key             TEXT NOT NULL,
    description             TEXT NOT NULL,
    control_id              TEXT NOT NULL REFERENCES compliance_controls(id),
    match_rule              JSONB NOT NULL,
    manufacturer_principle  TEXT,
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    -- Suggested verdict when this mapping matches. Every mapping fires on an
    -- insecure condition ('fail'), except a few that only surface evidence
    -- for a manual review ('review_required'). Read by the per-device
    -- assessment workspace's auto-verdict suggestions; see migration 007.
    verdict_hint            TEXT NOT NULL DEFAULT 'fail'
                            CHECK (verdict_hint IN ('fail', 'review_required')),
    UNIQUE (finding_key, control_id)
);

CREATE INDEX idx_compliance_finding_mappings_control_id ON compliance_finding_mappings(control_id);

CREATE TABLE compliance_assessments (
    id                        TEXT PRIMARY KEY,
    control_id                TEXT NOT NULL REFERENCES compliance_controls(id),
    device_id                 TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    organizational_scope_id   TEXT,
    applicability             TEXT NOT NULL CHECK (applicability IN ('applicable', 'not_applicable')),
    applicability_reason      TEXT,
    status                    TEXT NOT NULL CHECK (status IN ('pass', 'partial', 'fail', 'not_tested', 'review_required')),
    severity                  TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    finding                   TEXT,
    test_method               TEXT NOT NULL CHECK (test_method IN ('automated', 'manual', 'hybrid')),
    test_identifier           TEXT,
    raw_result_reference      TEXT,
    evidence_ids              JSONB NOT NULL DEFAULT '[]',
    scanner_tool              TEXT,
    scanner_tool_version      TEXT,
    firmware_version_assessed TEXT,
    assessed_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    assessed_by               TEXT NOT NULL,
    remediation               TEXT,
    remediation_due_date      DATE,
    retest_status             TEXT CHECK (retest_status IN ('not_requested', 'pending', 'passed', 'failed')),
    retested_at               TIMESTAMPTZ,
    superseded_by             TEXT REFERENCES compliance_assessments(id),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (device_id IS NOT NULL AND organizational_scope_id IS NULL)
        OR (device_id IS NULL AND organizational_scope_id IS NOT NULL)
    )
);

CREATE INDEX idx_compliance_assessments_control_id ON compliance_assessments(control_id);
CREATE INDEX idx_compliance_assessments_device_id ON compliance_assessments(device_id);
CREATE INDEX idx_compliance_assessments_org_scope ON compliance_assessments(organizational_scope_id);
CREATE INDEX idx_compliance_assessments_superseded_by ON compliance_assessments(superseded_by);

CREATE TABLE compliance_evidence (
    id                      TEXT PRIMARY KEY,
    assessment_id           TEXT REFERENCES compliance_assessments(id) ON DELETE SET NULL,
    evidence_type           TEXT NOT NULL,
    linked_evidence_id      TEXT REFERENCES evidence(evidence_id),
    original_filename       TEXT,
    object_reference        TEXT,
    sha256                  TEXT NOT NULL,
    collected_at            TIMESTAMPTZ NOT NULL,
    collected_by            TEXT NOT NULL,
    source_system           TEXT NOT NULL DEFAULT 'iotguard',
    retention_expires_at     TIMESTAMPTZ,
    access_control_note     TEXT NOT NULL DEFAULT 'internal-audit-only',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_compliance_evidence_assessment_id ON compliance_evidence(assessment_id);

CREATE TABLE compliance_exceptions (
    id                        TEXT PRIMARY KEY,
    control_id                TEXT NOT NULL REFERENCES compliance_controls(id),
    device_id                 TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    organizational_scope_id   TEXT,
    reason                    TEXT NOT NULL,
    compensating_control      TEXT,
    requested_by              TEXT NOT NULL,
    approved_by               TEXT,
    approved_at               TIMESTAMPTZ,
    status                    TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')) DEFAULT 'pending',
    expires_at                TIMESTAMPTZ NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (device_id IS NOT NULL AND organizational_scope_id IS NULL)
        OR (device_id IS NULL AND organizational_scope_id IS NOT NULL)
    )
);

CREATE INDEX idx_compliance_exceptions_control_id ON compliance_exceptions(control_id);

CREATE TABLE compliance_audit_events (
    id             SERIAL PRIMARY KEY,
    event_type     TEXT NOT NULL,
    entity_type    TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    before_value   JSONB,
    after_value    JSONB,
    actor          TEXT NOT NULL,
    reason         TEXT,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_compliance_audit_events_entity ON compliance_audit_events(entity_type, entity_id);
