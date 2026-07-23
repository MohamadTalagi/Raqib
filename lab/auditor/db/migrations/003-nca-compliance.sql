-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.

-- ===================================================================
-- NCA CGIoT-1:2024 compliance module (additive - the SA-IOT-* controls,
-- evidence, and verdicts tables above are untouched and keep driving the
-- existing Run Scan / verdict pipeline).
-- ===================================================================

CREATE TABLE IF NOT EXISTS compliance_controls (
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
    evidence_requirements   JSONB NOT NULL DEFAULT '[]',
    remediation_guidance    TEXT NOT NULL DEFAULT '',
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (framework, framework_version, guideline_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_controls_domain ON compliance_controls(domain_id);
CREATE INDEX IF NOT EXISTS idx_compliance_controls_scope ON compliance_controls(scope_type);

CREATE TABLE IF NOT EXISTS compliance_finding_mappings (
    id                      SERIAL PRIMARY KEY,
    finding_key             TEXT NOT NULL,
    description             TEXT NOT NULL,
    control_id              TEXT NOT NULL REFERENCES compliance_controls(id),
    match_rule              JSONB NOT NULL,
    manufacturer_principle  TEXT,
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (finding_key, control_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_finding_mappings_control_id ON compliance_finding_mappings(control_id);

CREATE TABLE IF NOT EXISTS compliance_assessments (
    id                        TEXT PRIMARY KEY,
    control_id                TEXT NOT NULL REFERENCES compliance_controls(id),
    device_id                 TEXT REFERENCES devices(device_id) ON DELETE SET NULL,
    organizational_scope_id   TEXT,
    applicability             TEXT NOT NULL CHECK (applicability IN ('applicable', 'not_applicable')),
    applicability_reason      TEXT,
    status                    TEXT NOT NULL CHECK (status IN ('pass', 'partial', 'fail', 'not_tested')),
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

CREATE INDEX IF NOT EXISTS idx_compliance_assessments_control_id ON compliance_assessments(control_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_device_id ON compliance_assessments(device_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_org_scope ON compliance_assessments(organizational_scope_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_superseded_by ON compliance_assessments(superseded_by);

CREATE TABLE IF NOT EXISTS compliance_evidence (
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

CREATE INDEX IF NOT EXISTS idx_compliance_evidence_assessment_id ON compliance_evidence(assessment_id);

CREATE TABLE IF NOT EXISTS compliance_exceptions (
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

CREATE INDEX IF NOT EXISTS idx_compliance_exceptions_control_id ON compliance_exceptions(control_id);

CREATE TABLE IF NOT EXISTS compliance_audit_events (
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

CREATE INDEX IF NOT EXISTS idx_compliance_audit_events_entity ON compliance_audit_events(entity_type, entity_id);
