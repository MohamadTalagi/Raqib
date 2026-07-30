export type Confidence = "high" | "medium" | "low";

export type SourceType = "automated" | "manual" | "document";

export interface EvidenceRecord {
  evidence_id: string;
  device_id: string;
  test_id: string;
  tool: string;
  tool_version: string;
  command: string;
  timestamp: string;
  finding: string;
  observations: Record<string, unknown>;
  raw_output_path: string;
  confidence: Confidence;
  sha256: string;
  assessment_id: string | null;
  source_type: SourceType;
  confidence_reason: string | null;
  error_state: string | null;
}

export type VerdictStatus = "PASS" | "FAIL" | "PARTIAL" | "INCONCLUSIVE" | "NOT_APPLICABLE";
export type Severity = "low" | "medium" | "high" | "critical";

export interface VerdictRecord {
  verdict_id: string;
  control_id: string;
  device_id: string;
  status: VerdictStatus;
  severity: Severity;
  evidence_ids: string[];
  matched: string;
  reason: string;
  saudi_source: string;
  remediation: string;
  timestamp: string;
  assessment_id: string | null;
  policy_version: string | null;
  conflict_detected: boolean;
  conflict_reason: string | null;
}

export interface SaudiSourceRef {
  framework: string;
  reference: string;
  clause: string;
}

export interface ControlRecord {
  control_id: string;
  title: string;
  saudi_source: SaudiSourceRef[];
  applicability: { device_type: string[] };
  required_evidence: { test_id: string }[];
  automated_test_ids: string[];
  severity: Severity;
  conditions: Record<string, unknown>;
  remediation: string;
}

export interface DeviceSummary {
  device_id: string;
  evidence_count: number;
  verdict_count: number;
}

export interface ComplianceReport {
  framework: string;
  tested_controls: number;
  passing_controls: number;
  percentage: number | null;
}

export interface DeviceComplianceReport extends ComplianceReport {
  device_id: string;
}

export interface Summary {
  total_evidence: number;
  total_verdicts: number;
  verdicts_by_status: Record<VerdictStatus, number>;
  device_compliance: DeviceComplianceReport[];
}

export type ScanTestCategory =
  | "web-and-auth"
  | "network-and-protocol"
  | "firmware"
  | "network-discovery";

export interface ScanTestSpec {
  test_id: string;
  label: string;
  category: ScanTestCategory;
  applicable_service_types: ServiceType[];
}

// -- Network discovery (discovery-first device onboarding) -----------------

export type HostClassification = "iot_device" | "uncertain" | "unknown";

export interface DiscoveredHostService {
  port: number;
  service: string;
  version: string | null;
}

export interface DiscoveredHost {
  ip: string;
  hostname: string | null;
  open_ports: number[];
  services: DiscoveredHostService[];
  classification: HostClassification;
  confidence: "high" | "low";
  rationale: string;
}

export interface NetworkScanObservations {
  subnet: string;
  hosts: DiscoveredHost[];
  iot_device_count: number;
  uncertain_count: number;
  unknown_count: number;
  notes: string[];
}

export type NetworkScanStatus = "pending" | "running" | "completed" | "failed";

export interface NetworkScan {
  id: number;
  status: NetworkScanStatus;
  tool: string | null;
  tool_version: string | null;
  command: string | null;
  raw_output: string | null;
  observations: NetworkScanObservations | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export type ScanJobStatus = "pending" | "running" | "awaiting_finding" | "recorded" | "failed";

export interface ScanJob {
  id: number;
  device_id: string;
  test_id: string;
  status: ScanJobStatus;
  tool: string | null;
  tool_version: string | null;
  command: string | null;
  raw_output: string | null;
  observations: Record<string, unknown> | null;
  error: string | null;
  evidence_id: string | null;
  assessment_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface RecomputeVerdictsResult {
  created: number;
  verdicts: VerdictRecord[];
}

export type AssessmentStatus =
  | "queued"
  | "running"
  | "partially_completed"
  | "completed"
  | "failed"
  | "cancelled";

export interface Assessment {
  id: string;
  device_id: string;
  status: AssessmentStatus;
  policy_version: string | null;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  created_at: string;
  jobs: ScanJob[];
}

export interface CreateAssessmentResult extends Assessment {
  errors: Record<string, string>;
}

export type ServiceType = "http" | "https" | "mqtt" | "mqtts" | "telnet" | "ssh";
export type DeviceTier = "insecure" | "partial" | "hardened" | "unknown";

export interface DeviceService {
  id: number;
  service_type: ServiceType;
  port: number;
  published_port: number | null;
  enabled: boolean;
}

/**
 * Fields present in EVERY device object the API returns, regardless of which
 * endpoint produced it. Verified against `lab/auditor/api/main.py`:
 *   - GET  /devices             (list, get_devices)       — full row incl. registered/counts/services
 *   - POST /devices             (create_device)           — no evidence_count/verdict_count
 *   - PATCH /devices/{id}       (update_device, via _device_row) — no registered/evidence_count/verdict_count
 *   - GET  /devices/{id}        (.device, via _device_row) — no registered/counts/services
 *   - POST/DELETE .../firmware  (via _device_row)          — no registered/evidence_count/verdict_count
 * Only the fields common to all endpoints live here; endpoint-specific
 * extras are added by the narrower types below instead of being declared
 * (and lied about) on every device object.
 */
export interface DeviceBase {
  device_id: string;
  display_name: string;
  description: string;
  tier: DeviceTier;
  host: string | null;
  vendor: string | null;
  model: string | null;
  location: string | null;
  owner: string | null;
  notes: string | null;
  source: "seeded" | "manual" | null;
  firmware_filename: string | null;
  firmware_sha256: string | null;
  firmware_uploaded_at: string | null;
}

/**
 * Shape returned by GET /devices — the only endpoint that includes
 * registration status and the evidence/verdict counts. This is the type the
 * Devices list page consumes.
 */
export interface Device extends DeviceBase {
  registered: boolean;
  evidence_count: number;
  verdict_count: number;
  services: DeviceService[];
}

/**
 * Shape returned by POST /devices and PATCH /devices/{id}: the created/
 * updated record with its services, but never the list-only evidence/verdict
 * counts. `registered` is optional (not `| undefined` in a union) because
 * POST's response always includes it (`true`) while PATCH's response omits
 * the field entirely — an optional property models both truthfully.
 */
export interface DeviceMutationResult extends DeviceBase {
  services: DeviceService[];
  registered?: boolean;
}

export interface DeviceDetail {
  device: DeviceBase;
  services: DeviceService[];
  evidence: Array<{
    evidence_id: string;
    test_id: string;
    tool: string;
    finding: string;
    confidence: string;
    timestamp: string;
  }>;
  verdicts: Array<{
    verdict_id: string;
    control_id: string;
    status: string;
    severity: string;
    reason: string;
    timestamp: string;
  }>;
  scan_jobs: Array<{
    id: number;
    test_id: string;
    status: string;
    created_at: string;
  }>;
  compliance: ComplianceReport;
}

export interface ControlVerdictRollup {
  control_id: string;
  verdicts: Array<{
    verdict_id: string;
    device_id: string;
    status: string;
    severity: string;
    reason: string;
    timestamp: string;
  }>;
  counts: { PASS: number; FAIL: number; PARTIAL: number; INCONCLUSIVE: number };
}

export interface ApiFieldError {
  field: string;
  detail: string;
}

// ---------------------------------------------------------------------------
// NCA CGIoT-1:2024 compliance module
// ---------------------------------------------------------------------------

export type NCAStatus = "pass" | "partial" | "fail" | "not_tested" | "review_required";
export type NCAReadinessClassification = "passed" | "partially_passed" | "failed";
export type NCAScopeType = "organization" | "device" | "mobile" | "supplier" | "cloud";
export type NCAAssessmentType = "automated" | "manual" | "hybrid";
export type NCAApplicability = "applicable" | "not_applicable";
export type NCARetestStatus = "not_requested" | "pending" | "passed" | "failed" | null;

export interface NCAControl {
  id: string;
  framework: string;
  framework_version: string;
  domain_id: string;
  domain_name: string;
  subdomain_id: string;
  subdomain_name: string;
  guideline_id: string;
  canonical_requirement: string;
  implementation_summary: string;
  source_page: string | null;
  scope_type: NCAScopeType;
  assessment_type: NCAAssessmentType;
  required: boolean;
  severity: Severity;
  blocking: boolean;
  evidence_requirements: unknown[];
  remediation_guidance: string;
  enabled: boolean;
}

export interface NCAAssessment {
  id: string;
  control_id: string;
  device_id: string | null;
  organizational_scope_id: string | null;
  applicability: NCAApplicability;
  applicability_reason: string | null;
  status: NCAStatus;
  severity: Severity;
  finding: string | null;
  test_method: NCAAssessmentType;
  test_identifier: string | null;
  raw_result_reference: string | null;
  evidence_ids: string[];
  scanner_tool: string | null;
  scanner_tool_version: string | null;
  firmware_version_assessed: string | null;
  assessed_at: string;
  assessed_by: string;
  remediation: string | null;
  remediation_due_date: string | null;
  retest_status: NCARetestStatus;
  retested_at: string | null;
  superseded_by: string | null;
  created_at: string;
}

export interface NCAException {
  id: string;
  control_id: string;
  device_id: string | null;
  organizational_scope_id: string | null;
  reason: string;
  compensating_control: string | null;
  requested_by: string;
  approved_by: string | null;
  approved_at: string | null;
  status: "pending" | "approved" | "rejected" | "expired";
  expires_at: string;
  created_at: string;
}

export interface NCADomainCounts {
  pass: number;
  partial: number;
  fail: number;
  not_tested: number;
  review_required: number;
}

export type NCADomainSummary = Record<string, NCADomainCounts>;

export interface NCASummary {
  product_label: string;
  framework: string;
  framework_version: string;
  disclaimer: string;
  total_devices: number;
  device_counts: NCADomainCounts;
  overall_pass_percentage: number | null;
  total_controls: number;
  last_assessment_at: string | null;
  status_definitions?: Record<string, string>;
  readiness_definitions?: Record<NCAReadinessClassification, string>;
}

export interface NCADeviceComplianceRow {
  device_id: string;
  display_name: string;
  tier: DeviceTier;
  vendor: string | null;
  model: string | null;
  overall_status: NCAStatus;
  score: number | null;
  domain_summary: NCADomainSummary;
  readiness_classification: NCAReadinessClassification;
}

/**
 * The Passed/Partially Passed/Failed compliance-readiness verdict computed
 * by policies/nca/evaluator.py::overall_classification - additive to (never
 * replacing) overall_status/score above. Never rely on `score` alone to
 * render this: `reasons` explains exactly why, and a blocking condition or
 * critical failure can force `failed`/`partially_passed` even at a high
 * score.
 */
export interface NCAReadiness {
  classification: NCAReadinessClassification;
  score: number | null;
  reasons: string[];
  blocking_control_ids: string[];
  critical_failure_control_ids: string[];
  not_tested_control_ids: string[];
  review_required_control_ids: string[];
  pass_threshold: number;
  partial_threshold: number;
}

export interface NCADeviceControlRow {
  control: NCAControl;
  assessment: NCAAssessment | null;
}

export interface NCADeviceDetail {
  device_id: string;
  display_name: string;
  tier: DeviceTier;
  overall_status: NCAStatus;
  score: number | null;
  domain_summary: NCADomainSummary;
  readiness: NCAReadiness;
  controls: NCADeviceControlRow[];
  exceptions: NCAException[];
}

/**
 * Auto-verdict hint for one control, from GET /nca/devices/{id}/suggestions.
 * Emitted only when a finding mapping matched real automated evidence for
 * this device - it suggests a status the auditor confirms or overrides. The
 * absence of a suggestion never implies a pass (a test may not have run).
 */
export interface NCADeviceSuggestion {
  control_id: string;
  suggested_status: Extract<NCAStatus, "fail" | "review_required">;
  evidence_ids: string[];
  test_ids: string[];
  reasons: string[];
}

export interface NCADeviceSuggestions {
  device_id: string;
  suggestions: Record<string, NCADeviceSuggestion>;
}

export interface NCAControlDetail {
  control: NCAControl;
  assessments: NCAAssessment[];
  audit_events: Array<{
    id: number;
    event_type: string;
    entity_type: string;
    entity_id: string;
    before_value: unknown;
    after_value: unknown;
    actor: string;
    reason: string | null;
    occurred_at: string;
  }>;
}

export interface NCAOrganizationalCompliance {
  organizational_scope_id: string;
  overall_status: NCAStatus;
  score: number | null;
  domain_summary: NCADomainSummary;
  readiness: NCAReadiness;
  controls: NCADeviceControlRow[];
}

export interface CreateNCAAssessmentPayload {
  control_id: string;
  device_id?: string | null;
  organizational_scope_id?: string | null;
  applicability?: NCAApplicability;
  applicability_reason?: string | null;
  status: NCAStatus;
  severity: Severity;
  finding?: string | null;
  test_method: NCAAssessmentType;
  test_identifier?: string | null;
  raw_result_reference?: string | null;
  evidence_ids?: string[];
  scanner_tool?: string | null;
  scanner_tool_version?: string | null;
  firmware_version_assessed?: string | null;
  assessed_by: string;
  remediation?: string | null;
  remediation_due_date?: string | null;
  reason?: string;
}

export interface OverrideNCAAssessmentPayload {
  status: NCAStatus;
  justification: string;
  overridden_by: string;
  original_status?: NCAStatus;
  remediation?: string | null;
}

export interface CreateNCAExceptionPayload {
  control_id: string;
  device_id?: string | null;
  organizational_scope_id?: string | null;
  reason: string;
  compensating_control?: string | null;
  requested_by: string;
  expires_at: string;
}

// -- Vulnerability intelligence (IoTGuard Stage 05) -------------------------
// Sourced from evidence.observations recorded by the worker's Grype/CISA-KEV
// -backed TEST-FW-MANIFEST collector - see lab/auditor/api/vuln_routes.py.

export interface VulnCVE {
  id: string;
  cvss: number | null;
  summary: string;
  kev_listed: boolean;
  kev_date_added: string | null;
}

export interface VulnPackageAdvisory {
  name: string;
  version: string;
  outdated: boolean | null;
  eol: boolean | null;
  latest_known_version: string | null;
  official_patch_available: boolean | null;
  patched_version: string | null;
  // null means "not cross-referenced against KEV here" (e.g. the static
  // reference-table fallback) - never a guessed 0. See vuln_routes.py.
  kev_listed_count: number | null;
  cves: VulnCVE[];
  notes: string[];
}

export interface VulnIntelStatus {
  known: boolean;
  vuln_db_built_at: string | null;
  vuln_db_checksum: string | null;
  observed_at: string | null;
  observed_from_evidence_id: string | null;
  observed_from_device_id: string | null;
}

export interface VulnDeviceRollup {
  device_id: string;
  observed_at: string;
  total_packages: number;
  outdated_packages: number;
  total_cves: number;
  kev_listed_cves: number;
  highest_cvss: number | null;
}

export interface VulnFleetSummary {
  devices: VulnDeviceRollup[];
  total_cves: number;
  total_kev_listed_cves: number;
}

export interface VulnDeviceSummary {
  device_id: string;
  has_data: boolean;
  evidence_id: string | null;
  observed_at: string | null;
  packages: VulnPackageAdvisory[];
  total_packages: number;
  outdated_packages: number;
  total_cves: number;
  kev_listed_cves: number;
  highest_cvss: number | null;
}
