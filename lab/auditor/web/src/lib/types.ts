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
  // Device-scoped but needs no live host/port AND no uploaded firmware -
  // only that the device is registered. See scan_tests.is_device_intel_test().
  | "device-intel"
  | "network-discovery";

// -- Dashboard-overhaul guided pipeline --------------------------------------
// Which of the ordered pipeline phases (see lib/pipeline.ts) a scan test
// belongs to - null for tests that aren't part of any per-device phase (e.g.
// TEST-NET-DISCOVERY, the standalone subnet sweep).
export type PipelinePhaseId =
  | "devices"
  | "fingerprinting"
  | "sa_iot_compliance"
  | "nca_compliance"
  | "vuln_intelligence"
  | "risk_assessment";

// A scan test can only ever belong to one of the phases that are actually
// driven by running a SCAN_CATALOG test - Devices/NCA Compliance/Risk
// Assessment are reached through other mechanisms entirely (registration, a
// separate NCA assessment workspace, live risk computation), never a test_id.
// "pqc_readiness" is deliberately not part of PipelinePhaseId/PIPELINE_PHASES
// (lib/pipeline.ts) - it's a real SCAN_CATALOG-driven phase, but (like
// Remediation/Executive Summary) it's never tracked in a device's
// furthest-reached-phase badge, since it's explicitly informational only and
// never feeds risk_engine.py.
export type ScanTestPipelinePhase =
  | Extract<PipelinePhaseId, "fingerprinting" | "sa_iot_compliance" | "vuln_intelligence">
  | "pqc_readiness";

export interface ScanTestSpec {
  test_id: string;
  label: string;
  category: ScanTestCategory;
  applicable_service_types: ServiceType[];
  pipeline_phase: ScanTestPipelinePhase | null;
}

// -- Network discovery (discovery-first device onboarding) -----------------

export type HostClassification = "iot_device" | "uncertain" | "unknown";

export interface DiscoveredHostService {
  port: number;
  service: string;
  version: string | null;
}

export type MacVendorSource = "ieee_registry" | "nmap_bundled";

export interface DiscoveredHost {
  ip: string;
  hostname: string | null;
  open_ports: number[];
  services: DiscoveredHostService[];
  classification: HostClassification;
  confidence: "high" | "medium" | "low";
  rationale: string;
  mac_address: string | null;
  mac_vendor: string | null;
  mac_vendor_source: MacVendorSource | null;
  discovery_signals: string[];
}

export interface NetworkScanObservations {
  subnets: string[];
  hosts: DiscoveredHost[];
  iot_device_count: number;
  uncertain_count: number;
  unknown_count: number;
  notes: string[];
}

export type NetworkScanStatus = "pending" | "running" | "completed" | "failed";
export type NetworkScanKind = "subnet_sweep" | "interface_detect";

export interface InterfaceDetectCandidate {
  interface: string;
  cidr: string;
}

export interface InterfaceDetectObservations {
  candidates: InterfaceDetectCandidate[];
  excluded_backend_subnet: string | null;
  error?: string;
}

export interface NetworkScan {
  id: number;
  status: NetworkScanStatus;
  tool: string | null;
  tool_version: string | null;
  command: string | null;
  raw_output: string | null;
  // Shape depends on `kind` - a subnet sweep reports NetworkScanObservations,
  // "Detect automatically" (Network Scope) reports InterfaceDetectObservations.
  observations: NetworkScanObservations | InterfaceDetectObservations | null;
  error: string | null;
  kind: NetworkScanKind;
  created_at: string;
  updated_at: string;
}

// Configurable scan-target boundary ("Network Scope") - see
// lab/auditor/api/network_scope_routes.py.
export type NetworkScopeKind = "lab_preset" | "custom";
export type NetworkScopeSource = "manual" | "detected";

export interface NetworkScope {
  id: number;
  label: string;
  cidr: string;
  kind: NetworkScopeKind;
  source: NetworkScopeSource;
  is_active: boolean;
  added_by: string;
  reason: string | null;
  created_at: string;
  deactivated_at: string | null;
  deactivated_by: string | null;
}

export interface DeactivateNetworkScopeResult extends NetworkScope {
  affected_device_count: number;
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
  // Only ever present while status is "awaiting_finding" - a suggestion
  // computed fresh from the real observations, never persisted, never
  // itself recorded as evidence. The auditor still reviews/edits/confirms.
  suggested_finding: string | null;
  suggested_confidence: Confidence | null;
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
  // Present on POST /assessments and GET /assessments/{id}; absent on the
  // GET /assessments list endpoint, which returns assessment summaries only.
  jobs?: ScanJob[];
  // Same availability as jobs - derived live from the assessment's own
  // scan_jobs, empty until job_runner.py actually executes a collector.
  collector_versions?: { tool: string; tool_version: string }[];
}

export type ReportFormat = "pdf" | "html" | "json";

export interface ReportRecord {
  id: string;
  format: ReportFormat;
  generated_at: string;
}

export interface CreateAssessmentResult extends Assessment {
  jobs: ScanJob[];
  errors: Record<string, string>;
}

export type ServiceType =
  | "http"
  | "https"
  | "mqtt"
  | "mqtts"
  | "telnet"
  | "ssh"
  | "modbus"
  | "rtsp"
  | "upnp"
  | "mdns";
export type DeviceTier = "insecure" | "partial" | "hardened" | "unknown";

// Dynamic Risk Assessment (Stage 06) device-level inputs - auditor-set, no
// scan can determine these. See policies/risk/risk_engine.py.
export type RiskCriticality = "low" | "medium" | "high" | "critical";
export type RiskExposure = "none" | "internal_only" | "internet_facing";

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
  /**
   * The version the DEVICE reports about itself (via TEST-DEVICE-ID's read of
   * its /api/device/info endpoint) - not to be confused with the three
   * firmware_* fields above, which describe an archive an auditor uploaded.
   */
  firmware_version: string | null;
  /**
   * Provenance for vendor/model/firmware_version as a set. "auto_detected"
   * means all three were filled in by TEST-DEVICE-ID and no human has edited
   * any of them since - the basis for AutoDetectedIdentityBadge. Never
   * settable through PATCH; editing any of the three resets it to "manual"
   * server-side. `null` only for an orphan device_id that has evidence but no
   * devices row (GET /devices' UNION half), where there is no provenance to
   * report.
   */
  identity_source: "manual" | "auto_detected" | null;
  criticality: RiskCriticality;
  exposure: RiskExposure;
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
    confidence_reason: string | null;
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
  attested_role: string | null;
  attestation_confirmed: boolean;
  attestation_statement: string | null;
  // True only when a Fully Automated Run recorded this row with zero human
  // review - never set by RecordAssessmentDialog's normal human flow, which
  // always defaults false server-side. See automated_run_runner.py.
  auto_recorded: boolean;
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
 * The general shape RecordAssessmentDialog's `suggestion` prop accepts -
 * covers both a device auto-verdict hint (NCADeviceSuggestion, always
 * fail/review_required) and a checklist-derived suggestion (any status,
 * including pass - a checklist genuinely can conclude a guideline is
 * satisfied, unlike scan evidence which never implies a pass on its own).
 */
export interface NCAAssessmentSuggestion {
  control_id: string;
  suggested_status: NCAStatus;
  evidence_ids: string[];
  test_ids: string[];
  reasons: string[];
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
  attested_role?: string | null;
  attestation_confirmed?: boolean;
  attestation_statement?: string | null;
  auto_recorded?: boolean;
}

export interface NCAChecklistQuestion {
  key: string;
  label: string;
  type: "yes_no" | "text" | "date";
  required: boolean;
}

export interface NCACoverage {
  total_guidelines: number;
  automated_or_hybrid_count: number;
  checklist_count: number;
  guided_or_automated_count: number;
}

export interface NCAChecklist {
  control_id: string;
  questions: NCAChecklistQuestion[];
  suggestion_rule: unknown;
}

export interface NCAComplianceEvidence {
  id: string;
  assessment_id: string | null;
  evidence_type: string;
  linked_evidence_id: string | null;
  original_filename: string | null;
  object_reference: string | null;
  sha256: string;
  collected_at: string;
  collected_by: string;
  source_system: string;
  retention_expires_at: string | null;
  access_control_note: string;
  created_at: string;
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

/**
 * The device's own identity as TEST-DEVICE-CVE-LOOKUP saw it, plus whether it
 * resolved to a real NVD CPE. `cpe_matched: false` is an honest gap ("this
 * product isn't in NVD's CPE dictionary"), never a clean bill of health.
 */
export interface VulnDeviceIdentity {
  vendor: string | null;
  model: string | null;
  firmware_version: string | null;
  /** The matched CPE 2.3 "part:vendor:product" prefix, null when unmatched. */
  cpe: string | null;
  cpe_matched: boolean;
}

export interface VulnDeviceSummary {
  device_id: string;
  /**
   * Package-level data only: a TEST-FW-MANIFEST scan has run for this device.
   * Deliberately NOT widened to cover device-level CVEs - report.py,
   * risk_routes.py and lib/pipeline.ts all read it with this narrower meaning.
   */
  has_data: boolean;
  evidence_id: string | null;
  observed_at: string | null;
  packages: VulnPackageAdvisory[];
  total_packages: number;
  outdated_packages: number;
  total_cves: number;
  kev_listed_cves: number;
  highest_cvss: number | null;

  // -- Device-level CVE lookup (no firmware image required) ------------------
  // Independent of everything above: a device may have either source, both, or
  // neither. Sourced from TEST-DEVICE-CVE-LOOKUP evidence, matched against
  // real NVD data by vendor/model CPE at scan time.
  has_device_cve_data: boolean;
  device_cve_evidence_id: string | null;
  device_cve_observed_at: string | null;
  device_identity: VulnDeviceIdentity | null;
  /** Reuses VulnCVE - a device-level CVE has the same shape as a package one. */
  device_cves: VulnCVE[];
  total_device_cves: number;
  kev_listed_device_cves: number;
  highest_device_cvss: number | null;
  /** The collector's own deterministic explanation of what it did or couldn't do. */
  notes?: string[];
}

// -- Dynamic Risk Assessment (IoTGuard Stage 06) -----------------------------
// Sourced from lab/auditor/api/risk_routes.py, which assembles these 7
// inputs by reusing the NCA/vuln-intel/device data every other page already
// reads, then calls policies/risk/risk_engine.py's pure scoring function.

export type RiskCategory = "low" | "medium" | "high" | "critical";

export const RISK_FACTOR_KEYS = [
  "compliance",
  "cvss",
  "exploit_availability",
  "criticality",
  "exposure",
  "violations",
  "insecure_services",
] as const;
export type RiskFactorKey = (typeof RISK_FACTOR_KEYS)[number];

export interface RiskFactorBreakdown {
  raw_value: string | number | boolean | null;
  normalized: number;
  weight: number;
  contribution: number;
}

export interface DeviceRiskRanking {
  device_id: string;
  risk_score: number;
  risk_category: RiskCategory;
  priority_rank: number;
}

export interface RiskDevicesResponse {
  devices: DeviceRiskRanking[];
}

export interface DeviceRiskDetail {
  device_id: string;
  known: boolean;
  risk_score?: number;
  risk_category?: RiskCategory;
  breakdown?: Record<RiskFactorKey, RiskFactorBreakdown>;
}

export interface RiskFleetSummary {
  total_devices: number;
  average_score: number | null;
  by_category: Record<RiskCategory, number>;
}

// -- Fully Automated Run ------------------------------------------------

export type AutomatedRunStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface AutomatedRunSummary {
  hosts_discovered?: number;
  devices_registered?: number;
  tests_run?: number;
  evidence_recorded?: number;
  verdicts_computed?: number;
  /** Package-level (TEST-FW-MANIFEST) - only devices with firmware uploaded. */
  vuln_intel_devices_scanned?: number;
  /** Device-level (TEST-DEVICE-CVE-LOOKUP) - any device with a known vendor+model. */
  device_cve_devices_scanned?: number;
  pqc_devices_scanned?: number;
  nca_assessments_recorded?: number;
  errors?: string[];
}

export interface AutomatedRun {
  id: number;
  status: AutomatedRunStatus;
  device_ids: string[] | null;
  current_stage: string | null;
  summary: AutomatedRunSummary;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

// -- AI-Assisted Remediation (IoTGuard Stage 07) -------------------------

export type RemediationFindingType = "sa_iot_verdict" | "nca_assessment";
export type RemediationPriority = "immediate" | "short_term" | "long_term";

export interface RemediationBlueprint {
  id: string;
  finding_type: RemediationFindingType;
  finding_id: string;
  device_id: string | null;
  control_id: string;
  model: string;
  root_cause: string;
  remediation_steps: string[];
  priority: RemediationPriority;
  estimated_effort: string | null;
  caveats: string | null;
  generated_at: string;
  reviewed: boolean;
  reviewed_by: string | null;
  reviewed_at: string | null;
  superseded_by: string | null;
}

// -- Post-Quantum Readiness (bonus pipeline stage, informational only) ------
// Sourced from lab/auditor/api/pqc_routes.py. Never feeds risk_engine.py or
// any compliance verdict - purely informational, matching every field this
// router returns.

export type PqcCriterionStatus = "pass" | "fail" | "unknown" | "not_applicable";

export interface PqcTlsKeyExchange {
  status: PqcCriterionStatus;
  negotiated_group: string | null;
  tip?: string;
}

export interface PqcCertificateSignature {
  status: PqcCriterionStatus;
  signature_algorithm: string | null;
  tip?: string;
}

export interface PqcFirmwarePackage {
  name: string;
  version: string;
  pqc_status: PqcCriterionStatus;
}

export interface PqcFirmwareCrypto {
  status: PqcCriterionStatus;
  packages: PqcFirmwarePackage[];
  tip?: string;
}

export interface DevicePqcReadiness {
  device_id: string;
  known?: boolean;
  overall_status?: PqcCriterionStatus;
  fail_count?: number;
  tls_key_exchange?: PqcTlsKeyExchange;
  certificate_signature?: PqcCertificateSignature;
  firmware_crypto?: PqcFirmwareCrypto;
}

export interface PqcReadinessDevicesResponse {
  devices: DevicePqcReadiness[];
}

export interface PqcCriterionCounts {
  pass: number;
  fail: number;
  unknown: number;
  not_applicable: number;
}

export interface PqcReadinessFleetSummary {
  total_devices: number;
  tls_key_exchange: PqcCriterionCounts;
  certificate_signature: PqcCriterionCounts;
  firmware_crypto: PqcCriterionCounts;
}

// -- AI Executive Summary (IoTGuard Stage 08) -----------------------------

export interface ExecutiveSummarySaIotGap {
  control_id: string;
  title: string | null;
  severity: Severity;
  status: VerdictStatus;
  reason: string;
  remediation: string | null;
}

export interface ExecutiveSummaryNcaGap {
  control_id: string;
  domain_name: string;
  subdomain_name: string;
  guideline_id: string;
  canonical_requirement: string;
  blocking: boolean;
  status: string;
}

export interface ExecutiveSummaryEvidence {
  evidence_id: string;
  test_id: string;
  tool: string;
  tool_version: string;
  command: string;
  timestamp: string;
  finding: string;
  confidence: Confidence;
  raw_output_path: string;
  sha256: string;
}

export interface ExecutiveSummaryDevice {
  device_id: string;
  display_name: string;
  risk_score: number;
  risk_category: RiskCategory;
  priority_rank: number;
  sa_iot_gaps: ExecutiveSummarySaIotGap[];
  nca_gaps: ExecutiveSummaryNcaGap[];
  evidence: ExecutiveSummaryEvidence[];
  remediation: RemediationBlueprint[];
  /** Informational only - never affects risk_score/risk_category above. */
  pqc_readiness: DevicePqcReadiness;
}

export interface ExecutiveSummaryFleet {
  total_devices: number;
  average_risk_score: number | null;
  risk_by_category: Record<RiskCategory, number>;
  total_compliance_gaps: number;
  remediation_generated: number;
  remediation_reviewed: number;
  remediation_coverage_pct: number | null;
}

export interface ExecutiveSummaryPriorityRecommendation extends RemediationBlueprint {
  device_display_name: string;
}

export interface ExecutiveSummarySignificantGap extends ExecutiveSummaryNcaGap {
  device_id: string;
  device_display_name: string;
}

export interface ExecutiveSummary {
  generated_at: string;
  devices: ExecutiveSummaryDevice[];
  fleet_summary: ExecutiveSummaryFleet;
  priority_recommendations: ExecutiveSummaryPriorityRecommendation[];
  significant_compliance_gaps: ExecutiveSummarySignificantGap[];
  /** Its own section, deliberately separate from fleet_summary - informational
   * only, never affects risk_score or a compliance-gap count. */
  post_quantum_readiness: PqcReadinessFleetSummary;
}
