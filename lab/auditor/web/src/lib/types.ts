export type Confidence = "high" | "medium" | "low";

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
}

export type VerdictStatus = "PASS" | "FAIL" | "PARTIAL" | "INCONCLUSIVE";
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

export interface Summary {
  total_evidence: number;
  total_verdicts: number;
  verdicts_by_status: Record<VerdictStatus, number>;
}

export type ScanTestCategory = "web-and-auth" | "network-and-protocol" | "firmware";

export interface ScanTestSpec {
  test_id: string;
  label: string;
  category: ScanTestCategory;
  applicable_service_types: ServiceType[];
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
  created_at: string;
  updated_at: string;
}

export interface RecomputeVerdictsResult {
  created: number;
  verdicts: VerdictRecord[];
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
