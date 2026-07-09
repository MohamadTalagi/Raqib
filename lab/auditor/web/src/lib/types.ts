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
