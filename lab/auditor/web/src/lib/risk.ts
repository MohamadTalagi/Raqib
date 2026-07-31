import type { RiskFactorKey } from "@/lib/types";

/** Human-readable labels for the risk-scoring engine's 7 inputs (see
 * policies/risk/risk_engine.py) - shared between RiskAssessmentPage and
 * DeviceAssessmentReportPage so the two surfaces never drift out of sync. */
export const RISK_FACTOR_LABELS: Record<RiskFactorKey, string> = {
  compliance: "Compliance (NCA CGIoT-1:2024)",
  cvss: "Highest CVSS",
  exploit_availability: "Exploit availability (CISA KEV)",
  criticality: "Device criticality",
  exposure: "Internet exposure",
  violations: "Violation count (SA-IOT + NCA combined)",
  insecure_services: "Insecure service count",
};

export function formatRiskRawValue(value: string | number | boolean | null): string {
  if (value === null) return "no data";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}
