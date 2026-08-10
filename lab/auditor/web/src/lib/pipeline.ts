import type {
  DeviceRiskDetail,
  NCADeviceDetail,
  PipelinePhaseId,
  ScanTestSpec,
  VulnDeviceSummary,
} from "./types";

export interface PipelinePhaseDef {
  id: PipelinePhaseId;
  label: string;
}

/**
 * The single source of truth for pipeline order - drives both the sidebar's
 * top-to-bottom grouping and every phase-status badge. Devices is always
 * "reached" once a device is registered; Discovery isn't listed here since
 * it's a pre-registration, fleet-wide activity with no per-device status of
 * its own (see the Discovery page).
 */
export const PIPELINE_PHASES: PipelinePhaseDef[] = [
  { id: "devices", label: "Devices" },
  { id: "fingerprinting", label: "Fingerprinting" },
  { id: "sa_iot_compliance", label: "SA-IOT Compliance" },
  { id: "nca_compliance", label: "NCA Compliance" },
  { id: "vuln_intelligence", label: "Vulnerability Intelligence" },
  { id: "risk_assessment", label: "Risk Assessment" },
];

/**
 * Per-device inputs to devicePipelineStatus() - deliberately pre-scoped to
 * one device by the caller (a device's own evidence/verdicts arrays, its own
 * NCA/vuln/risk detail), not raw fleet-wide tables this function would have
 * to filter itself. Every page that needs this already fetches all of these
 * for other reasons (Device Detail, the new phase pages) - nothing new to
 * fetch just for status computation.
 */
export interface DevicePipelineData {
  /** This device's own evidence records (only .test_id is used). */
  evidenceTestIds: string[];
  /** True once this device has at least one recorded SA-IOT verdict. */
  hasSaIotVerdict: boolean;
  /** The full scan test catalog, used to classify evidenceTestIds by phase. */
  scanTests: ScanTestSpec[];
  nca: NCADeviceDetail | null;
  vuln: VulnDeviceSummary | null;
  risk: DeviceRiskDetail | null;
}

export type PipelinePhaseStatus = Record<PipelinePhaseId, boolean>;

/**
 * Computed live from whatever data already exists - never a stored "current
 * phase" pointer. Matches this project's own rule elsewhere (risk score,
 * compliance %, collector_versions): a device that gets re-scanned looks
 * current again everywhere at once, with no explicit "reset" action needed.
 */
export function devicePipelineStatus(data: DevicePipelineData): PipelinePhaseStatus {
  const fingerprintingTestIds = new Set(
    data.scanTests.filter((t) => t.pipeline_phase === "fingerprinting").map((t) => t.test_id),
  );
  const hasFingerprintingEvidence = data.evidenceTestIds.some((id) => fingerprintingTestIds.has(id));
  const hasNcaAssessment = data.nca !== null && data.nca.overall_status !== "not_tested";
  const hasVulnData = data.vuln !== null && data.vuln.has_data;
  // Device-level CVE data (TEST-DEVICE-CVE-LOOKUP) is real vulnerability
  // intelligence and needs no firmware image, so it counts toward reaching
  // that phase. It is deliberately kept out of hasUpstreamPipelineData below.
  const hasDeviceCveData = data.vuln !== null && data.vuln.has_device_cve_data;

  // GET /risk/devices/{id}'s `known` flag is true for any device_id that
  // exists in the devices table - not "a real assessment happened" - because
  // risk_engine.py always computes a defensible worst-case score even with
  // zero upstream evidence (a never-assessed device must never look safe).
  // So `known` alone is trivially true the instant a device is registered,
  // before any other phase has run. Require real signal that actually
  // changes the risk score before calling this phase reached.
  //
  // Deliberately excludes fingerprinting: risk_routes.py's 7 inputs
  // (compliance/CVSS/KEV/criticality/exposure/violation-count/
  // insecure-service-count) are assembled from SA-IOT verdicts, NCA
  // assessments, vuln-intel (firmware manifest) evidence, and device_services
  // recorded at registration time - never from fingerprinting scan evidence
  // (TEST-NET-PORTSCAN etc.). A device with only fingerprinting evidence
  // produces the exact same risk score as one with none, so fingerprinting
  // alone must not count as "reached" risk assessment.
  //
  // hasDeviceCveData is excluded for exactly the same reason: risk_engine.py's
  // CVSS and exploit-availability factors read observations.packages[] from
  // TEST-FW-MANIFEST only, so device-level CVEs (however real) do not move the
  // risk score at all. Adding them here would claim a phase was reached when
  // nothing it computes has changed.
  //
  // firmware_currency rides on the same has_device_cve_data flag and follows
  // the identical rule: it is informational vuln-intel, never a risk input.
  // Same precedent as PQC readiness, which is likewise real computed data that
  // deliberately never feeds risk_engine.py.
  const hasUpstreamPipelineData = data.hasSaIotVerdict || hasNcaAssessment || hasVulnData;

  return {
    devices: true,
    fingerprinting: hasFingerprintingEvidence,
    sa_iot_compliance: data.hasSaIotVerdict,
    nca_compliance: hasNcaAssessment,
    vuln_intelligence: hasVulnData || hasDeviceCveData,
    risk_assessment: data.risk !== null && data.risk.known && hasUpstreamPipelineData,
  };
}

/** The furthest phase (in pipeline order) this device has reached, for a
 * single summary badge - null only if somehow not even "devices" is true
 * (shouldn't happen for a registered device, since that phase is always true). */
export function furthestReachedPhase(status: PipelinePhaseStatus): PipelinePhaseDef | null {
  let furthest: PipelinePhaseDef | null = null;
  for (const phase of PIPELINE_PHASES) {
    if (status[phase.id]) furthest = phase;
  }
  return furthest;
}
