import { describe, expect, it } from "vitest";
import { PIPELINE_PHASES, devicePipelineStatus, furthestReachedPhase } from "./pipeline";
import type { DeviceRiskDetail, NCADeviceDetail, ScanTestSpec, VulnDeviceSummary } from "./types";

const SCAN_TESTS: ScanTestSpec[] = [
  { test_id: "TEST-NET-PORTSCAN", label: "Nmap service/port scan", category: "network-and-protocol", applicable_service_types: ["http"], pipeline_phase: "fingerprinting" },
  { test_id: "TEST-AUTH-DEFAULT-CREDS", label: "Default credentials", category: "web-and-auth", applicable_service_types: ["http"], pipeline_phase: "nca_compliance" },
  { test_id: "TEST-FW-MANIFEST", label: "Packet manifest", category: "firmware", applicable_service_types: [], pipeline_phase: "vuln_intelligence" },
];

const NO_NCA: NCADeviceDetail | null = null;
const NOT_ASSESSED_NCA: NCADeviceDetail = {
  device_id: "d", display_name: "d", tier: "unknown", overall_status: "not_tested", score: null,
  domain_summary: {}, readiness: {
    classification: "failed", score: 0, reasons: [], blocking_control_ids: [],
    critical_failure_control_ids: [], not_tested_control_ids: [], review_required_control_ids: [],
    pass_threshold: 85, partial_threshold: 50,
  },
  controls: [], exceptions: [],
};
const ASSESSED_NCA: NCADeviceDetail = { ...NOT_ASSESSED_NCA, overall_status: "partial" };

const NO_VULN: VulnDeviceSummary | null = null;
const VULN_NO_DATA: VulnDeviceSummary = {
  device_id: "d", has_data: false, evidence_id: null, observed_at: null, packages: [],
  total_packages: 0, outdated_packages: 0, total_cves: 0, kev_listed_cves: 0, highest_cvss: null,
  has_device_cve_data: false, device_cve_evidence_id: null, device_cve_observed_at: null,
  device_identity: null, device_cves: [], total_device_cves: 0,
  kev_listed_device_cves: 0, highest_device_cvss: null, firmware_currency: null,
};
const VULN_WITH_DATA: VulnDeviceSummary = { ...VULN_NO_DATA, has_data: true };
const VULN_WITH_DEVICE_CVES: VulnDeviceSummary = { ...VULN_NO_DATA, has_device_cve_data: true };

const NO_RISK: DeviceRiskDetail | null = null;
const RISK_UNKNOWN: DeviceRiskDetail = { device_id: "d", known: false };
const RISK_KNOWN: DeviceRiskDetail = { device_id: "d", known: true, risk_score: 40, risk_category: "medium" };

describe("devicePipelineStatus", () => {
  it("is all-false past devices for a freshly registered device with no data anywhere", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: NO_RISK,
    });
    expect(status).toEqual({
      devices: true, fingerprinting: false,
      nca_compliance: false, vuln_intelligence: false, risk_assessment: false,
    });
  });

  it("marks fingerprinting reached only from a fingerprinting-tagged test_id, not any evidence", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: ["TEST-AUTH-DEFAULT-CREDS"], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: NO_RISK,
    });
    expect(status.fingerprinting).toBe(false);

    const status2 = devicePipelineStatus({
      evidenceTestIds: ["TEST-NET-PORTSCAN"], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: NO_RISK,
    });
    expect(status2.fingerprinting).toBe(true);
  });

  it("does not mark nca_compliance reached while the device is only not_tested", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NOT_ASSESSED_NCA, vuln: NO_VULN, risk: NO_RISK,
    });
    expect(status.nca_compliance).toBe(false);
  });

  it("marks nca_compliance reached once a real assessment status exists", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: ASSESSED_NCA, vuln: NO_VULN, risk: NO_RISK,
    });
    expect(status.nca_compliance).toBe(true);
  });

  it("distinguishes vuln_intelligence fetched-but-empty from real data", () => {
    const empty = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: VULN_NO_DATA, risk: NO_RISK,
    });
    expect(empty.vuln_intelligence).toBe(false);

    const withData = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: VULN_WITH_DATA, risk: NO_RISK,
    });
    expect(withData.vuln_intelligence).toBe(true);
  });

  it("distinguishes risk fetched-but-unknown from a real computed score", () => {
    const unknown = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: RISK_UNKNOWN,
    });
    expect(unknown.risk_assessment).toBe(false);
  });

  // Regression: GET /risk/devices/{id}'s `known` flag is true for any
  // device_id that exists in the devices table, not "a real assessment
  // happened" - risk_engine.py always computes a defensible worst-case score
  // even with zero upstream evidence. Caught live: every freshly-registered
  // device (0 evidence, 0 verdicts) showed "Risk Assessment" - the LAST
  // pipeline phase - as its furthest reached phase immediately upon
  // registration, since `risk.known` alone was trivially true from the
  // moment the device row existed.
  it("does not mark risk_assessment reached from a known-but-otherwise-untouched device", () => {
    const freshlyRegistered = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: RISK_KNOWN,
    });
    expect(freshlyRegistered.risk_assessment).toBe(false);
  });

  // Regression: fingerprinting evidence alone must not count either. Caught
  // live: risk_routes.py's inputs are assembled from NCA assessments,
  // vuln-intel evidence, and registration-time device_services - never from
  // TEST-NET-PORTSCAN/etc. evidence - so a device with only fingerprinting
  // evidence produces the identical risk score to one with none.
  it("does not mark risk_assessment reached from fingerprinting evidence alone", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: ["TEST-NET-PORTSCAN"], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: RISK_KNOWN,
    });
    expect(status.fingerprinting).toBe(true);
    expect(status.risk_assessment).toBe(false);
  });

  it("marks risk_assessment reached once risk is known AND an earlier phase has real data", () => {
    // A real NCA assessment is now the upstream signal - this used to be
    // satisfied by an SA-IOT verdict, which is no longer a risk input at all.
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: ASSESSED_NCA, vuln: NO_VULN, risk: RISK_KNOWN,
    });
    expect(status.risk_assessment).toBe(true);
  });
});

describe("devicePipelineStatus and device-level CVE data", () => {
  it("counts device-level CVE data toward vuln_intelligence with no firmware scan at all", () => {
    // The feature's whole premise - a device with no firmware archive still
    // reaches Vulnerability Intelligence via TEST-DEVICE-CVE-LOOKUP.
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: VULN_WITH_DEVICE_CVES, risk: RISK_KNOWN,
    });
    expect(status.vuln_intelligence).toBe(true);
  });

  it("does NOT let device-level CVE data alone mark risk_assessment reached", () => {
    // risk_engine.py's CVSS/exploit-availability factors read only
    // TEST-FW-MANIFEST's observations.packages[], so device-level CVEs do not
    // move the risk score - claiming the phase was reached would be false.
    // Same reasoning the file already applies to fingerprinting.
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: VULN_WITH_DEVICE_CVES, risk: RISK_KNOWN,
    });
    expect(status.risk_assessment).toBe(false);

    // ...whereas package-level data does, since it really is a risk input.
    const withFirmware = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: VULN_WITH_DATA, risk: RISK_KNOWN,
    });
    expect(withFirmware.risk_assessment).toBe(true);
  });
});

describe("furthestReachedPhase", () => {
  it("returns devices when nothing past it has been reached", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: [], scanTests: SCAN_TESTS,
      nca: NO_NCA, vuln: NO_VULN, risk: NO_RISK,
    });
    expect(furthestReachedPhase(status)?.id).toBe("devices");
  });

  it("returns the last reached phase in pipeline order, not just any true one", () => {
    const status = devicePipelineStatus({
      evidenceTestIds: ["TEST-NET-PORTSCAN"], scanTests: SCAN_TESTS,
      nca: ASSESSED_NCA, vuln: NO_VULN, risk: RISK_KNOWN,
    });
    // fingerprinting + nca_compliance + risk_assessment are true, but
    // vuln_intelligence in between is not - furthest must still be
    // risk_assessment (the true entry latest in PIPELINE_PHASES order), not
    // nca_compliance (the last true entry with no gap before it).
    expect(furthestReachedPhase(status)?.id).toBe("risk_assessment");
  });

  it("PIPELINE_PHASES stays in the agreed pipeline order", () => {
    // sa_iot_compliance was removed when that stage was retired as redundant
    // with NCA Compliance; its collectors moved into the nca_compliance phase.
    expect(PIPELINE_PHASES.map((p) => p.id)).toEqual([
      "devices", "fingerprinting",
      "nca_compliance", "vuln_intelligence", "risk_assessment",
    ]);
  });
});
