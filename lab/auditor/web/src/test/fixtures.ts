import type {
  ControlRecord,
  Device,
  DeviceRiskDetail,
  EvidenceRecord,
  RiskDevicesResponse,
  RiskFleetSummary,
  Summary,
  VerdictRecord,
  VulnDeviceSummary,
  VulnFleetSummary,
  VulnIntelStatus,
} from "@/lib/types";

export const summaryFixture: Summary = {
  total_evidence: 12,
  total_verdicts: 8,
  verdicts_by_status: { PASS: 4, FAIL: 4, PARTIAL: 0, INCONCLUSIVE: 0, NOT_APPLICABLE: 0 },
  device_compliance: [
    { device_id: "device-insecure", framework: "CGIoT-1:2024", tested_controls: 2, passing_controls: 0, percentage: 0 },
    { device_id: "device-hardened", framework: "CGIoT-1:2024", tested_controls: 2, passing_controls: 2, percentage: 100 },
  ],
};

export const devicesFixture: Device[] = [
  {
    device_id: "device-hardened",
    display_name: "Smart Camera — Hardened",
    description: "HTTPS only, strong creds, MQTT over TLS.",
    tier: "hardened",
    host: "device-hardened",
    vendor: "KAUST Labs",
    model: "SC-3000",
    location: "Lab Rack A",
    owner: "auditor-team",
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 2,
    verdict_count: 2,
    services: [{ id: 1, service_type: "https", port: 443, published_port: 8083, enabled: true }],
  },
  {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP, Telnet, unencrypted MQTT.",
    tier: "insecure",
    host: "device-insecure",
    vendor: "KAUST Labs",
    model: "SC-1000",
    location: "Lab Rack A",
    owner: "auditor-team",
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 7,
    verdict_count: 3,
    services: [{ id: 2, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  },
  {
    device_id: "device-partial",
    display_name: "Smart Camera — Partially Hardened",
    description: "Telnet removed, HTTPS with a weak cert, MQTT still unencrypted.",
    tier: "partial",
    host: "device-partial",
    vendor: "KAUST Labs",
    model: "SC-2000",
    location: "Lab Rack A",
    owner: "auditor-team",
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 1,
    verdict_count: 1,
    services: [{ id: 3, service_type: "https", port: 443, published_port: 8082, enabled: true }],
  },
  {
    device_id: "device-unregistered-cam",
    display_name: "Unregistered Test Camera",
    description: "Has evidence from manual scans but no formal device record yet.",
    tier: "unknown",
    host: null,
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: null,
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: false,
    evidence_count: 1,
    verdict_count: 0,
    services: [],
  },
];

export const evidenceFixture: EvidenceRecord[] = [
  {
    evidence_id: "EV-2026-07-08-0013",
    device_id: "device-insecure",
    test_id: "TEST-NET-PORTSCAN",
    tool: "nmap",
    tool_version: "7.95",
    command: "nmap -sV -p- device-insecure",
    timestamp: "2026-07-08T08:58:42Z",
    finding: "Port 80 open; no unnecessary Telnet",
    observations: { open_ports: [80], telnet_open: false },
    raw_output_path: "document-store/raw/EV-2026-07-08-0013.txt",
    confidence: "high",
    sha256: "f".repeat(64),
    assessment_id: null,
    source_type: "automated",
    confidence_reason: null,
    error_state: null,
  },
];

export const verdictsFixture: VerdictRecord[] = [
  {
    verdict_id: "VD-2026-07-08-0001",
    control_id: "SA-IOT-003",
    device_id: "device-insecure",
    status: "PASS",
    severity: "high",
    evidence_ids: ["EV-2026-07-08-0013"],
    matched: "pass",
    reason: "observations.telnet_open equals False",
    saudi_source: "CGIoT-1:2024 §2-15-2",
    remediation: "Remove Telnet and any other non-essential listening service from the device image.",
    timestamp: "2026-07-08T08:58:42Z",
    assessment_id: null,
    policy_version: "1.0.0",
    conflict_detected: false,
    conflict_reason: null,
  },
  {
    verdict_id: "VD-2026-07-08-0002",
    control_id: "SA-IOT-002",
    device_id: "device-insecure",
    status: "FAIL",
    severity: "critical",
    evidence_ids: ["EV-2026-07-08-0015"],
    matched: "fail",
    reason: "observations.default_creds_accepted equals True",
    saudi_source: "CGIoT-1:2024 §2-4-1",
    remediation: "Force a password change on first boot.",
    timestamp: "2026-07-08T08:58:42Z",
    assessment_id: null,
    policy_version: "1.0.0",
    conflict_detected: false,
    conflict_reason: null,
  },
];

export const controlsFixture: ControlRecord[] = [
  {
    control_id: "SA-IOT-003",
    title: "Disable unnecessary network services",
    saudi_source: [{ framework: "CGIoT-1:2024", reference: "2-15-2", clause: "..." }],
    applicability: { device_type: ["smart-camera"] },
    required_evidence: [{ test_id: "TEST-NET-PORTSCAN" }],
    automated_test_ids: ["TEST-NET-PORTSCAN"],
    severity: "high",
    conditions: {},
    remediation: "Remove Telnet and any other non-essential listening service from the device image.",
  },
];

export const vulnIntelStatusFixture: VulnIntelStatus = {
  known: true,
  vuln_db_built_at: "2026-03-09 00:31:20 +0000 UTC",
  vuln_db_checksum: "sha256:a65e27aecbbb2cd6671f5da84c16db7e9c60f0114075e6ae9bcc71f466460a0c",
  observed_at: "2026-07-30T20:41:48+00:00",
  observed_from_evidence_id: "EV-2026-07-30-0001",
  observed_from_device_id: "device-insecure",
};

export const vulnFleetSummaryFixture: VulnFleetSummary = {
  devices: [
    {
      device_id: "device-insecure",
      observed_at: "2026-07-30T20:41:48+00:00",
      total_packages: 2,
      outdated_packages: 2,
      total_cves: 101,
      kev_listed_cves: 1,
      highest_cvss: 10,
    },
  ],
  total_cves: 101,
  total_kev_listed_cves: 1,
};

export const vulnDeviceSummaryFixture: VulnDeviceSummary = {
  device_id: "device-insecure",
  has_data: true,
  evidence_id: "EV-2026-07-30-0001",
  observed_at: "2026-07-30T20:41:48+00:00",
  total_packages: 2,
  outdated_packages: 2,
  total_cves: 2,
  kev_listed_cves: 1,
  highest_cvss: 7.5,
  packages: [
    {
      name: "openssl",
      version: "1.0.1e",
      outdated: true,
      eol: null,
      latest_known_version: null,
      official_patch_available: true,
      patched_version: "1.0.1g",
      kev_listed_count: 1,
      cves: [
        {
          id: "CVE-2014-0160",
          cvss: 7.5,
          summary: "Heartbleed - a missing bounds check in the TLS heartbeat extension.",
          kev_listed: true,
          kev_date_added: "2022-05-04",
        },
        {
          id: "CVE-2016-6304",
          cvss: 5.9,
          summary: "OOB write via OCSP status request.",
          kev_listed: false,
          kev_date_added: null,
        },
      ],
      notes: [],
    },
  ],
};

export const riskDevicesFixture: RiskDevicesResponse = {
  devices: [
    { device_id: "device-insecure", risk_score: 78, risk_category: "critical", priority_rank: 1 },
    // Deliberately not 12 or 8 - those already appear elsewhere in these
    // shared fixtures (total_evidence/total_verdicts), which caused a real
    // cross-test collision (screen.getByText("12") matched two things).
    { device_id: "device-hardened", risk_score: 15, risk_category: "low", priority_rank: 2 },
  ],
};

export const riskDeviceDetailFixture: DeviceRiskDetail = {
  device_id: "device-insecure",
  known: true,
  risk_score: 78,
  risk_category: "critical",
  breakdown: {
    compliance: { raw_value: 20, normalized: 80, weight: 0.25, contribution: 20 },
    cvss: { raw_value: 9.8, normalized: 98, weight: 0.2, contribution: 19.6 },
    exploit_availability: { raw_value: true, normalized: 100, weight: 0.2, contribution: 20 },
    criticality: { raw_value: "high", normalized: 75, weight: 0.15, contribution: 11.25 },
    exposure: { raw_value: "internal_only", normalized: 40, weight: 0.1, contribution: 4 },
    violations: { raw_value: 2, normalized: 40, weight: 0.05, contribution: 2 },
    insecure_services: { raw_value: 1, normalized: 25, weight: 0.05, contribution: 1.25 },
  },
};

export const riskFleetSummaryFixture: RiskFleetSummary = {
  total_devices: 2,
  average_score: 45,
  by_category: { low: 1, medium: 0, high: 0, critical: 1 },
};

export function mockFetchImplementation(path: string): Promise<Response> {
  const routes: Record<string, unknown> = {
    "/summary": summaryFixture,
    "/devices": devicesFixture,
    "/evidence": evidenceFixture,
    "/verdicts": verdictsFixture,
    "/controls": controlsFixture,
    "/vuln-intel/status": vulnIntelStatusFixture,
    "/vuln-intel/fleet-summary": vulnFleetSummaryFixture,
    "/vuln-intel/devices/device-insecure": vulnDeviceSummaryFixture,
    "/risk/devices/device-insecure": riskDeviceDetailFixture,
    "/risk/devices": riskDevicesFixture,
    "/risk/fleet-summary": riskFleetSummaryFixture,
  };
  // Longest (most specific) match wins - e.g. "/risk/devices" must not lose
  // to the shorter, unrelated "/devices" route just because it also happens
  // to be a suffix match ("/risk/devices".endsWith("/devices") is true).
  const matched = Object.keys(routes)
    .filter((route) => path.endsWith(route))
    .sort((a, b) => b.length - a.length)[0];
  if (!matched) {
    return Promise.resolve(new Response("not found", { status: 404 }));
  }
  return Promise.resolve(
    new Response(JSON.stringify(routes[matched]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}
