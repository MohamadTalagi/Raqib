import type { ControlRecord, Device, EvidenceRecord, Summary, VerdictRecord } from "@/lib/types";

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

export function mockFetchImplementation(path: string): Promise<Response> {
  const routes: Record<string, unknown> = {
    "/summary": summaryFixture,
    "/devices": devicesFixture,
    "/evidence": evidenceFixture,
    "/verdicts": verdictsFixture,
    "/controls": controlsFixture,
  };
  const matched = Object.keys(routes).find((route) => path.endsWith(route));
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
