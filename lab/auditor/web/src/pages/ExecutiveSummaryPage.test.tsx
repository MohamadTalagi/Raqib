import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ExecutiveSummaryPage } from "./ExecutiveSummaryPage";
import { api } from "@/lib/api";
import type { ExecutiveSummary } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const SUMMARY: ExecutiveSummary = {
  generated_at: "2026-08-02T00:00:00Z",
  fleet_summary: {
    total_devices: 2,
    average_risk_score: 61,
    risk_by_category: { critical: 1, high: 0, medium: 1, low: 0 },
    total_compliance_gaps: 2,
    remediation_generated: 1,
    remediation_reviewed: 0,
    remediation_coverage_pct: 50,
  },
  priority_recommendations: [
    {
      id: "RB-1",
      finding_type: "sa_iot_verdict",
      finding_id: "VD-1",
      device_id: "device-insecure",
      control_id: "SA-IOT-002",
      model: "gemini-3.5-flash-lite",
      root_cause: "Default credentials were never rotated.",
      remediation_steps: ["Force a password change."],
      priority: "immediate",
      estimated_effort: "Low",
      caveats: null,
      generated_at: "2026-08-02T00:00:00Z",
      reviewed: false,
      reviewed_by: null,
      reviewed_at: null,
      superseded_by: null,
      device_display_name: "Insecure Smart Camera",
    },
  ],
  significant_compliance_gaps: [
    {
      control_id: "NCA-CGIoT-1_2024-2-2-2",
      domain_name: "Cybersecurity Defense",
      subdomain_name: "Access and Permission Restriction",
      guideline_id: "2-2-2",
      canonical_requirement: "Do not use default or hard-coded passwords.",
      blocking: true,
      status: "fail",
      device_id: "device-insecure",
      device_display_name: "Insecure Smart Camera",
    },
  ],
  post_quantum_readiness: {
    total_devices: 2,
    tls_key_exchange: { pass: 1, fail: 1, unknown: 0, not_applicable: 0 },
    certificate_signature: { pass: 0, fail: 2, unknown: 0, not_applicable: 0 },
    firmware_crypto: { pass: 0, fail: 0, unknown: 0, not_applicable: 2 },
  },
  devices: [
    {
      device_id: "device-insecure",
      display_name: "Insecure Smart Camera",
      risk_score: 82,
      risk_category: "critical",
      priority_rank: 1,
      sa_iot_gaps: [
        {
          control_id: "SA-IOT-002",
          title: "No default or hard-coded credentials",
          severity: "high",
          status: "FAIL",
          reason: "observations.default_creds equals True",
          remediation: "Force a unique password on first boot.",
        },
      ],
      nca_gaps: [
        {
          control_id: "NCA-CGIoT-1_2024-2-2-2",
          domain_name: "Cybersecurity Defense",
          subdomain_name: "Access and Permission Restriction",
          guideline_id: "2-2-2",
          canonical_requirement: "Do not use default or hard-coded passwords.",
          blocking: true,
          status: "fail",
        },
      ],
      evidence: [
        {
          evidence_id: "EV-1",
          test_id: "TEST-AUTH-DEFAULT-CREDS",
          tool: "curl",
          tool_version: "8.5.0",
          command: "curl -s -X POST http://device-insecure/login",
          timestamp: "2026-08-02T00:00:00Z",
          finding: "Default creds admin/admin accepted",
          confidence: "high",
          raw_output_path: "document-store/raw/EV-1.txt",
          sha256: "abc123",
        },
      ],
      remediation: [
        {
          id: "RB-1",
          finding_type: "sa_iot_verdict",
          finding_id: "VD-1",
          device_id: "device-insecure",
          control_id: "SA-IOT-002",
          model: "gemini-3.5-flash-lite",
          root_cause: "Default credentials were never rotated.",
          remediation_steps: ["Force a password change."],
          priority: "immediate",
          estimated_effort: "Low",
          caveats: null,
          generated_at: "2026-08-02T00:00:00Z",
          reviewed: false,
          reviewed_by: null,
          reviewed_at: null,
          superseded_by: null,
        },
      ],
      pqc_readiness: {
        device_id: "device-insecure",
        known: true,
        overall_status: "fail",
        fail_count: 1,
        tls_key_exchange: { status: "pass", negotiated_group: "X25519MLKEM768" },
        certificate_signature: {
          status: "fail",
          signature_algorithm: "sha256WithRSAEncryption",
          tip: "Deploy an ML-DSA or SLH-DSA certificate once your CA supports it.",
        },
        firmware_crypto: { status: "not_applicable", packages: [] },
      },
    },
    {
      device_id: "device-hardened",
      display_name: "Hardened Smart Camera",
      risk_score: 12,
      risk_category: "medium",
      priority_rank: 2,
      sa_iot_gaps: [],
      nca_gaps: [],
      evidence: [],
      remediation: [],
      pqc_readiness: {
        device_id: "device-hardened",
        known: true,
        overall_status: "fail",
        fail_count: 1,
        tls_key_exchange: { status: "fail", negotiated_group: "X25519" },
        certificate_signature: { status: "fail", signature_algorithm: "sha256WithRSAEncryption" },
        firmware_crypto: { status: "not_applicable", packages: [] },
      },
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ExecutiveSummaryPage />
    </MemoryRouter>,
  );
}

describe("ExecutiveSummaryPage", () => {
  it("shows fleet-wide summary tiles", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue(SUMMARY);
    renderPage();

    expect(await screen.findByText("Devices")).toBeInTheDocument();
    expect(screen.getByText("61")).toBeInTheDocument(); // average risk score
    expect(screen.getByText("50%")).toBeInTheDocument(); // remediation coverage
  });

  it("lists devices ranked by risk, highest first", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue(SUMMARY);
    renderPage();

    await screen.findByText("Devices, ranked by risk (highest first)");
    const deviceRowButtons = screen
      .getAllByRole("button")
      .filter((btn) => /Smart Camera/.test(btn.textContent ?? ""));
    expect(deviceRowButtons[0]).toHaveTextContent("Insecure Smart Camera");
    expect(deviceRowButtons[1]).toHaveTextContent("Hardened Smart Camera");
  });

  it("shows priority recommendations and significant compliance gaps", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue(SUMMARY);
    renderPage();

    expect(await screen.findByText("Priority recommendations")).toBeInTheDocument();
    expect(screen.getByText("Default credentials were never rotated.")).toBeInTheDocument();
    expect(screen.getByText("Most significant compliance gaps")).toBeInTheDocument();
    expect(screen.getByText("Do not use default or hard-coded passwords.")).toBeInTheDocument();
  });

  it("expands a device row to show its compliance gaps, evidence, and remediation", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue(SUMMARY);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Devices, ranked by risk (highest first)");
    const insecureRow = screen
      .getAllByRole("button")
      .find((btn) => /Insecure Smart Camera/.test(btn.textContent ?? ""))!;
    await user.click(insecureRow);

    expect(await screen.findByText("observations.default_creds equals True")).toBeInTheDocument();
    expect(screen.getByText("Default creds admin/admin accepted")).toBeInTheDocument();
    expect(screen.getByText(/ai-generated/i)).toBeInTheDocument();
  });

  it("shows the fleet-wide Post-Quantum Readiness section, informational only", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue(SUMMARY);
    renderPage();

    expect(await screen.findByText("Post-Quantum Readiness (informational)")).toBeInTheDocument();
    expect(screen.getByText("TLS key exchange (KEM)")).toBeInTheDocument();
    expect(screen.getByText(/never affects the risk scores or compliance gaps/i)).toBeInTheDocument();
  });

  it("shows a device's own 3-criterion PQC breakdown once expanded", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue(SUMMARY);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Devices, ranked by risk (highest first)");
    const insecureRow = screen
      .getAllByRole("button")
      .find((btn) => /Insecure Smart Camera/.test(btn.textContent ?? ""))!;
    await user.click(insecureRow);

    expect(await screen.findByText("Negotiated group: X25519MLKEM768")).toBeInTheDocument();
    expect(screen.getByText(/deploy an ml-dsa or slh-dsa certificate/i)).toBeInTheDocument();
  });

  it("shows an empty state when nothing is registered", async () => {
    vi.spyOn(api, "executiveSummary").mockResolvedValue({
      ...SUMMARY,
      devices: [],
      priority_recommendations: [],
      significant_compliance_gaps: [],
      fleet_summary: { ...SUMMARY.fleet_summary, total_devices: 0 },
    });
    renderPage();

    expect(await screen.findByText("No devices registered yet.")).toBeInTheDocument();
  });
});
