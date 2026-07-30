import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceAssessmentReportPage } from "./DeviceAssessmentReportPage";
import { api } from "@/lib/api";
import type { DeviceDetail, NCADeviceDetail, VulnDeviceSummary } from "@/lib/types";
import { vulnDeviceSummaryFixture, vulnIntelStatusFixture } from "@/test/fixtures";

const NO_VULN_DATA: VulnDeviceSummary = {
  device_id: "device-insecure",
  has_data: false,
  evidence_id: null,
  observed_at: null,
  packages: [],
  total_packages: 0,
  outdated_packages: 0,
  total_cves: 0,
  kev_listed_cves: 0,
  highest_cvss: null,
};

afterEach(() => vi.restoreAllMocks());

const DETAIL: DeviceDetail = {
  device: {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP.",
    tier: "insecure",
    host: "device-insecure",
    vendor: "AcmeCam",
    model: "AC-100",
    location: "Lab",
    owner: "Blue Team",
    notes: "Test unit",
    source: "manual",
    firmware_filename: "fw.zip",
    firmware_sha256: "abcdef1234567890abcdef1234567890abcdef1234567890",
    firmware_uploaded_at: "2026-07-27T00:00:00Z",
  },
  services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  evidence: [
    { evidence_id: "EV-1", test_id: "TEST-AUTH-DEFAULT-CREDS", tool: "curl", finding: "Default creds accepted", confidence: "high", timestamp: "2026-07-08T00:00:00Z" },
  ],
  verdicts: [
    { verdict_id: "VD-1", control_id: "SA-IOT-002", status: "FAIL", severity: "critical", reason: "default_creds true", timestamp: "2026-07-08T00:00:00Z" },
  ],
  scan_jobs: [],
  compliance: { framework: "CGIoT-1:2024", tested_controls: 2, passing_controls: 0, percentage: 0 },
};

const NCA: NCADeviceDetail = {
  device_id: "device-insecure",
  display_name: "Smart Camera — Insecure",
  tier: "insecure",
  overall_status: "fail",
  score: 0,
  domain_summary: {},
  readiness: {
    classification: "failed",
    score: 0,
    reasons: ["A blocking control failed."],
    blocking_control_ids: ["NCA-CGIoT-1_2024-2-2-2"],
    critical_failure_control_ids: [],
    not_tested_control_ids: [],
    review_required_control_ids: [],
    pass_threshold: 85,
    partial_threshold: 50,
  },
  controls: [],
  exceptions: [],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/devices/device-insecure/assessment"]}>
      <Routes>
        <Route path="/devices/:deviceId/assessment" element={<DeviceAssessmentReportPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("DeviceAssessmentReportPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "ncaDevice").mockResolvedValue(NCA);
    vi.spyOn(api, "vulnIntelDevice").mockResolvedValue(NO_VULN_DATA);
    vi.spyOn(api, "vulnIntelStatus").mockResolvedValue(vulnIntelStatusFixture);
  });

  it("consolidates profile, firmware, verdicts, evidence, and NCA readiness", async () => {
    renderPage();

    expect(await screen.findByText("Device profile")).toBeInTheDocument();
    // Inventory the user entered.
    expect(screen.getByText("AcmeCam")).toBeInTheDocument();
    expect(screen.getByText("Blue Team")).toBeInTheDocument();
    // Firmware.
    expect(screen.getByText("fw.zip")).toBeInTheDocument();
    // Verdict + evidence.
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("EV-1")).toBeInTheDocument();
    // NCA readiness reason.
    expect(screen.getByText(/A blocking control failed/)).toBeInTheDocument();
  });

  it("offers PDF / HTML / JSON downloads", async () => {
    renderPage();

    const pdf = await screen.findByRole("link", { name: /download pdf/i });
    expect(pdf).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.pdf"));
    expect(screen.getByRole("link", { name: "HTML" })).toHaveAttribute(
      "href",
      expect.stringContaining("/report.html"),
    );
    expect(screen.getByRole("link", { name: "JSON" })).toHaveAttribute(
      "href",
      expect.stringContaining("/report.json"),
    );
  });

  it("renders an error state when the device fails to load", async () => {
    vi.spyOn(api, "device").mockRejectedValue(new Error("device not found"));
    renderPage();
    expect(await screen.findByText(/device not found/i)).toBeInTheDocument();
  });

  it("says no manifest scan has run when there's no vulnerability data yet", async () => {
    renderPage();
    expect(await screen.findByText(/no firmware manifest scan/i)).toBeInTheDocument();
  });

  it("shows real CVE/KEV data in the Vulnerability intelligence section", async () => {
    vi.spyOn(api, "vulnIntelDevice").mockResolvedValue(vulnDeviceSummaryFixture);
    renderPage();

    expect(await screen.findByText("Vulnerability intelligence (2 CVEs)")).toBeInTheDocument();
    expect(screen.getByText("openssl@1.0.1e")).toBeInTheDocument();
    expect(screen.getByText("CVE-2014-0160")).toBeInTheDocument();
  });
});
