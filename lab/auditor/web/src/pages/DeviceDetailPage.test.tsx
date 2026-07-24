import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceDetailPage } from "./DeviceDetailPage";
import { api, ApiError } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";
import type { DeviceDetail, NCADeviceDetail } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const NCA_DETAIL: NCADeviceDetail = {
  device_id: "device-insecure",
  display_name: "Smart Camera — Insecure",
  tier: "insecure",
  overall_status: "fail",
  score: 20,
  domain_summary: {
    "Cybersecurity Governance": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
    "Cybersecurity Defense": { pass: 1, partial: 0, fail: 1, not_tested: 0, review_required: 0 },
    "Cybersecurity Resilience": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
    "Third-Party and Cloud Computing Cybersecurity": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
  },
  readiness: {
    classification: "failed",
    score: 20,
    reasons: ["Score 20% is below the failing threshold of 50%."],
    blocking_control_ids: [],
    critical_failure_control_ids: [],
    not_tested_control_ids: [],
    review_required_control_ids: [],
    pass_threshold: 85,
    partial_threshold: 50,
  },
  controls: [
    {
      control: {
        id: "NCA-CGIoT-1_2024-2-2-2",
        framework: "NCA-CGIoT",
        framework_version: "1:2024",
        domain_id: "2",
        domain_name: "Cybersecurity Defense",
        subdomain_id: "2-2",
        subdomain_name: "Access and Permission Restriction",
        guideline_id: "2-2-2",
        canonical_requirement: "Do not use default or hard-coded passwords.",
        implementation_summary: "No default creds.",
        source_page: "17",
        scope_type: "device",
        assessment_type: "automated",
        required: true,
        severity: "high",
        blocking: true,
        evidence_requirements: [],
        remediation_guidance: "",
        enabled: true,
      },
      assessment: {
        id: "ASM-1",
        control_id: "NCA-CGIoT-1_2024-2-2-2",
        device_id: "device-insecure",
        organizational_scope_id: null,
        applicability: "applicable",
        applicability_reason: null,
        status: "fail",
        severity: "high",
        finding: "default creds accepted",
        test_method: "automated",
        test_identifier: "TEST-AUTH-DEFAULT-CREDS",
        raw_result_reference: null,
        evidence_ids: [],
        scanner_tool: "curl",
        scanner_tool_version: "8.5.0",
        firmware_version_assessed: null,
        assessed_at: "2026-07-20T00:00:00Z",
        assessed_by: "reviewer-1",
        remediation: "Force a unique password on first boot.",
        remediation_due_date: null,
        retest_status: "not_requested",
        retested_at: null,
        superseded_by: null,
        created_at: "2026-07-20T00:00:00Z",
      },
    },
  ],
  exceptions: [],
};

const DETAIL: DeviceDetail = {
  device: {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP.",
    tier: "insecure",
    host: "device-insecure",
    vendor: "AcmeCam",
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
  },
  services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  evidence: [
    {
      evidence_id: "EV-1",
      test_id: "TEST-NET-PORTSCAN",
      tool: "nmap",
      finding: "Telnet exposed",
      confidence: "high",
      timestamp: "2026-07-08T10:00:00+00:00",
    },
  ],
  verdicts: [
    {
      verdict_id: "V-1",
      control_id: "SA-IOT-002",
      status: "FAIL",
      severity: "high",
      reason: "default creds accepted",
      timestamp: "2026-07-08T10:05:00+00:00",
    },
  ],
  scan_jobs: [],
  compliance: { framework: "CGIoT-1:2024", tested_controls: 1, passing_controls: 0, percentage: 0 },
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/devices/device-insecure"]}>
      <ToastProvider>
        <Routes>
          <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("DeviceDetailPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "ncaDevice").mockResolvedValue(NCA_DETAIL);
  });

  it("shows the device's NCA compliance percentage", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("0%")).toBeInTheDocument();
    expect(screen.getByText(/Automated scan coverage:/)).toBeInTheDocument();
  });

  it("hides the legacy automated-scan-coverage chip on the Compliance tab, since it sits above the real NCA readiness card there", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText(/Automated scan coverage:/);
    await user.click(screen.getByRole("tab", { name: "NCA Compliance" }));

    expect(screen.queryByText(/Automated scan coverage:/)).not.toBeInTheDocument();
  });

  it("shows 'not assessed' when no controls have been tested for this device", async () => {
    vi.spyOn(api, "device").mockResolvedValue({
      ...DETAIL,
      compliance: { framework: "CGIoT-1:2024", tested_controls: 0, passing_controls: 0, percentage: null },
    });
    renderPage();

    expect(await screen.findByText("NOT ASSESSED")).toBeInTheDocument();
  });

  it("shows the device, its evidence and verdicts together", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("Smart Camera — Insecure")).toBeInTheDocument();
    expect(screen.getByText("AcmeCam")).toBeInTheDocument();
    expect(screen.getByText("Telnet exposed")).toBeInTheDocument();
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();
  });

  it("no longer shows a security-tier badge", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    expect(screen.queryByText("Insecure")).not.toBeInTheDocument();
  });

  it("renders an error state when the device is missing", async () => {
    vi.spyOn(api, "device").mockRejectedValue(new Error("device not found"));
    renderPage();
    await waitFor(() => expect(screen.getByText(/device not found/i)).toBeInTheDocument());
  });

  it("offers a download link to the device report", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL as never);
    renderPage();

    const link = await screen.findByRole("link", { name: /download report/i });
    expect(link).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.pdf"));
  });

  it("offers HTML and JSON report export links alongside the PDF one", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL as never);
    renderPage();

    const htmlLink = await screen.findByRole("link", { name: "HTML" });
    expect(htmlLink).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.html"));
    const jsonLink = screen.getByRole("link", { name: "JSON" });
    expect(jsonLink).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.json"));
  });

  it("shows a Deregister control on the detail page", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByRole("button", { name: /deregister/i })).toBeInTheDocument();
  });

  it("does not call deleteDevice immediately on click — a confirmation appears first", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const deleteSpy = vi.spyOn(api, "deleteDevice").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));

    expect(deleteSpy).not.toHaveBeenCalled();
    expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  });

  it("calls deleteDevice with the correct device id when the confirmation is confirmed", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const deleteSpy = vi.spyOn(api, "deleteDevice").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /deregister device/i }));

    await waitFor(() => expect(deleteSpy).toHaveBeenCalledWith("device-insecure"));
  });

  it("does not call deleteDevice when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const deleteSpy = vi.spyOn(api, "deleteDevice").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));

    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(deleteSpy).not.toHaveBeenCalled();
  });

  it("states in the confirmation that evidence and verdicts are kept, not deleted", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));
    const dialog = await screen.findByRole("alertdialog");

    expect(within(dialog).getByText(/evidence.*(kept|preserved|retained|not deleted)/i)).toBeInTheDocument();
  });

  it("shows an upload control when no firmware has been uploaded yet", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByLabelText(/firmware archive/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /upload firmware/i })).toBeDisabled();
  });

  it("uploads firmware and then shows its filename and hash", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const uploadSpy = vi.spyOn(api, "uploadFirmware").mockResolvedValue({
      ...DETAIL.device,
      firmware_filename: "cam-fw-1.2.0.tar.gz",
      firmware_sha256: "b".repeat(64),
      firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
      services: DETAIL.services,
    });
    renderPage();

    const file = new File(["dummy"], "cam-fw-1.2.0.tar.gz", { type: "application/gzip" });
    const input = await screen.findByLabelText(/firmware archive/i);
    await user.upload(input, file);

    const uploadButton = screen.getByRole("button", { name: /upload firmware/i });
    expect(uploadButton).toBeEnabled();
    await user.click(uploadButton);

    await waitFor(() => expect(uploadSpy).toHaveBeenCalledWith("device-insecure", file));
    expect(await screen.findByText("cam-fw-1.2.0.tar.gz")).toBeInTheDocument();
    expect(screen.getByText(/b{16}…/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /remove firmware/i })).toBeInTheDocument();
  });

  it("surfaces the API's error message when a firmware upload is rejected", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "uploadFirmware").mockRejectedValue(
      new ApiError("not a valid .tar.gz archive", 400),
    );
    renderPage();

    const file = new File(["dummy"], "cam-fw.tar.gz", { type: "application/gzip" });
    const input = await screen.findByLabelText(/firmware archive/i);
    await user.upload(input, file);
    await user.click(screen.getByRole("button", { name: /upload firmware/i }));

    expect(await screen.findByText(/not a valid \.tar\.gz archive/i)).toBeInTheDocument();
  });

  it("removes firmware and reverts to the upload control", async () => {
    const user = userEvent.setup();
    const withFirmware: DeviceDetail = {
      ...DETAIL,
      device: {
        ...DETAIL.device,
        firmware_filename: "cam-fw-1.2.0.tar.gz",
        firmware_sha256: "b".repeat(64),
        firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
      },
    };
    vi.spyOn(api, "device").mockResolvedValue(withFirmware);
    const deleteSpy = vi.spyOn(api, "deleteFirmware").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /remove firmware/i }));

    await waitFor(() => expect(deleteSpy).toHaveBeenCalledWith("device-insecure"));
    expect(await screen.findByLabelText(/firmware archive/i)).toBeInTheDocument();
  });

  it("excludes organization-scope-only domains with zero device-scope controls from the Compliance tab", async () => {
    // NCA_DETAIL's fixture domain_summary has Governance/Resilience/Third-
    // Party all at zero across every status - those domains have no
    // device-scope guideline at all, so they must not appear here, while
    // Defense (which has real pass/fail counts) must still show.
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    await user.click(screen.getByRole("tab", { name: /NCA Compliance/i }));

    expect(await screen.findByText("Cybersecurity Defense")).toBeInTheDocument();
    expect(screen.queryByText("Cybersecurity Governance")).not.toBeInTheDocument();
    expect(screen.queryByText("Cybersecurity Resilience")).not.toBeInTheDocument();
    expect(screen.queryByText("Third-Party and Cloud Computing Cybersecurity")).not.toBeInTheDocument();
  });

  it("shows the NCA Compliance tab with per-control status, hidden until selected", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    expect(screen.queryByText("No default creds.")).not.toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /NCA Compliance/i }));

    expect(await screen.findByText("No default creds.")).toBeInTheDocument();
    expect(screen.getAllByText("Fail").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Force a unique password on first boot.")).toBeInTheDocument();
    // NCA_DETAIL's one control has blocking: true - its failure alone forces
    // the device's readiness to Failed, so the Controls list must flag it.
    expect(screen.getByText("blocking")).toBeInTheDocument();
  });
});
