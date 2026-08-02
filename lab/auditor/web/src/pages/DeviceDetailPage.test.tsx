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
        attested_role: "Lead Auditor",
        attestation_confirmed: true,
        attestation_statement: "Reviewed and certified.",
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
    criticality: "medium",
    exposure: "internal_only",
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
      confidence_reason: null,
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
    vi.spyOn(api, "riskDevice").mockResolvedValue({ device_id: "device-insecure", known: false });
    vi.spyOn(api, "listAssessments").mockResolvedValue([]);
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

  it("offers a PDF download link and a consolidated assessment link", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL as never);
    renderPage();

    const pdf = await screen.findByRole("link", { name: "PDF" });
    expect(pdf).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.pdf"));

    const assessment = screen.getByRole("link", { name: /view assessment/i });
    expect(assessment).toHaveAttribute("href", "/devices/device-insecure/assessment");
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

  it("points to the Vulnerability Intelligence page instead of embedding the Firmware card itself", async () => {
    // Firmware upload/removal and the real CVE/CVSS/CISA-KEV display moved
    // to their own cohort-aware pipeline page (Phase 9) - this page only
    // links there now.
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    expect(screen.queryByLabelText(/firmware archive/i)).not.toBeInTheDocument();
    const link = screen.getByRole("link", { name: /open vulnerability intelligence/i });
    expect(link).toHaveAttribute("href", "/vulnerability-intelligence");
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

  it("shows the device's current criticality and exposure", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await screen.findByText("Smart Camera — Insecure");

    expect(screen.getByLabelText("Criticality")).toHaveValue(DETAIL.device.criticality);
    expect(screen.getByLabelText("Internet exposure")).toHaveValue(DETAIL.device.exposure);
  });

  it("saves a criticality change via PATCH /devices/{id} and shows a toast", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const updateSpy = vi.spyOn(api, "updateDevice").mockResolvedValue({
      ...DETAIL.device, criticality: "critical", services: [],
    });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    await user.selectOptions(screen.getByLabelText("Criticality"), "critical");

    expect(updateSpy).toHaveBeenCalledWith("device-insecure", { criticality: "critical" });
    expect(await screen.findByText(/criticality updated/i)).toBeInTheDocument();
  });

  it("saves an exposure change via PATCH /devices/{id} and shows a toast", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const updateSpy = vi.spyOn(api, "updateDevice").mockResolvedValue({
      ...DETAIL.device, exposure: "internet_facing", services: [],
    });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    await user.selectOptions(screen.getByLabelText("Internet exposure"), "internet_facing");

    expect(updateSpy).toHaveBeenCalledWith("device-insecure", { exposure: "internet_facing" });
    expect(await screen.findByText(/internet exposure updated/i)).toBeInTheDocument();
  });

  it("shows an error toast when saving the risk profile fails", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "updateDevice").mockRejectedValue(new ApiError("device not found", 404));
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Smart Camera — Insecure");
    await user.selectOptions(screen.getByLabelText("Criticality"), "high");

    expect(await screen.findByText("device not found")).toBeInTheDocument();
  });

  it("shows the device's risk category in the header, linking to the Risk Assessment page", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "riskDevice").mockResolvedValue({
      device_id: "device-insecure", known: true, risk_score: 62, risk_category: "high",
    });
    renderPage();

    await screen.findByText("Smart Camera — Insecure");

    const riskLink = await screen.findByRole("link", { name: /high/i });
    expect(riskLink).toHaveAttribute("href", "/risk");
  });

  it("shows no risk badge when the device has never been scored", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    // beforeEach's default mock already returns known: false.
    renderPage();

    await screen.findByText("Smart Camera — Insecure");

    expect(screen.queryByText("Risk:")).not.toBeInTheDocument();
  });

  it("shows an empty state when no assessments have been run", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText(/no assessments have been run/i)).toBeInTheDocument();
  });

  it("lists past assessments with their status, policy version, and timestamp", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "listAssessments").mockResolvedValue([
      {
        id: "ASMT-2026-07-31-0001",
        device_id: "device-insecure",
        status: "completed",
        policy_version: "1.0.0",
        started_at: "2026-07-31T10:00:00+00:00",
        completed_at: "2026-07-31T10:01:00+00:00",
        error: null,
        created_at: "2026-07-31T10:00:00+00:00",
      },
      {
        id: "ASMT-2026-07-31-0002",
        device_id: "device-insecure",
        status: "failed",
        policy_version: null,
        started_at: null,
        completed_at: null,
        error: "worker unreachable",
        created_at: "2026-07-31T11:00:00+00:00",
      },
    ]);
    renderPage();

    expect(await screen.findByText("ASMT-2026-07-31-0001")).toBeInTheDocument();
    expect(screen.getByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("policy 1.0.0")).toBeInTheDocument();
    expect(screen.getByText("ASMT-2026-07-31-0002")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("worker unreachable")).toBeInTheDocument();
    expect(screen.getByText("policy version unknown")).toBeInTheDocument();
  });

  it("expands an assessment row to lazily load and show its collector jobs", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "listAssessments").mockResolvedValue([
      {
        id: "ASMT-2026-07-31-0001",
        device_id: "device-insecure",
        status: "completed",
        policy_version: "1.0.0",
        started_at: "2026-07-31T10:00:00+00:00",
        completed_at: "2026-07-31T10:01:00+00:00",
        error: null,
        created_at: "2026-07-31T10:00:00+00:00",
      },
    ]);
    const getAssessmentSpy = vi.spyOn(api, "getAssessment").mockResolvedValue({
      id: "ASMT-2026-07-31-0001",
      device_id: "device-insecure",
      status: "completed",
      policy_version: "1.0.0",
      started_at: "2026-07-31T10:00:00+00:00",
      completed_at: "2026-07-31T10:01:00+00:00",
      error: null,
      created_at: "2026-07-31T10:00:00+00:00",
      jobs: [
        {
          id: 42,
          device_id: "device-insecure",
          test_id: "TEST-MQTT-OPEN",
          status: "recorded",
          tool: "nmap",
          tool_version: "7.94",
          command: null,
          raw_output: null,
          observations: null,
          error: null,
          evidence_id: "EV-1",
          assessment_id: "ASMT-2026-07-31-0001",
          created_at: "2026-07-31T10:00:05+00:00",
          updated_at: "2026-07-31T10:00:10+00:00",
          suggested_finding: null,
          suggested_confidence: null,
        },
      ],
    });
    renderPage();

    const row = await screen.findByRole("button", { name: /ASMT-2026-07-31-0001/ });
    await user.click(row);

    expect(getAssessmentSpy).toHaveBeenCalledWith("ASMT-2026-07-31-0001");
    expect(await screen.findByText("TEST-MQTT-OPEN")).toBeInTheDocument();
    expect(screen.getByText("#42")).toBeInTheDocument();

    // Collapsing and re-expanding must not refetch - the jobs are cached.
    await user.click(row);
    await user.click(row);
    expect(getAssessmentSpy).toHaveBeenCalledTimes(1);
  });

  it("shows the collector versions used by an expanded assessment", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "listAssessments").mockResolvedValue([
      {
        id: "ASMT-2026-07-31-0001", device_id: "device-insecure", status: "completed",
        policy_version: "1.0.0", started_at: "2026-07-31T10:00:00+00:00",
        completed_at: "2026-07-31T10:01:00+00:00", error: null, created_at: "2026-07-31T10:00:00+00:00",
      },
    ]);
    vi.spyOn(api, "getAssessment").mockResolvedValue({
      id: "ASMT-2026-07-31-0001", device_id: "device-insecure", status: "completed",
      policy_version: "1.0.0", started_at: "2026-07-31T10:00:00+00:00",
      completed_at: "2026-07-31T10:01:00+00:00", error: null, created_at: "2026-07-31T10:00:00+00:00",
      jobs: [],
      collector_versions: [{ tool: "nmap", tool_version: "7.94" }, { tool: "curl", tool_version: "8.14.1" }],
    });
    renderPage();

    await user.click(await screen.findByRole("button", { name: /ASMT-2026-07-31-0001/ }));

    expect(await screen.findByText(/nmap 7\.94/)).toBeInTheDocument();
    expect(screen.getByText(/curl 8\.14\.1/)).toBeInTheDocument();
  });

  it("doesn't show a collectors line when an assessment has no collector versions yet", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "listAssessments").mockResolvedValue([
      {
        id: "ASMT-2026-07-31-0002", device_id: "device-insecure", status: "queued",
        policy_version: null, started_at: null, completed_at: null, error: null,
        created_at: "2026-07-31T10:00:00+00:00",
      },
    ]);
    vi.spyOn(api, "getAssessment").mockResolvedValue({
      id: "ASMT-2026-07-31-0002", device_id: "device-insecure", status: "queued",
      policy_version: null, started_at: null, completed_at: null, error: null,
      created_at: "2026-07-31T10:00:00+00:00", jobs: [], collector_versions: [],
    });
    renderPage();

    await user.click(await screen.findByRole("button", { name: /ASMT-2026-07-31-0002/ }));

    await screen.findByText(/No collector jobs recorded/);
    expect(screen.queryByText(/Collectors:/)).not.toBeInTheDocument();
  });
});
