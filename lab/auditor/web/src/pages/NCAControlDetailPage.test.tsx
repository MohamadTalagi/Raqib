import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NCAControlDetailPage } from "./NCAControlDetailPage";
import { api } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";
import type { Device, NCAControlDetail, NCAException } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const REGISTERED_DEVICE: Device = {
  device_id: "device-insecure",
  display_name: "Smart Camera — Insecure",
  description: "",
  tier: "insecure",
  host: "device-insecure",
  vendor: null,
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
  registered: true,
  evidence_count: 0,
  verdict_count: 0,
  services: [],
};

const CONTROL_ID = "NCA-CGIoT-1_2024-2-2-2";

const DETAIL: NCAControlDetail = {
  control: {
    id: CONTROL_ID,
    framework: "NCA-CGIoT",
    framework_version: "1:2024",
    domain_id: "2",
    domain_name: "Cybersecurity Defense",
    subdomain_id: "2-2",
    subdomain_name: "Access and Permission Restriction",
    guideline_id: "2-2-2",
    canonical_requirement: "Do not use default or hard-coded passwords.",
    implementation_summary: "No default creds.",
    source_page: "17-23",
    scope_type: "device",
    assessment_type: "automated",
    required: true,
    severity: "high",
    blocking: true,
    evidence_requirements: [],
    remediation_guidance: "Force a unique password on first boot.",
    enabled: true,
  },
  assessments: [
    {
      id: "ASM-1",
      control_id: CONTROL_ID,
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
      remediation: null,
      remediation_due_date: null,
      retest_status: "not_requested",
      retested_at: null,
      superseded_by: null,
      created_at: "2026-07-20T00:00:00Z",
    },
  ],
  audit_events: [
    {
      id: 1,
      event_type: "assessment_superseded",
      entity_type: "compliance_assessment",
      entity_id: "ASM-2",
      before_value: { status: "fail" },
      after_value: { status: "pass" },
      actor: "reviewer-2",
      reason: "credentials rotated",
      occurred_at: "2026-07-21T00:00:00Z",
    },
  ],
};

function renderPage(initialPath = `/nca-compliance/controls/${CONTROL_ID}`) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <ToastProvider>
        <Routes>
          <Route path="/nca-compliance/controls/:controlId" element={<NCAControlDetailPage />} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("NCAControlDetailPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "devices").mockResolvedValue([REGISTERED_DEVICE]);
    vi.spyOn(api, "ncaExceptions").mockResolvedValue([]);
  });

  it("shows the guideline text, classification, and remediation guidance", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("Do not use default or hard-coded passwords.")).toBeInTheDocument();
    expect(screen.getByText("device")).toBeInTheDocument();
    expect(screen.getByText("automated")).toBeInTheDocument();
    expect(screen.getByText("Force a unique password on first boot.")).toBeInTheDocument();
  });

  it("lists assessments with device links and reviewer identity", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("default creds accepted")).toBeInTheDocument();
    expect(screen.getByText("reviewer-1")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /device-insecure/ });
    expect(link).toHaveAttribute("href", "/devices/device-insecure");
  });

  it("shows the audit trail for reassessments", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("assessment_superseded")).toBeInTheDocument();
    expect(screen.getByText("reviewer-2")).toBeInTheDocument();
    expect(screen.getByText("credentials rotated")).toBeInTheDocument();
  });

  it("renders an error state when the control fails to load", async () => {
    vi.spyOn(api, "ncaControl").mockRejectedValue(new Error("control not found"));
    renderPage();

    expect(await screen.findByText(/control not found/i)).toBeInTheDocument();
  });

  it("opens the Record assessment dialog and records a new assessment", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    vi.spyOn(api, "createNcaAssessment").mockResolvedValue({
      ...DETAIL.assessments[0],
      id: "ASM-9",
      status: "pass",
    });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Do not use default or hard-coded passwords.");
    await user.click(screen.getByRole("button", { name: /^record assessment$/i }));

    expect(screen.getByRole("heading", { name: /^record assessment$/i })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.selectOptions(screen.getByLabelText("Status"), "pass");
    await user.type(screen.getByLabelText("Your name"), "auditor-3");
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(await screen.findByText(/assessment asm-9 recorded/i)).toBeInTheDocument();
  });

  it("pre-fills the device from the ?device_id= query param when navigated from a device's Compliance tab", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    const user = userEvent.setup();
    renderPage(`/nca-compliance/controls/${CONTROL_ID}?device_id=device-insecure`);

    await screen.findByText("Do not use default or hard-coded passwords.");
    await user.click(screen.getByRole("button", { name: /^record assessment$/i }));

    expect(screen.getByLabelText("Device")).toHaveValue("device-insecure");
  });

  it("opens a Retest dialog pre-filled from the current assessment", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("default creds accepted");
    await user.click(screen.getByRole("button", { name: /^retest$/i }));

    expect(screen.getByRole("heading", { name: /retest assessment/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Finding")).toHaveValue("default creds accepted");
  });

  it("shows a Request exception button and records a new exception", async () => {
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    vi.spyOn(api, "createNcaException").mockResolvedValue({
      id: "EXC-5",
      control_id: CONTROL_ID,
      device_id: "device-insecure",
      organizational_scope_id: null,
      reason: "Compensating control in place.",
      compensating_control: null,
      requested_by: "auditor-4",
      approved_by: null,
      approved_at: null,
      status: "pending",
      expires_at: "2026-12-31",
      created_at: "2026-07-24T00:00:00Z",
    });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Do not use default or hard-coded passwords.");
    await user.click(screen.getByRole("button", { name: /request exception/i }));
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.type(screen.getByLabelText("Reason"), "Compensating control in place.");
    await user.type(screen.getByLabelText("Expires on"), "2026-12-31");
    await user.type(screen.getByLabelText("Your name"), "auditor-4");
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: /^request exception$/i }));

    expect(await screen.findByText(/exception exc-5 requested/i)).toBeInTheDocument();
  });

  it("lists existing exceptions and lets a pending one be approved with a reviewer name", async () => {
    const pendingException: NCAException = {
      id: "EXC-1",
      control_id: CONTROL_ID,
      device_id: "device-insecure",
      organizational_scope_id: null,
      reason: "Awaiting patch from vendor.",
      compensating_control: null,
      requested_by: "auditor-1",
      approved_by: null,
      approved_at: null,
      status: "pending",
      expires_at: "2026-12-31",
      created_at: "2026-07-20T00:00:00Z",
    };
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    vi.spyOn(api, "ncaExceptions").mockResolvedValue([pendingException]);
    const approveSpy = vi.spyOn(api, "approveNcaException").mockResolvedValue({
      ...pendingException,
      status: "approved",
      approved_by: "auditor-5",
    });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Awaiting patch from vendor.")).toBeInTheDocument();
    await user.type(screen.getByLabelText(/reviewer name for exception approval/i), "auditor-5");
    await user.click(screen.getByRole("button", { name: /^approve$/i }));

    expect(approveSpy).toHaveBeenCalledWith("EXC-1", "auditor-5");
  });

  it("requires a reviewer name before approving or rejecting an exception", async () => {
    const pendingException: NCAException = {
      id: "EXC-1",
      control_id: CONTROL_ID,
      device_id: "device-insecure",
      organizational_scope_id: null,
      reason: "Awaiting patch from vendor.",
      compensating_control: null,
      requested_by: "auditor-1",
      approved_by: null,
      approved_at: null,
      status: "pending",
      expires_at: "2026-12-31",
      created_at: "2026-07-20T00:00:00Z",
    };
    vi.spyOn(api, "ncaControl").mockResolvedValue(DETAIL);
    vi.spyOn(api, "ncaExceptions").mockResolvedValue([pendingException]);
    const approveSpy = vi.spyOn(api, "approveNcaException");
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Awaiting patch from vendor.");
    await user.click(screen.getByRole("button", { name: /^approve$/i }));

    expect(await screen.findByText(/enter your name/i)).toBeInTheDocument();
    expect(approveSpy).not.toHaveBeenCalled();
  });
});
