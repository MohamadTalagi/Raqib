import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceAssessmentPage } from "./DeviceAssessmentPage";
import { api } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";
import type { Device, NCAControl, NCADeviceDetail, NCADeviceSuggestions } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICE_ID = "device-insecure";

function control(overrides: Partial<NCAControl> & { id: string; guideline_id: string }): NCAControl {
  return {
    framework: "NCA-CGIoT",
    framework_version: "1:2024",
    domain_id: "2",
    domain_name: "Cybersecurity Defense",
    subdomain_id: "2-2",
    subdomain_name: "Access and Permission Restriction",
    canonical_requirement: "req",
    implementation_summary: "summary",
    source_page: "17",
    scope_type: "device",
    assessment_type: "automated",
    required: true,
    severity: "high",
    blocking: false,
    evidence_requirements: [],
    remediation_guidance: "",
    enabled: true,
    ...overrides,
  };
}

const CREDS_ID = "NCA-CGIoT-1_2024-2-2-2";
const TELNET_ID = "NCA-CGIoT-1_2024-2-15-2";

const DETAIL: NCADeviceDetail = {
  device_id: DEVICE_ID,
  display_name: "Smart Camera — Insecure",
  tier: "insecure",
  overall_status: "fail",
  score: 20,
  domain_summary: {},
  readiness: {
    classification: "failed",
    score: 20,
    reasons: ["A blocking control failed."],
    blocking_control_ids: [CREDS_ID],
    critical_failure_control_ids: [],
    not_tested_control_ids: [],
    review_required_control_ids: [],
    pass_threshold: 85,
    partial_threshold: 50,
  },
  controls: [
    {
      control: control({ id: CREDS_ID, guideline_id: "2-2-2", blocking: true }),
      assessment: null,
    },
    {
      control: control({ id: TELNET_ID, guideline_id: "2-15-2", implementation_summary: "No Telnet." }),
      assessment: {
        id: "ASM-1",
        control_id: TELNET_ID,
        device_id: DEVICE_ID,
        organizational_scope_id: null,
        applicability: "applicable",
        applicability_reason: null,
        status: "pass",
        severity: "high",
        finding: "Telnet not exposed.",
        test_method: "automated",
        test_identifier: "TEST-NET-PORTSCAN",
        raw_result_reference: null,
        evidence_ids: [],
        scanner_tool: null,
        scanner_tool_version: null,
        firmware_version_assessed: null,
        assessed_at: "2026-07-20T00:00:00Z",
        assessed_by: "auditor-1",
        remediation: null,
        remediation_due_date: null,
        retest_status: "not_requested",
        retested_at: null,
        superseded_by: null,
        created_at: "2026-07-20T00:00:00Z",
        attested_role: "Lead Auditor",
        attestation_confirmed: true,
        attestation_statement: "Reviewed and certified.",
        auto_recorded: false,
      },
    },
  ],
  exceptions: [],
};

const SUGGESTIONS: NCADeviceSuggestions = {
  device_id: DEVICE_ID,
  suggestions: {
    [CREDS_ID]: {
      control_id: CREDS_ID,
      suggested_status: "fail",
      evidence_ids: ["EV-1"],
      test_ids: ["TEST-AUTH-DEFAULT-CREDS"],
      reasons: ["Default credential accepted. (evidence EV-1)"],
    },
  },
};

const DEVICE: Device = {
  device_id: DEVICE_ID,
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
  firmware_version: null,
  identity_source: "manual",
  criticality: "medium",
  exposure: "internal_only",
  registered: true,
  evidence_count: 0,
  verdict_count: 0,
  services: [],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={[`/nca-compliance/devices/${DEVICE_ID}`]}>
      <ToastProvider>
        <Routes>
          <Route path="/nca-compliance/devices/:deviceId" element={<DeviceAssessmentPage />} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("DeviceAssessmentPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "ncaDevice").mockResolvedValue(DETAIL);
    vi.spyOn(api, "ncaDeviceSuggestions").mockResolvedValue(SUGGESTIONS);
    vi.spyOn(api, "devices").mockResolvedValue([DEVICE]);
  });

  it("shows progress: one of two controls assessed", async () => {
    renderPage();
    expect(await screen.findByText("1 / 2 controls assessed")).toBeInTheDocument();
  });

  it("shows a suggestion chip on the unassessed, mapped control only", async () => {
    renderPage();
    // The creds control is unassessed and has a suggestion.
    expect(await screen.findByText(/suggests fail/i)).toBeInTheDocument();
    // Exactly one suggestion chip (the passed Telnet control has none).
    expect(screen.getAllByText(/suggests/i)).toHaveLength(1);
  });

  it("opens the record dialog pre-filled from the suggestion when Record is clicked", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("1 / 2 controls assessed");
    // Exact match, not /record/i - "Auto-recorded" (the new filter tab added
    // alongside this test) also matches a loose substring regex.
    await user.click(screen.getAllByRole("button", { name: "Record" })[0]);

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/suggested from automated evidence/i)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Status")).toHaveValue("fail");
  });

  it("filters to unassessed controls", async () => {
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("1 / 2 controls assessed");
    await user.click(screen.getByRole("button", { name: /^Unassessed/ }));

    // The passed Telnet control's summary disappears; the creds one stays.
    expect(screen.queryByText("No Telnet.")).not.toBeInTheDocument();
    expect(screen.getByText(/suggests fail/i)).toBeInTheDocument();
  });

  it("renders an error state when the device fails to load", async () => {
    vi.spyOn(api, "ncaDevice").mockRejectedValue(new Error("device not found"));
    renderPage();
    expect(await screen.findByText(/device not found/i)).toBeInTheDocument();
  });
});
