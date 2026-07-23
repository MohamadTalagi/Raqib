import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NCAControlDetailPage } from "./NCAControlDetailPage";
import { api } from "@/lib/api";
import type { NCAControlDetail } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

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

function renderPage() {
  return render(
    <MemoryRouter initialEntries={[`/nca-compliance/controls/${CONTROL_ID}`]}>
      <Routes>
        <Route path="/nca-compliance/controls/:controlId" element={<NCAControlDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("NCAControlDetailPage", () => {
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
});
