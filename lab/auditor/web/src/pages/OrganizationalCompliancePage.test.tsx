import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OrganizationalCompliancePage } from "./OrganizationalCompliancePage";
import { api, ApiError } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";
import type { NCAOrganizationalCompliance } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const ORG: NCAOrganizationalCompliance = {
  organizational_scope_id: "default",
  overall_status: "partial",
  score: 40,
  domain_summary: {
    "Cybersecurity Governance": { pass: 2, partial: 1, fail: 0, not_tested: 6, review_required: 0 },
    "Cybersecurity Defense": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
    "Cybersecurity Resilience": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
    "Third-Party and Cloud Computing Cybersecurity": { pass: 0, partial: 0, fail: 0, not_tested: 11, review_required: 0 },
  },
  readiness: {
    classification: "failed",
    score: 40,
    reasons: ["Score 40% is below the failing threshold of 50%."],
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
        id: "NCA-CGIoT-1_2024-1-1-1",
        framework: "NCA-CGIoT",
        framework_version: "1:2024",
        domain_id: "1",
        domain_name: "Cybersecurity Governance",
        subdomain_id: "1-1",
        subdomain_name: "Cybersecurity Strategy",
        guideline_id: "1-1-1",
        canonical_requirement: "Establish a cybersecurity strategy.",
        implementation_summary: "Have a strategy document.",
        source_page: "17",
        scope_type: "organization",
        assessment_type: "manual",
        required: true,
        severity: "medium",
        blocking: false,
        evidence_requirements: [],
        remediation_guidance: "",
        enabled: true,
      },
      assessment: null,
    },
    {
      control: {
        id: "NCA-CGIoT-1_2024-2-4-3",
        framework: "NCA-CGIoT",
        framework_version: "1:2024",
        domain_id: "2",
        domain_name: "Cybersecurity Defense",
        subdomain_id: "2-4",
        subdomain_name: "Secure Communications",
        guideline_id: "2-4-3",
        canonical_requirement: "Encrypt sensitive data in transit.",
        implementation_summary: "Sensitive data is encrypted in transit.",
        source_page: "18",
        scope_type: "organization",
        assessment_type: "manual",
        required: true,
        severity: "high",
        blocking: true,
        evidence_requirements: [],
        remediation_guidance: "",
        enabled: true,
      },
      assessment: null,
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <OrganizationalCompliancePage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("OrganizationalCompliancePage", () => {
  it("shows the overall organizational status and score", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    renderPage();

    expect(await screen.findByText("Partial")).toBeInTheDocument();
    expect(screen.getByText("40% informational score")).toBeInTheDocument();
  });

  it("lists organizational controls as not-assessed when no assessment exists yet", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    renderPage();

    expect(await screen.findByText("Have a strategy document.")).toBeInTheDocument();
    expect(screen.getAllByText("Not Assessed").length).toBeGreaterThanOrEqual(1);
  });

  it("flags a blocking control in the controls list", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    renderPage();

    expect(await screen.findByText("Sensitive data is encrypted in transit.")).toBeInTheDocument();
    expect(screen.getByText("blocking")).toBeInTheDocument();
  });

  it("renders an error state when organizational data fails to load", async () => {
    vi.spyOn(api, "ncaOrganization").mockRejectedValue(new Error("could not load organization"));
    renderPage();

    expect(await screen.findByText(/could not load organization/i)).toBeInTheDocument();
  });

  it("shows the progress bar with the assessed count", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    renderPage();

    expect(await screen.findByText("0 / 2 controls assessed")).toBeInTheDocument();
  });

  it("opens the guided checklist when Assess is clicked, and falls back to the plain dialog when no checklist exists", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    vi.spyOn(api, "ncaControlChecklist").mockRejectedValue(new ApiError("not found", 404));
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Have a strategy document.");
    const assessButtons = screen.getAllByRole("button", { name: /^assess$/i });
    await user.click(assessButtons[0]);

    expect(await screen.findByText(/no guided checklist/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /record assessment/i }));

    expect(await screen.findByRole("heading", { name: /^record assessment$/i })).toBeInTheDocument();
    // Organizational controls never show a device picker.
    expect(screen.queryByLabelText("Device")).not.toBeInTheDocument();
  });

  it("records an assessment via the guided flow and refreshes the page", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    vi.spyOn(api, "ncaControlChecklist").mockRejectedValue(new ApiError("not found", 404));
    const createSpy = vi.spyOn(api, "createNcaAssessment").mockResolvedValue({
      id: "ASM-9",
      control_id: "NCA-CGIoT-1_2024-1-1-1",
      device_id: null,
      organizational_scope_id: "default",
      applicability: "applicable",
      applicability_reason: null,
      status: "pass",
      severity: "medium",
      finding: "Strategy document reviewed.",
      test_method: "manual",
      test_identifier: null,
      raw_result_reference: null,
      evidence_ids: [],
      scanner_tool: null,
      scanner_tool_version: null,
      firmware_version_assessed: null,
      assessed_at: "2026-08-03T00:00:00Z",
      assessed_by: "auditor-1",
      remediation: null,
      remediation_due_date: null,
      retest_status: "not_requested",
      retested_at: null,
      superseded_by: null,
      created_at: "2026-08-03T00:00:00Z",
      attested_role: "Lead Auditor",
      attestation_confirmed: true,
      attestation_statement: "Reviewed and certified.",
      auto_recorded: false,
    });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Have a strategy document.");
    const assessButtons = screen.getAllByRole("button", { name: /^assess$/i });
    await user.click(assessButtons[0]);
    await screen.findByText(/no guided checklist/i);
    await user.click(screen.getByRole("button", { name: /record assessment/i }));

    await user.selectOptions(await screen.findByLabelText("Status"), "pass");
    await user.type(screen.getByLabelText("Finding"), "Strategy document reviewed.");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.type(screen.getByLabelText("Your role"), "Lead Auditor");
    await user.click(screen.getByLabelText("Attestation confirmation"));
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        control_id: "NCA-CGIoT-1_2024-1-1-1",
        device_id: null,
        organizational_scope_id: "default",
        status: "pass",
      }),
    );
    expect(await screen.findByText(/assessment asm-9 recorded/i)).toBeInTheDocument();
  });
});
