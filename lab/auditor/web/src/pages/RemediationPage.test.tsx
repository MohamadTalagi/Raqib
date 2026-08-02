import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RemediationPage } from "./RemediationPage";
import { api } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";
import type { NCAAssessment, RemediationBlueprint, VerdictRecord } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const FAILING_VERDICT: VerdictRecord = {
  verdict_id: "VD-1",
  control_id: "SA-IOT-002",
  device_id: "device-insecure",
  status: "FAIL",
  severity: "critical",
  evidence_ids: [],
  matched: "fail",
  reason: "observations.default_creds equals True",
  saudi_source: "CGIoT-1:2024 §2-2-2",
  remediation: "Force a unique password on first boot.",
  timestamp: "2026-07-08T08:58:42Z",
  assessment_id: null,
  policy_version: "1.0.0",
  conflict_detected: false,
  conflict_reason: null,
};

const PASSING_VERDICT: VerdictRecord = {
  ...FAILING_VERDICT,
  verdict_id: "VD-2",
  control_id: "SA-IOT-003",
  device_id: "device-hardened",
  status: "PASS",
};

const FAILING_NCA_ASSESSMENT: NCAAssessment = {
  id: "ASM-1",
  control_id: "NCA-CGIoT-1_2024-2-2-2",
  device_id: "device-insecure",
  organizational_scope_id: null,
  applicability: "applicable",
  applicability_reason: null,
  status: "fail",
  severity: "high",
  finding: "Default credentials accepted on login.",
  test_method: "automated",
  test_identifier: null,
  raw_result_reference: null,
  evidence_ids: [],
  scanner_tool: null,
  scanner_tool_version: null,
  firmware_version_assessed: null,
  assessed_at: "2026-08-02T00:00:00Z",
  assessed_by: "reviewer",
  remediation: null,
  remediation_due_date: null,
  retest_status: "not_requested",
  retested_at: null,
  superseded_by: null,
  created_at: "2026-08-02T00:00:00Z",
  attested_role: "Lead Auditor",
  attestation_confirmed: true,
  attestation_statement: "Reviewed and certified.",
  auto_recorded: false,
};

const BLUEPRINT: RemediationBlueprint = {
  id: "RB-1",
  finding_type: "sa_iot_verdict",
  finding_id: "VD-1",
  device_id: "device-insecure",
  control_id: "SA-IOT-002",
  model: "gemini-3.5-flash-lite",
  root_cause: "Default credentials were never rotated.",
  remediation_steps: ["Force a password change on first boot.", "Disable the default account."],
  priority: "immediate",
  estimated_effort: "Low",
  caveats: "Confirm no automation depends on the default account.",
  generated_at: "2026-08-02T00:00:00Z",
  reviewed: false,
  reviewed_by: null,
  reviewed_at: null,
  superseded_by: null,
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <RemediationPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function mockEmpty() {
  vi.spyOn(api, "verdicts").mockResolvedValue([]);
  vi.spyOn(api, "ncaAssessments").mockResolvedValue([]);
  vi.spyOn(api, "allRemediationBlueprints").mockResolvedValue([]);
}

describe("RemediationPage", () => {
  it("shows an empty state when nothing is currently failing or partial", async () => {
    mockEmpty();
    renderPage();
    expect(await screen.findByText(/nothing to remediate/i)).toBeInTheDocument();
  });

  it("lists failing SA-IOT verdicts and NCA assessments, not passing ones", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([FAILING_VERDICT, PASSING_VERDICT]);
    vi.spyOn(api, "ncaAssessments").mockResolvedValue([FAILING_NCA_ASSESSMENT]);
    vi.spyOn(api, "allRemediationBlueprints").mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText("Currently failing or partial findings (2)")).toBeInTheDocument();
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("NCA-CGIoT-1_2024-2-2-2")).toBeInTheDocument();
    expect(screen.queryByText("SA-IOT-003")).not.toBeInTheDocument();
  });

  it("generates a blueprint when clicked and shows it once returned", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([FAILING_VERDICT]);
    vi.spyOn(api, "ncaAssessments").mockResolvedValue([]);
    const blueprintsSpy = vi
      .spyOn(api, "allRemediationBlueprints")
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([BLUEPRINT]);
    const generateSpy = vi.spyOn(api, "generateRemediation").mockResolvedValue(BLUEPRINT);
    const user = userEvent.setup();
    renderPage();

    const generateButton = await screen.findByRole("button", { name: /generate ai remediation/i });
    await user.click(generateButton);

    expect(generateSpy).toHaveBeenCalledWith("sa_iot_verdict", "VD-1");
    await waitFor(() => expect(blueprintsSpy).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Default credentials were never rotated.")).toBeInTheDocument();
    expect(screen.getByText("Force a password change on first boot.")).toBeInTheDocument();
    expect(screen.getByText(/ai-generated/i)).toBeInTheDocument();
  });

  it("shows a row error and never a fabricated blueprint when generation fails", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([FAILING_VERDICT]);
    vi.spyOn(api, "ncaAssessments").mockResolvedValue([]);
    vi.spyOn(api, "allRemediationBlueprints").mockResolvedValue([]);
    const { ApiError } = await import("@/lib/api");
    vi.spyOn(api, "generateRemediation").mockRejectedValue(
      new ApiError("Gemini did not return a usable response - check GEMINI_API_KEY/quota and try again", 502),
    );
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: /generate ai remediation/i }));

    expect(await screen.findByText(/gemini did not return a usable response/i)).toBeInTheDocument();
  });

  it("disables Mark reviewed until a reviewer name is entered, then marks it reviewed", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([FAILING_VERDICT]);
    vi.spyOn(api, "ncaAssessments").mockResolvedValue([]);
    vi.spyOn(api, "allRemediationBlueprints").mockResolvedValue([BLUEPRINT]);
    const reviewSpy = vi.spyOn(api, "reviewRemediationBlueprint").mockResolvedValue({
      ...BLUEPRINT,
      reviewed: true,
      reviewed_by: "Lead Auditor",
      reviewed_at: "2026-08-02T01:00:00Z",
    });
    const user = userEvent.setup();
    renderPage();

    const reviewButton = await screen.findByRole("button", { name: /mark reviewed/i });
    expect(reviewButton).toBeDisabled();

    await user.type(screen.getByLabelText(/your name, to mark generated blueprints reviewed/i), "Lead Auditor");
    expect(reviewButton).toBeEnabled();

    await user.click(reviewButton);
    expect(reviewSpy).toHaveBeenCalledWith("RB-1", "Lead Auditor");
  });

  it("Generate all missing is disabled once every failing finding already has a blueprint", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([FAILING_VERDICT]);
    vi.spyOn(api, "ncaAssessments").mockResolvedValue([]);
    vi.spyOn(api, "allRemediationBlueprints").mockResolvedValue([BLUEPRINT]);
    renderPage();

    const bulkButton = await screen.findByRole("button", { name: /generate all missing \(0\)/i });
    expect(bulkButton).toBeDisabled();
  });
});
