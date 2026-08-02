import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChecklistAssessmentPanel } from "./ChecklistAssessmentPanel";
import { api, ApiError } from "@/lib/api";
import type { NCAChecklist, NCAControl } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const CONTROL: NCAControl = {
  id: "NCA-CGIoT-1_2024-1-1-1",
  framework: "NCA-CGIoT",
  framework_version: "1:2024",
  domain_id: "1",
  domain_name: "Cybersecurity Governance",
  subdomain_id: "1-1",
  subdomain_name: "Cybersecurity Strategy",
  guideline_id: "1-1-1",
  canonical_requirement: "Define, document, and approve IoT cybersecurity requirements.",
  implementation_summary: "Define and approve an IoT cybersecurity strategy.",
  source_page: "24",
  scope_type: "organization",
  assessment_type: "manual",
  required: true,
  severity: "medium",
  blocking: false,
  evidence_requirements: [],
  remediation_guidance: "",
  enabled: true,
};

const CHECKLIST: NCAChecklist = {
  control_id: CONTROL.id,
  questions: [
    { key: "strategy_exists", label: "Does a documented IoT cybersecurity strategy exist?", type: "yes_no", required: true },
  ],
  suggestion_rule: [],
};

describe("ChecklistAssessmentPanel", () => {
  it("falls back to a plain Record assessment entry point when no checklist exists yet", async () => {
    vi.spyOn(api, "ncaControlChecklist").mockRejectedValue(new ApiError("not found", 404));
    const onContinue = vi.fn();
    render(<ChecklistAssessmentPanel control={CONTROL} onContinue={onContinue} />);

    expect(await screen.findByText(/no guided checklist/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /record assessment/i }));
    expect(onContinue).toHaveBeenCalledWith(null);
  });

  it("renders authored questions and shows a live suggestion as answers change", async () => {
    vi.spyOn(api, "ncaControlChecklist").mockResolvedValue(CHECKLIST);
    vi.spyOn(api, "evaluateNcaChecklist").mockResolvedValue({ control_id: CONTROL.id, suggested_status: "pass" });
    const user = userEvent.setup();
    render(<ChecklistAssessmentPanel control={CONTROL} onContinue={() => {}} />);

    const question = await screen.findByLabelText(/does a documented iot cybersecurity strategy exist/i);
    await user.selectOptions(question, "true");

    expect(await screen.findByText(/suggested from your answers: pass/i)).toBeInTheDocument();
  });

  it("continues with a suggestion built from the answers given", async () => {
    vi.spyOn(api, "ncaControlChecklist").mockResolvedValue(CHECKLIST);
    vi.spyOn(api, "evaluateNcaChecklist").mockResolvedValue({ control_id: CONTROL.id, suggested_status: "pass" });
    const onContinue = vi.fn();
    const user = userEvent.setup();
    render(<ChecklistAssessmentPanel control={CONTROL} onContinue={onContinue} />);

    const question = await screen.findByLabelText(/does a documented iot cybersecurity strategy exist/i);
    await user.selectOptions(question, "true");
    await screen.findByText(/suggested from your answers: pass/i);

    await user.click(screen.getByRole("button", { name: /continue to assessment/i }));

    expect(onContinue).toHaveBeenCalledWith(
      expect.objectContaining({
        control_id: CONTROL.id,
        suggested_status: "pass",
        reasons: expect.arrayContaining([expect.stringContaining("strategy exist")]),
      }),
    );
  });

  it("requires a name before attaching a document", async () => {
    vi.spyOn(api, "ncaControlChecklist").mockResolvedValue(CHECKLIST);
    const uploadSpy = vi.spyOn(api, "uploadNcaComplianceDocument");
    const user = userEvent.setup();
    render(<ChecklistAssessmentPanel control={CONTROL} onContinue={() => {}} />);

    await screen.findByLabelText(/does a documented iot cybersecurity strategy exist/i);
    const file = new File(["policy text"], "policy.pdf", { type: "application/pdf" });
    await user.upload(screen.getByLabelText(/attach document evidence/i), file);

    expect(await screen.findByText(/enter your name/i)).toBeInTheDocument();
    expect(uploadSpy).not.toHaveBeenCalled();
  });

  it("uploads a document once a name is given, and includes it in the suggestion", async () => {
    vi.spyOn(api, "ncaControlChecklist").mockResolvedValue(CHECKLIST);
    vi.spyOn(api, "uploadNcaComplianceDocument").mockResolvedValue({
      id: "CEV-1",
      assessment_id: null,
      evidence_type: "document",
      linked_evidence_id: null,
      original_filename: "policy.pdf",
      object_reference: "document-store/compliance/CEV-1-policy.pdf",
      sha256: "abc123",
      collected_at: "2026-08-03T00:00:00Z",
      collected_by: "auditor-1",
      source_system: "iotguard",
      retention_expires_at: null,
      access_control_note: "internal-audit-only",
      created_at: "2026-08-03T00:00:00Z",
    });
    const onContinue = vi.fn();
    const user = userEvent.setup();
    render(<ChecklistAssessmentPanel control={CONTROL} onContinue={onContinue} />);

    await screen.findByLabelText(/does a documented iot cybersecurity strategy exist/i);
    await user.type(screen.getByLabelText(/your name \(for the document evidence record\)/i), "auditor-1");
    const file = new File(["policy text"], "policy.pdf", { type: "application/pdf" });
    await user.upload(screen.getByLabelText(/attach document evidence/i), file);

    await waitFor(() => expect(screen.getByText(/attached: policy\.pdf/i)).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /continue to assessment/i }));
    expect(onContinue).toHaveBeenCalledWith(
      expect.objectContaining({ evidence_ids: ["CEV-1"] }),
    );
  });
});
