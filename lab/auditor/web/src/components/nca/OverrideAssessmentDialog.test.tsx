import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OverrideAssessmentDialog } from "./OverrideAssessmentDialog";
import { api } from "@/lib/api";
import type { NCAAssessment, NCAStatus } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const ASSESSMENT: NCAAssessment = {
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
};

const OVERRIDDEN: NCAAssessment & { original_status: NCAStatus; override_justification: string } = {
  ...ASSESSMENT,
  id: "ASM-2",
  status: "pass",
  assessed_by: "auditor-1",
  original_status: "fail",
  override_justification: "compensating network segmentation verified on-site",
};

describe("OverrideAssessmentDialog", () => {
  it("renders nothing when closed", () => {
    render(
      <OverrideAssessmentDialog open={false} assessment={ASSESSMENT} onSaved={() => {}} onCancel={() => {}} />,
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows the current result and requires a justification before submitting", async () => {
    const overrideSpy = vi.spyOn(api, "overrideNcaAssessment");
    const user = userEvent.setup();

    render(<OverrideAssessmentDialog open assessment={ASSESSMENT} onSaved={() => {}} onCancel={() => {}} />);

    expect(screen.getByText("Fail")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /save override/i }));

    expect(await screen.findByText(/written justification is required/i)).toBeInTheDocument();
    expect(overrideSpy).not.toHaveBeenCalled();
  });

  it("requires the auditor's name before submitting", async () => {
    const overrideSpy = vi.spyOn(api, "overrideNcaAssessment");
    const user = userEvent.setup();

    render(<OverrideAssessmentDialog open assessment={ASSESSMENT} onSaved={() => {}} onCancel={() => {}} />);

    await user.type(screen.getByLabelText("Written justification"), "risk accepted after review");
    await user.click(screen.getByRole("button", { name: /save override/i }));

    expect(await screen.findByText(/your name.*is required/i)).toBeInTheDocument();
    expect(overrideSpy).not.toHaveBeenCalled();
  });

  it("submits the override with status, justification, and auditor identity", async () => {
    const overrideSpy = vi.spyOn(api, "overrideNcaAssessment").mockResolvedValue(OVERRIDDEN);
    const onSaved = vi.fn();
    const user = userEvent.setup();

    render(<OverrideAssessmentDialog open assessment={ASSESSMENT} onSaved={onSaved} onCancel={() => {}} />);

    await user.selectOptions(screen.getByLabelText("New status"), "pass");
    await user.type(
      screen.getByLabelText("Written justification"),
      "compensating network segmentation verified on-site",
    );
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /save override/i }));

    expect(overrideSpy).toHaveBeenCalledWith("ASM-1", {
      status: "pass",
      justification: "compensating network segmentation verified on-site",
      overridden_by: "auditor-1",
      original_status: "fail",
    });
    expect(onSaved).toHaveBeenCalledWith(OVERRIDDEN);
  });

  it("surfaces an API error instead of silently failing", async () => {
    vi.spyOn(api, "overrideNcaAssessment").mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();

    render(<OverrideAssessmentDialog open assessment={ASSESSMENT} onSaved={() => {}} onCancel={() => {}} />);

    await user.type(screen.getByLabelText("Written justification"), "reason");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /save override/i }));

    expect(await screen.findByText(/could not save the override/i)).toBeInTheDocument();
  });
});
