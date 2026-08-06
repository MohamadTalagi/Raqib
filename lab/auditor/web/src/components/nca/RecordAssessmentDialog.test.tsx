import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RecordAssessmentDialog } from "./RecordAssessmentDialog";
import { api } from "@/lib/api";
import type { Device, NCAAssessment, NCAControl } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

async function signOff(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Your role"), "Lead Auditor");
  await user.click(screen.getByLabelText("Attestation confirmation"));
}

const DEVICE_CONTROL: NCAControl = {
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
};

const ORG_CONTROL: NCAControl = {
  ...DEVICE_CONTROL,
  id: "NCA-CGIoT-1_2024-1-1-1",
  guideline_id: "1-1-1",
  domain_name: "Cybersecurity Governance",
  scope_type: "organization",
};

const DEVICES: Device[] = [
  {
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
    firmware_version: null,
    identity_source: "manual",
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [],
  },
];

const EXISTING: NCAAssessment = {
  id: "ASM-1",
  control_id: DEVICE_CONTROL.id,
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
  evidence_ids: ["EV-1"],
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
  attested_role: "Lead Auditor",
  attestation_confirmed: true,
  attestation_statement: "Reviewed and certified.",
  auto_recorded: false,
};

describe("RecordAssessmentDialog", () => {
  it("renders nothing when closed", () => {
    render(
      <RecordAssessmentDialog
        open={false}
        control={DEVICE_CONTROL}
        devices={DEVICES}
        onSaved={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("requires a device for a device-scoped control and creates the assessment on submit", async () => {
    const createSpy = vi.spyOn(api, "createNcaAssessment").mockResolvedValue({
      ...EXISTING,
      id: "ASM-2",
      status: "pass",
    });
    const onSaved = vi.fn();
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog
        open
        control={DEVICE_CONTROL}
        devices={DEVICES}
        onSaved={onSaved}
        onCancel={() => {}}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.selectOptions(screen.getByLabelText("Status"), "pass");
    await user.type(screen.getByLabelText("Finding"), "Unique password enforced on first boot.");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        control_id: DEVICE_CONTROL.id,
        device_id: "device-insecure",
        organizational_scope_id: null,
        status: "pass",
        finding: "Unique password enforced on first boot.",
        assessed_by: "auditor-1",
        attested_role: "Lead Auditor",
        attestation_confirmed: true,
      }),
    );
    expect(onSaved).toHaveBeenCalled();
  });

  it("rejects submission without a device when the control is device-scoped", async () => {
    const createSpy = vi.spyOn(api, "createNcaAssessment");
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={DEVICE_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    await user.selectOptions(screen.getByLabelText("Status"), "pass");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(await screen.findByText(/choose a device/i)).toBeInTheDocument();
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("records against the default organizational scope for an organization-scoped control, with no device picker", async () => {
    const createSpy = vi.spyOn(api, "createNcaAssessment").mockResolvedValue(EXISTING);
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    expect(screen.queryByLabelText("Device")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Status"), "fail");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        control_id: ORG_CONTROL.id,
        device_id: null,
        organizational_scope_id: "default",
        status: "fail",
      }),
    );
  });

  it("requires an applicability reason when marking a control not applicable", async () => {
    const createSpy = vi.spyOn(api, "createNcaAssessment");
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    await user.selectOptions(screen.getByLabelText("Applicability"), "not_applicable");
    await user.selectOptions(screen.getByLabelText("Status"), "not_tested");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(await screen.findByText(/why doesn't this apply/i)).toBeInTheDocument();
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("pre-fills from an existing assessment and submits a retest instead of a new assessment", async () => {
    const retestSpy = vi.spyOn(api, "retestNcaAssessment").mockResolvedValue({ ...EXISTING, id: "ASM-3", status: "pass" });
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog
        open
        control={DEVICE_CONTROL}
        devices={DEVICES}
        existingAssessment={EXISTING}
        onSaved={() => {}}
        onCancel={() => {}}
      />,
    );

    expect(screen.getByRole("heading", { name: /retest assessment/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Finding")).toHaveValue("default creds accepted");
    expect(screen.getByLabelText("Device")).toBeDisabled();

    await user.clear(screen.getByLabelText("Finding"));
    await user.type(screen.getByLabelText("Finding"), "Password now unique per device.");
    await user.selectOptions(screen.getByLabelText("Status"), "pass");
    await user.type(screen.getByLabelText("Your name"), "auditor-2");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save retest/i }));

    expect(retestSpy).toHaveBeenCalledWith(
      "ASM-1",
      expect.objectContaining({ status: "pass", finding: "Password now unique per device.", assessed_by: "auditor-2" }),
    );
  });

  it("pre-fills a suggested status, evidence ids, and automated method from an auto-verdict suggestion", async () => {
    const createSpy = vi.spyOn(api, "createNcaAssessment").mockResolvedValue({ ...EXISTING, id: "ASM-9" });
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog
        open
        control={DEVICE_CONTROL}
        devices={DEVICES}
        initialDeviceId="device-insecure"
        suggestion={{
          control_id: DEVICE_CONTROL.id,
          suggested_status: "fail",
          evidence_ids: ["EV-SUG-1"],
          test_ids: ["TEST-AUTH-DEFAULT-CREDS"],
          reasons: ["Default credential accepted. (evidence EV-SUG-1)"],
        }}
        onSaved={() => {}}
        onCancel={() => {}}
      />,
    );

    // Banner is shown and fields are pre-filled from the suggestion.
    expect(screen.getByText(/suggested from automated evidence/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Status")).toHaveValue("fail");
    expect(screen.getByLabelText("Test method")).toHaveValue("automated");
    expect(screen.getByLabelText("Linked evidence ids")).toHaveValue("EV-SUG-1");

    // Auditor still records the finding + their name, then confirms.
    await user.type(screen.getByLabelText("Finding"), "Confirmed: admin:admin accepted.");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        control_id: DEVICE_CONTROL.id,
        device_id: "device-insecure",
        status: "fail",
        test_method: "automated",
        evidence_ids: ["EV-SUG-1"],
      }),
    );
  });

  it("ignores a suggestion when retesting an existing assessment", () => {
    render(
      <RecordAssessmentDialog
        open
        control={DEVICE_CONTROL}
        devices={DEVICES}
        existingAssessment={EXISTING}
        suggestion={{
          control_id: DEVICE_CONTROL.id,
          suggested_status: "review_required",
          evidence_ids: ["EV-OTHER"],
          test_ids: [],
          reasons: ["should be ignored on retest"],
        }}
        onSaved={() => {}}
        onCancel={() => {}}
      />,
    );

    expect(screen.queryByText(/suggested from automated evidence/i)).not.toBeInTheDocument();
    // Retest keeps the prior assessment's own recorded values, not the suggestion's.
    expect(screen.getByLabelText("Status")).toHaveValue("fail");
  });

  it("surfaces the API error message on failure", async () => {
    vi.spyOn(api, "createNcaAssessment").mockRejectedValue(new Error("network down"));
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    await user.selectOptions(screen.getByLabelText("Status"), "fail");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await signOff(user);
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(await screen.findByText(/could not save the assessment/i)).toBeInTheDocument();
  });

  it("disables Save until a role is entered and the attestation checkbox is checked", async () => {
    const createSpy = vi.spyOn(api, "createNcaAssessment").mockResolvedValue(EXISTING);
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    await user.selectOptions(screen.getByLabelText("Status"), "fail");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    const saveButton = screen.getByRole("button", { name: /save assessment/i });
    expect(saveButton).toBeDisabled();

    await user.type(screen.getByLabelText("Your role"), "Lead Auditor");
    expect(saveButton).toBeDisabled();

    await user.click(screen.getByLabelText("Attestation confirmation"));
    expect(saveButton).toBeEnabled();

    await user.click(saveButton);
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        attested_role: "Lead Auditor",
        attestation_confirmed: true,
        attestation_statement: expect.stringContaining("reviewed the evidence"),
      }),
    );
  });

  it("resets the sign-off fields every time the dialog opens, including on retest", () => {
    render(
      <RecordAssessmentDialog
        open
        control={DEVICE_CONTROL}
        devices={DEVICES}
        existingAssessment={EXISTING}
        onSaved={() => {}}
        onCancel={() => {}}
      />,
    );

    expect(screen.getByLabelText("Your role")).toHaveValue("");
    expect(screen.getByLabelText("Attestation confirmation")).not.toBeChecked();
  });

  it("calls onCancel when Cancel is clicked", async () => {
    const onCancel = vi.fn();
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={onCancel} />,
    );
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });
});
