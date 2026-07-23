import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RecordAssessmentDialog } from "./RecordAssessmentDialog";
import { api } from "@/lib/api";
import type { Device, NCAAssessment, NCAControl } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

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
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        control_id: DEVICE_CONTROL.id,
        device_id: "device-insecure",
        organizational_scope_id: null,
        status: "pass",
        finding: "Unique password enforced on first boot.",
        assessed_by: "auditor-1",
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
    await user.click(screen.getByRole("button", { name: /save retest/i }));

    expect(retestSpy).toHaveBeenCalledWith(
      "ASM-1",
      expect.objectContaining({ status: "pass", finding: "Password now unique per device.", assessed_by: "auditor-2" }),
    );
  });

  it("surfaces the API error message on failure", async () => {
    vi.spyOn(api, "createNcaAssessment").mockRejectedValue(new Error("network down"));
    const user = userEvent.setup();

    render(
      <RecordAssessmentDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    await user.selectOptions(screen.getByLabelText("Status"), "fail");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /save assessment/i }));

    expect(await screen.findByText(/could not save the assessment/i)).toBeInTheDocument();
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
