import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RequestExceptionDialog } from "./RequestExceptionDialog";
import { api } from "@/lib/api";
import type { Device, NCAControl, NCAException } from "@/lib/types";

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

const ORG_CONTROL: NCAControl = { ...DEVICE_CONTROL, scope_type: "organization" };

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

const SAVED: NCAException = {
  id: "EXC-1",
  control_id: DEVICE_CONTROL.id,
  device_id: "device-insecure",
  organizational_scope_id: null,
  reason: "Compensating firewall rule in place.",
  compensating_control: "VLAN isolation",
  requested_by: "auditor-1",
  approved_by: null,
  approved_at: null,
  status: "pending",
  expires_at: "2026-12-31",
  created_at: "2026-07-24T00:00:00Z",
};

describe("RequestExceptionDialog", () => {
  it("renders nothing when closed", () => {
    render(
      <RequestExceptionDialog open={false} control={DEVICE_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("requires a device for a device-scoped control", async () => {
    const createSpy = vi.spyOn(api, "createNcaException");
    const user = userEvent.setup();

    render(
      <RequestExceptionDialog open control={DEVICE_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />,
    );

    await user.type(screen.getByLabelText("Reason"), "Compensating control in place.");
    await user.type(screen.getByLabelText("Expires on"), "2026-12-31");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /request exception/i }));

    expect(await screen.findByText(/choose a device/i)).toBeInTheDocument();
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("submits a device-scoped exception request with every required field", async () => {
    const createSpy = vi.spyOn(api, "createNcaException").mockResolvedValue(SAVED);
    const onSaved = vi.fn();
    const user = userEvent.setup();

    render(
      <RequestExceptionDialog open control={DEVICE_CONTROL} devices={DEVICES} onSaved={onSaved} onCancel={() => {}} />,
    );

    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.type(screen.getByLabelText("Reason"), "Compensating firewall rule in place.");
    await user.type(screen.getByLabelText("Expires on"), "2026-12-31");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /request exception/i }));

    expect(createSpy).toHaveBeenCalledWith({
      control_id: DEVICE_CONTROL.id,
      device_id: "device-insecure",
      organizational_scope_id: null,
      reason: "Compensating firewall rule in place.",
      compensating_control: null,
      requested_by: "auditor-1",
      expires_at: "2026-12-31",
    });
    expect(onSaved).toHaveBeenCalledWith(SAVED);
  });

  it("uses the default organizational scope with no device picker for an organization-scoped control", async () => {
    const createSpy = vi.spyOn(api, "createNcaException").mockResolvedValue(SAVED);
    const user = userEvent.setup();

    render(<RequestExceptionDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />);

    expect(screen.queryByLabelText("Device")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Reason"), "Governance review pending.");
    await user.type(screen.getByLabelText("Expires on"), "2026-12-31");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /request exception/i }));

    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({ device_id: null, organizational_scope_id: "default" }),
    );
  });

  it("surfaces the API error message on failure", async () => {
    vi.spyOn(api, "createNcaException").mockRejectedValue(new Error("boom"));
    const user = userEvent.setup();

    render(<RequestExceptionDialog open control={ORG_CONTROL} devices={DEVICES} onSaved={() => {}} onCancel={() => {}} />);

    await user.type(screen.getByLabelText("Reason"), "x");
    await user.type(screen.getByLabelText("Expires on"), "2026-12-31");
    await user.type(screen.getByLabelText("Your name"), "auditor-1");
    await user.click(screen.getByRole("button", { name: /request exception/i }));

    expect(await screen.findByText(/could not request the exception/i)).toBeInTheDocument();
  });
});
