import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PhaseRunnerCard } from "./PhaseRunnerCard";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";
import type { Assessment, CreateAssessmentResult, Device, ScanJob, ScanTestSpec } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICE: Device = {
  device_id: "device-insecure",
  display_name: "Smart Camera — Insecure",
  description: "Default creds, plain HTTP.",
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
  services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
};

const TESTS: ScanTestSpec[] = [
  {
    test_id: "TEST-NET-PORTSCAN",
    label: "Nmap service/port scan",
    category: "network-and-protocol",
    applicable_service_types: ["http"],
    pipeline_phase: "fingerprinting",
  },
];

function makeJob(overrides: Partial<ScanJob> & { id: number; test_id: string }): ScanJob {
  return {
    device_id: "device-insecure",
    status: "pending",
    tool: null,
    tool_version: null,
    command: null,
    raw_output: null,
    observations: null,
    error: null,
    evidence_id: null,
    assessment_id: "ASMT-2026-07-22-0001",
    created_at: "2026-07-12T00:00:00Z",
    updated_at: "2026-07-12T00:00:00Z",
    suggested_finding: null,
    suggested_confidence: null,
    ...overrides,
  };
}

function makeAssessmentResult(jobs: ScanJob[], overrides: Partial<Assessment> = {}): CreateAssessmentResult {
  return {
    id: "ASMT-2026-07-22-0001",
    device_id: "device-insecure",
    status: "queued",
    policy_version: "1.0.0",
    started_at: null,
    completed_at: null,
    error: null,
    created_at: "2026-07-22T00:00:00Z",
    jobs,
    errors: {},
    ...overrides,
  };
}

function renderCard(props: Partial<Parameters<typeof PhaseRunnerCard>[0]> = {}) {
  return render(
    <ToastProvider>
      <PhaseRunnerCard device={DEVICE} tests={TESTS} {...props} />
    </ToastProvider>,
  );
}

describe("PhaseRunnerCard", () => {
  it("shows the emptyHint when there are no applicable tests", () => {
    renderCard({ tests: [], emptyHint: <p>No firmware uploaded for this device.</p> });
    expect(screen.getByText("No firmware uploaded for this device.")).toBeInTheDocument();
  });

  it("runs the selected test and renders its ScanJobCard", async () => {
    const jobState = makeJob({
      id: 1,
      test_id: "TEST-NET-PORTSCAN",
      status: "awaiting_finding",
      tool: "nmap",
      raw_output: "80/tcp open http",
      observations: { open_ports: [80] },
    });
    vi.spyOn(api, "createAssessment").mockResolvedValue(makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockResolvedValue(jobState);

    const user = userEvent.setup();
    renderCard();

    await user.click(screen.getByRole("checkbox", { name: "Nmap service/port scan" }));
    await user.click(screen.getByRole("button", { name: /run selected \(1\)/i }));

    // Wait for the ScanJobCard itself to render (its own status text is
    // unambiguous), then confirm the test label now appears a second time -
    // once as the checkbox label, once as the ScanJobCard's own label.
    await screen.findByText(/awaiting your finding/i);
    expect(screen.getAllByText("Nmap service/port scan")).toHaveLength(2);
    expect(screen.getByText((_, node) => node?.textContent === "job #1 · device-insecure · TEST-NET-PORTSCAN")).toBeInTheDocument();
  });

  it("renders resultsActions once real jobs exist, not before", async () => {
    const jobState = makeJob({ id: 2, test_id: "TEST-NET-PORTSCAN", status: "pending" });
    vi.spyOn(api, "createAssessment").mockResolvedValue(makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockResolvedValue(jobState);

    const user = userEvent.setup();
    renderCard({ resultsActions: <button type="button">Recompute verdicts</button> });

    expect(screen.queryByRole("button", { name: /recompute verdicts/i })).not.toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: "Nmap service/port scan" }));
    await user.click(screen.getByRole("button", { name: /run selected \(1\)/i }));

    expect(await screen.findByRole("button", { name: /recompute verdicts/i })).toBeInTheDocument();
  });
});
