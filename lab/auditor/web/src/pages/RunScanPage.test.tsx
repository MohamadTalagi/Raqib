import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RunScanPage } from "./RunScanPage";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";
import type { Assessment, CreateAssessmentResult, Device, ScanJob, ScanTestSpec } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICES: Device[] = [
  {
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
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  },
  {
    device_id: "telnet-sim",
    display_name: "Telnet simulator",
    description: "Telnet-only service.",
    tier: "unknown",
    host: "telnet-sim",
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
    services: [{ id: 2, service_type: "telnet", port: 23, published_port: null, enabled: true }],
  },
  {
    device_id: "device-with-firmware",
    display_name: "Smart Camera — With Firmware",
    description: "Has an uploaded firmware archive.",
    tier: "insecure",
    host: "device-with-firmware",
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: "cam-fw-1.2.0.tar.gz",
    firmware_sha256: "b".repeat(64),
    firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 3, service_type: "http", port: 80, published_port: 8084, enabled: true }],
  },
  {
    device_id: "device-unregistered-cam",
    display_name: "Unregistered Test Camera",
    description: "Not yet registered.",
    tier: "unknown",
    host: null,
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: null,
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    registered: false,
    evidence_count: 0,
    verdict_count: 0,
    services: [],
  },
];

const SCAN_TESTS: ScanTestSpec[] = [
  {
    test_id: "TEST-NET-PORTSCAN",
    label: "Nmap service/port scan",
    category: "network-and-protocol",
    applicable_service_types: ["http", "https", "mqtt", "mqtts", "telnet", "ssh"],
  },
  {
    test_id: "TEST-FW-VERSION",
    label: "Version file",
    category: "firmware",
    applicable_service_types: [],
  },
  {
    test_id: "TEST-FW-UPDATESCRIPT",
    label: "Update script",
    category: "firmware",
    applicable_service_types: [],
  },
  {
    test_id: "TEST-AUTH-DEFAULT-CREDS",
    label: "Default credentials (admin/admin)",
    category: "web-and-auth",
    applicable_service_types: ["http", "https"],
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

describe("RunScanPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.spyOn(api, "scanTests").mockResolvedValue(SCAN_TESTS);
  });

  it("offers only registered devices in the device dropdown", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    expect(screen.getByRole("option", { name: "telnet-sim" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "device-unregistered-cam" })).not.toBeInTheDocument();
  });

  it("intersects a test's applicable_service_types with the selected device's exposed services, not by device name", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByRole("option", { name: "telnet-sim" })).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText("Device"), "telnet-sim");
    expect(await screen.findByText("Nmap service/port scan")).toBeInTheDocument();
    expect(screen.queryByText("Default credentials (admin/admin)")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    expect(await screen.findByText("Default credentials (admin/admin)")).toBeInTheDocument();
  });

  it("shows the firmware section as disabled with an upload hint when no firmware is uploaded", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");

    expect(await screen.findByText(/Simulated Firmware Analysis/i)).toBeInTheDocument();
    const versionFileCheckbox = screen.getByRole("checkbox", { name: "Version file" });
    expect(versionFileCheckbox).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Update script" })).toBeDisabled();
    expect(screen.getByRole("link", { name: /upload firmware/i })).toHaveAttribute(
      "href",
      "/devices/device-insecure",
    );
  });

  it("enables the firmware section once the device has firmware uploaded", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByRole("option", { name: "device-with-firmware" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-with-firmware");

    const versionFileCheckbox = await screen.findByRole("checkbox", { name: "Version file" });
    expect(versionFileCheckbox).toBeEnabled();

    const selectAllBoxes = screen.getAllByRole("checkbox", { name: /select all/i });
    for (const box of selectAllBoxes) {
      await user.click(box);
    }
    expect(versionFileCheckbox).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Update script" })).toBeChecked();
  });

  it("runs the full flow: select tests, run selected, read output, record evidence, recompute verdicts", async () => {
    let jobState = makeJob({
      id: 1,
      test_id: "TEST-NET-PORTSCAN",
      status: "awaiting_finding",
      tool: "nmap",
      tool_version: "7.95",
      command: "nmap -sV -p- device-insecure",
      raw_output: "80/tcp open http\n",
      observations: { open_ports: [80], telnet_open: false },
    });

    vi.spyOn(api, "createAssessment").mockImplementation(async () => makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockImplementation(async () => jobState);
    vi.spyOn(api, "recordScanJob").mockImplementation(async () => {
      jobState = { ...jobState, status: "recorded", evidence_id: "EV-2026-07-12-0001" };
      return {
        evidence_id: "EV-2026-07-12-0001",
        device_id: "device-insecure",
        test_id: "TEST-NET-PORTSCAN",
        tool: "nmap",
        tool_version: "7.95",
        command: jobState.command ?? "",
        timestamp: "2026-07-12T00:00:01Z",
        finding: "Only HTTP open",
        observations: jobState.observations ?? {},
        raw_output_path: "document-store/raw/EV-2026-07-12-0001.txt",
        confidence: "high",
        sha256: "a".repeat(64),
        assessment_id: jobState.assessment_id,
        source_type: "automated",
        confidence_reason: null,
        error_state: null,
      };
    });
    vi.spyOn(api, "recomputeVerdicts").mockResolvedValue({ created: 1, verdicts: [] });
    vi.spyOn(api, "getAssessment").mockImplementation(async () => ({
      id: "ASMT-2026-07-22-0001", device_id: "device-insecure", status: "completed",
      policy_version: "1.0.0", started_at: "2026-07-12T00:00:00Z", completed_at: "2026-07-12T00:00:02Z",
      error: null, created_at: "2026-07-12T00:00:00Z", jobs: [jobState],
    }));

    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");

    await user.click(await screen.findByRole("checkbox", { name: "Nmap service/port scan" }));
    await user.click(screen.getByRole("button", { name: /run selected \(1\)/i }));

    expect(await screen.findByText(/Awaiting your finding/i)).toBeInTheDocument();
    expect(screen.getByText("nmap -sV -p- device-insecure")).toBeInTheDocument();
    expect(screen.getByText(/80\/tcp open http/)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/your finding/i), "Only HTTP open");
    await user.click(screen.getByRole("button", { name: /record evidence/i }));

    expect(await screen.findByText(/Recorded as evidence/i)).toBeInTheDocument();
    expect(screen.getByText("EV-2026-07-12-0001")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /recompute verdicts/i }));
    expect(await screen.findByText(/1 new verdict generated/i)).toBeInTheDocument();
  });

  it("disables Run selected while the launched scan is still pending/running, re-enabling once it finishes", async () => {
    let jobState = makeJob({ id: 9, test_id: "TEST-NET-PORTSCAN", status: "pending" });
    vi.spyOn(api, "createAssessment").mockImplementation(async () => makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockImplementation(async () => jobState);
    vi.spyOn(api, "getAssessment").mockImplementation(async () => ({
      id: "ASMT-2026-07-22-0001", device_id: "device-insecure", status: "running",
      policy_version: "1.0.0", started_at: "2026-07-21T00:00:00Z", completed_at: null,
      error: null, created_at: "2026-07-21T00:00:00Z", jobs: [jobState],
    }));

    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.click(await screen.findByRole("checkbox", { name: "Nmap service/port scan" }));

    const runButton = screen.getByRole("button", { name: /run selected \(1\)/i });
    await user.click(runButton);

    expect(await screen.findByText(/queued/i)).toBeInTheDocument();
    expect(runButton).toBeDisabled();
    expect(screen.getByText(/a scan is already running/i)).toBeInTheDocument();

    jobState = { ...jobState, status: "awaiting_finding", command: "nmap -sV -p- device-insecure", raw_output: "80/tcp open http\n" };
    // The next poll fires POLL_INTERVAL_MS (1200ms) after the previous one -
    // longer than testing-library's default waitFor timeout.
    await waitFor(() => expect(runButton).toBeEnabled(), { timeout: 3000 });
    expect(screen.queryByText(/a scan is already running/i)).not.toBeInTheDocument();
  });

  it("can select every test in a section at once via Select all", async () => {
    vi.spyOn(api, "createAssessment").mockImplementation(async (_deviceId, testIds) =>
      makeAssessmentResult(
        testIds.map((testId) => makeJob({ id: testId === "TEST-NET-PORTSCAN" ? 1 : 2, test_id: testId })),
      ),
    );

    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");

    const selectAllBoxes = await screen.findAllByRole("checkbox", { name: /select all/i });
    for (const box of selectAllBoxes) {
      await user.click(box);
    }
    expect(screen.getByRole("checkbox", { name: "Nmap service/port scan" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Default credentials (admin/admin)" })).toBeChecked();

    await user.click(screen.getByRole("button", { name: /run selected \(2\)/i }));
    await waitFor(() =>
      expect(api.createAssessment).toHaveBeenCalledWith(
        "device-insecure",
        expect.arrayContaining(["TEST-NET-PORTSCAN", "TEST-AUTH-DEFAULT-CREDS"]),
      ),
    );
  });

  it("disables Record evidence until a finding is typed", async () => {
    const jobState = makeJob({
      id: 2,
      test_id: "TEST-NET-PORTSCAN",
      status: "awaiting_finding",
      tool: "nmap",
      tool_version: "7.95",
      command: "nmap -sV -p- device-insecure",
      raw_output: "80/tcp open http\n",
      observations: { open_ports: [80], telnet_open: false },
    });
    vi.spyOn(api, "createAssessment").mockResolvedValue(makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockResolvedValue(jobState);

    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.click(await screen.findByRole("checkbox", { name: "Nmap service/port scan" }));
    await user.click(screen.getByRole("button", { name: /run selected \(1\)/i }));

    await screen.findByText(/Awaiting your finding/i);
    expect(screen.getByRole("button", { name: /record evidence/i })).toBeDisabled();
  });

  it("shows the assessment status bar and a cancel button while it's in flight", async () => {
    const jobState = makeJob({ id: 3, test_id: "TEST-NET-PORTSCAN", status: "pending" });
    vi.spyOn(api, "createAssessment").mockResolvedValue(makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockResolvedValue(jobState);
    vi.spyOn(api, "getAssessment").mockResolvedValue({
      id: "ASMT-2026-07-22-0001", device_id: "device-insecure", status: "queued",
      policy_version: "1.0.0", started_at: null, completed_at: null,
      error: null, created_at: "2026-07-22T00:00:00Z", jobs: [jobState],
    });

    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.click(await screen.findByRole("checkbox", { name: "Nmap service/port scan" }));
    await user.click(screen.getByRole("button", { name: /run selected \(1\)/i }));

    expect(await screen.findByText("ASMT-2026-07-22-0001")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel assessment/i })).toBeInTheDocument();
  });

  it("cancels the assessment when the cancel button is clicked", async () => {
    const jobState = makeJob({ id: 4, test_id: "TEST-NET-PORTSCAN", status: "pending" });
    vi.spyOn(api, "createAssessment").mockResolvedValue(makeAssessmentResult([jobState]));
    vi.spyOn(api, "getScanJob").mockResolvedValue(jobState);
    vi.spyOn(api, "getAssessment").mockResolvedValue({
      id: "ASMT-2026-07-22-0001", device_id: "device-insecure", status: "queued",
      policy_version: "1.0.0", started_at: null, completed_at: null,
      error: null, created_at: "2026-07-22T00:00:00Z", jobs: [jobState],
    });
    const cancelSpy = vi.spyOn(api, "cancelAssessment").mockResolvedValue({
      id: "ASMT-2026-07-22-0001", device_id: "device-insecure", status: "cancelled",
      policy_version: "1.0.0", started_at: null, completed_at: "2026-07-22T00:00:01Z",
      error: null, created_at: "2026-07-22T00:00:00Z", jobs: [jobState],
    });

    render(
      <MemoryRouter>
        <ToastProvider>
          <RunScanPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.click(await screen.findByRole("checkbox", { name: "Nmap service/port scan" }));
    await user.click(screen.getByRole("button", { name: /run selected \(1\)/i }));

    await user.click(await screen.findByRole("button", { name: /cancel assessment/i }));

    await waitFor(() => expect(cancelSpy).toHaveBeenCalledWith("ASMT-2026-07-22-0001"));
    expect(await screen.findByText(/^Cancelled$/i)).toBeInTheDocument();
  });
});
