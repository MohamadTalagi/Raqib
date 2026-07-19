import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RunScanPage } from "./RunScanPage";
import { api } from "@/lib/api";
import type { Device, ScanJob, ScanTestSpec } from "@/lib/types";

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
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 2, service_type: "telnet", port: 23, published_port: null, enabled: true }],
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
    applicable_service_types: ["http", "https", "mqtt", "mqtts", "telnet", "ssh"],
  },
  {
    test_id: "TEST-AUTH-DEFAULT-CREDS",
    label: "Default credentials (admin/admin)",
    applicable_service_types: ["http", "https"],
  },
];

describe("RunScanPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.spyOn(api, "scanTests").mockResolvedValue(SCAN_TESTS);
  });

  it("offers only registered devices in the device dropdown", async () => {
    render(
      <MemoryRouter>
        <RunScanPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    expect(screen.getByRole("option", { name: "telnet-sim" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "device-unregistered-cam" })).not.toBeInTheDocument();
  });

  it("intersects a test's applicable_service_types with the selected device's exposed services, not by device name", async () => {
    render(
      <MemoryRouter>
        <RunScanPage />
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByRole("option", { name: "telnet-sim" })).toBeInTheDocument());

    await user.selectOptions(screen.getByLabelText("Device"), "telnet-sim");
    expect(screen.getByRole("option", { name: "Nmap service/port scan" })).toBeInTheDocument();
    expect(
      screen.queryByRole("option", { name: "Default credentials (admin/admin)" }),
    ).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    expect(screen.getByRole("option", { name: "Default credentials (admin/admin)" })).toBeInTheDocument();
  });

  it("runs the full flow: select, run, read output, record evidence, recompute verdicts", async () => {
    let jobState: ScanJob = {
      id: 1,
      device_id: "device-insecure",
      test_id: "TEST-NET-PORTSCAN",
      status: "awaiting_finding",
      tool: "nmap",
      tool_version: "7.95",
      command: "nmap -sV -p- device-insecure",
      raw_output: "80/tcp open http\n",
      observations: { open_ports: [80], telnet_open: false },
      error: null,
      evidence_id: null,
      created_at: "2026-07-12T00:00:00Z",
      updated_at: "2026-07-12T00:00:00Z",
    };

    vi.spyOn(api, "createScanJob").mockImplementation(async () => jobState);
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
      };
    });
    vi.spyOn(api, "recomputeVerdicts").mockResolvedValue({ created: 1, verdicts: [] });

    render(
      <MemoryRouter>
        <RunScanPage />
      </MemoryRouter>,
    );

    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.selectOptions(screen.getByLabelText("Test"), "TEST-NET-PORTSCAN");
    await user.click(screen.getByRole("button", { name: /run test/i }));

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

  it("disables Record evidence until a finding is typed", async () => {
    const jobState: ScanJob = {
      id: 2,
      device_id: "device-insecure",
      test_id: "TEST-NET-PORTSCAN",
      status: "awaiting_finding",
      tool: "nmap",
      tool_version: "7.95",
      command: "nmap -sV -p- device-insecure",
      raw_output: "80/tcp open http\n",
      observations: { open_ports: [80], telnet_open: false },
      error: null,
      evidence_id: null,
      created_at: "2026-07-12T00:00:00Z",
      updated_at: "2026-07-12T00:00:00Z",
    };
    vi.spyOn(api, "createScanJob").mockResolvedValue(jobState);
    vi.spyOn(api, "getScanJob").mockResolvedValue(jobState);

    render(
      <MemoryRouter>
        <RunScanPage />
      </MemoryRouter>,
    );
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByRole("option", { name: "device-insecure" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Device"), "device-insecure");
    await user.selectOptions(screen.getByLabelText("Test"), "TEST-NET-PORTSCAN");
    await user.click(screen.getByRole("button", { name: /run test/i }));

    await screen.findByText(/Awaiting your finding/i);
    expect(screen.getByRole("button", { name: /record evidence/i })).toBeDisabled();
  });
});
