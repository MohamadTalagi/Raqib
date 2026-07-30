import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScanConsolePage } from "./ScanConsolePage";
import { api } from "@/lib/api";
import type { Device, ScanJob, ScanTestSpec } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICE: Device = {
  device_id: "device-insecure",
  display_name: "Insecure Cam",
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
  criticality: "medium",
  exposure: "internal_only",
  registered: true,
  evidence_count: 0,
  verdict_count: 0,
  services: [],
};

const TEST: ScanTestSpec = {
  test_id: "TEST-NET-PORTSCAN",
  label: "Port scan",
  category: "network-and-protocol",
  applicable_service_types: ["http"],
};

const DONE_JOB: ScanJob = {
  id: 42,
  device_id: "device-insecure",
  test_id: "TEST-NET-PORTSCAN",
  status: "awaiting_finding",
  tool: "nmap",
  tool_version: "7.94",
  command: "nmap -sV -p- 172.30.0.5",
  raw_output: "PORT   STATE SERVICE\n23/tcp open  telnet",
  observations: { open_ports: [23] },
  error: null,
  evidence_id: null,
  assessment_id: null,
  created_at: "2026-07-30T00:00:00Z",
  updated_at: "2026-07-30T00:00:00Z",
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ScanConsolePage />
    </MemoryRouter>,
  );
}

async function typeCommand(user: ReturnType<typeof userEvent.setup>, cmd: string) {
  const input = screen.getByLabelText("Console command");
  await user.click(input);
  await user.type(input, `${cmd}{Enter}`);
}

describe("ScanConsolePage", () => {
  beforeEach(() => {
    vi.spyOn(api, "devices").mockResolvedValue([DEVICE]);
    vi.spyOn(api, "scanTests").mockResolvedValue([TEST]);
  });

  it("shows the security banner making clear it is not a shell", async () => {
    renderPage();
    // Appears in both the banner and the welcome line.
    expect((await screen.findAllByText(/not a shell/i)).length).toBeGreaterThan(0);
  });

  it("rejects an unknown command instead of running anything", async () => {
    const create = vi.spyOn(api, "createScanJob");
    renderPage();
    const user = userEvent.setup();
    await typeCommand(user, "rm -rf /");

    expect(await screen.findByText(/command not found: rm/i)).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });

  it("lists available tests", async () => {
    renderPage();
    const user = userEvent.setup();
    await typeCommand(user, "list tests");
    expect(await screen.findByText(/TEST-NET-PORTSCAN\s+—\s+Port scan/)).toBeInTheDocument();
  });

  it("runs a whitelisted scan and prints the command and output", async () => {
    const create = vi.spyOn(api, "createScanJob").mockResolvedValue({ ...DONE_JOB, status: "pending" });
    vi.spyOn(api, "getScanJob").mockResolvedValue(DONE_JOB);
    renderPage();
    const user = userEvent.setup();

    await typeCommand(user, "scan device-insecure TEST-NET-PORTSCAN");

    expect(create).toHaveBeenCalledWith("device-insecure", "TEST-NET-PORTSCAN");
    expect(await screen.findByText(/nmap -sV -p- 172.30.0.5/)).toBeInTheDocument();
    // Testing Library normalizes the double space to one.
    expect(screen.getByText(/23\/tcp open telnet/)).toBeInTheDocument();
  });

  it("refuses to scan an unregistered device without calling the API", async () => {
    const create = vi.spyOn(api, "createScanJob");
    renderPage();
    const user = userEvent.setup();
    await typeCommand(user, "scan ghost-device TEST-NET-PORTSCAN");

    expect(await screen.findByText(/unknown or unregistered device: ghost-device/i)).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });
});
