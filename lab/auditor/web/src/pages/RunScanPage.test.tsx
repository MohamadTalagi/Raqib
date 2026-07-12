import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RunScanPage } from "./RunScanPage";

const SCAN_TESTS = [
  { test_id: "TEST-NET-PORTSCAN", label: "Nmap service/port scan", allowed_devices: ["device-insecure"] },
];

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("RunScanPage", () => {
  beforeEach(() => {
    let jobState = {
      id: 1,
      device_id: "device-insecure",
      test_id: "TEST-NET-PORTSCAN",
      status: "awaiting_finding" as string,
      tool: "nmap",
      tool_version: "7.95",
      command: "nmap -sV -p- device-insecure",
      raw_output: "80/tcp open http\n",
      observations: { open_ports: [80], telnet_open: false },
      error: null,
      evidence_id: null as string | null,
      created_at: "2026-07-12T00:00:00Z",
      updated_at: "2026-07-12T00:00:00Z",
    };

    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        const method = init?.method ?? "GET";

        if (url.endsWith("/scan-tests")) {
          return Promise.resolve(jsonResponse(SCAN_TESTS));
        }
        if (url.endsWith("/scan-jobs") && method === "POST") {
          return Promise.resolve(jsonResponse(jobState));
        }
        if (url.match(/\/scan-jobs\/1$/) && method === "GET") {
          return Promise.resolve(jsonResponse(jobState));
        }
        if (url.match(/\/scan-jobs\/1\/record$/) && method === "POST") {
          jobState = { ...jobState, status: "recorded", evidence_id: "EV-2026-07-12-0001" };
          return Promise.resolve(
            jsonResponse({
              evidence_id: "EV-2026-07-12-0001",
              device_id: "device-insecure",
              test_id: "TEST-NET-PORTSCAN",
              tool: "nmap",
              tool_version: "7.95",
              command: jobState.command,
              timestamp: "2026-07-12T00:00:01Z",
              finding: "Only HTTP open",
              observations: jobState.observations,
              raw_output_path: "document-store/raw/EV-2026-07-12-0001.txt",
              confidence: "high",
              sha256: "a".repeat(64),
            }),
          );
        }
        if (url.endsWith("/verdicts/recompute") && method === "POST") {
          return Promise.resolve(jsonResponse({ created: 1, verdicts: [] }));
        }
        return Promise.resolve(jsonResponse({}, 404));
      }),
    );
  });

  it("runs the full flow: select, run, read output, record evidence, recompute verdicts", async () => {
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
