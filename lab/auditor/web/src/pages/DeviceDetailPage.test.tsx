import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeviceDetailPage } from "./DeviceDetailPage";
import { api } from "@/lib/api";
import type { DeviceDetail } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DETAIL: DeviceDetail = {
  device: {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP.",
    tier: "insecure",
    host: "device-insecure",
    vendor: "AcmeCam",
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
  },
  services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  evidence: [
    {
      evidence_id: "EV-1",
      test_id: "TEST-NET-PORTSCAN",
      tool: "nmap",
      finding: "Telnet exposed",
      confidence: "high",
      timestamp: "2026-07-08T10:00:00+00:00",
    },
  ],
  verdicts: [
    {
      verdict_id: "V-1",
      control_id: "SA-IOT-002",
      status: "FAIL",
      severity: "high",
      reason: "default creds accepted",
      timestamp: "2026-07-08T10:05:00+00:00",
    },
  ],
  scan_jobs: [],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/devices/device-insecure"]}>
      <Routes>
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("DeviceDetailPage", () => {
  it("shows the device, its services, evidence and verdicts together", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("Smart Camera — Insecure")).toBeInTheDocument();
    expect(screen.getByText("AcmeCam")).toBeInTheDocument();
    expect(screen.getByText(/8081/)).toBeInTheDocument();
    expect(screen.getByText("Telnet exposed")).toBeInTheDocument();
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();
  });

  it("renders an error state when the device is missing", async () => {
    vi.spyOn(api, "device").mockRejectedValue(new Error("device not found"));
    renderPage();
    await waitFor(() => expect(screen.getByText(/device not found/i)).toBeInTheDocument());
  });
});
