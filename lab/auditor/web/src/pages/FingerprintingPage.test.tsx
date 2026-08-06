import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FingerprintingPage } from "./FingerprintingPage";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";
import type { Device, ScanTestSpec } from "@/lib/types";

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
    firmware_version: null,
    identity_source: "manual",
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  },
  {
    device_id: "device-hardened",
    display_name: "Smart Camera — Hardened",
    description: "HTTPS only.",
    tier: "hardened",
    host: "device-hardened",
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
    services: [{ id: 2, service_type: "https", port: 443, published_port: 8083, enabled: true }],
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
    firmware_version: null,
    identity_source: "manual",
    criticality: "medium",
    exposure: "internal_only",
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
    applicable_service_types: ["http", "https"],
    pipeline_phase: "fingerprinting",
  },
  {
    test_id: "TEST-AUTH-DEFAULT-CREDS",
    label: "Default credentials",
    category: "web-and-auth",
    applicable_service_types: ["http", "https"],
    pipeline_phase: "sa_iot_compliance",
  },
];

describe("FingerprintingPage", () => {
  beforeEach(() => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.spyOn(api, "scanTests").mockResolvedValue(SCAN_TESTS);
  });

  it("offers only registered devices in the cohort picker", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <FingerprintingPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-insecure")).toBeInTheDocument();
    expect(screen.getByText("device-hardened")).toBeInTheDocument();
    expect(screen.queryByText("device-unregistered-cam")).not.toBeInTheDocument();
  });

  it("shows a PhaseRunnerCard, scoped to fingerprinting tests only, for each selected device", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <FingerprintingPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("checkbox", { name: /select all \(2\)/i }));

    // Both devices' cards show the fingerprinting-phase test...
    expect(screen.getAllByText("Nmap service/port scan").length).toBe(2);
    // ...but never the sa_iot_compliance-phase test, even though it's
    // applicable to both devices' service types.
    expect(screen.queryByText("Default credentials")).not.toBeInTheDocument();
  });

  it("seeds the initial selection from route state passed by Devices' 'Advance to Fingerprinting' action", async () => {
    render(
      <MemoryRouter
        initialEntries={[{ pathname: "/fingerprinting", state: { deviceIds: ["device-hardened"] } }]}
      >
        <ToastProvider>
          <Routes>
            <Route path="/fingerprinting" element={<FingerprintingPage />} />
          </Routes>
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    // Only device-hardened's checkbox starts checked, and only its card
    // renders below the picker.
    expect(screen.getByRole("checkbox", { name: /smart camera — hardened/i })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /smart camera — insecure/i })).not.toBeChecked();
  });
});
