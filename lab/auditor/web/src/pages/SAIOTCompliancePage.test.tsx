import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SAIOTCompliancePage } from "./SAIOTCompliancePage";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";
import type { Device, ScanTestSpec, VerdictRecord } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICE_NO_FIRMWARE: Device = {
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
  criticality: "medium",
  exposure: "internal_only",
  registered: true,
  evidence_count: 0,
  verdict_count: 0,
  services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
};

const DEVICE_WITH_FIRMWARE: Device = {
  ...DEVICE_NO_FIRMWARE,
  device_id: "device-with-firmware",
  display_name: "Smart Camera — With Firmware",
  firmware_filename: "cam-fw-1.2.0.tar.gz",
  firmware_sha256: "b".repeat(64),
  firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
};

const SCAN_TESTS: ScanTestSpec[] = [
  {
    test_id: "TEST-AUTH-DEFAULT-CREDS",
    label: "Default credentials",
    category: "web-and-auth",
    applicable_service_types: ["http", "https"],
    pipeline_phase: "sa_iot_compliance",
  },
  {
    test_id: "TEST-FW-VERSION",
    label: "Version file",
    category: "firmware",
    applicable_service_types: [],
    pipeline_phase: "sa_iot_compliance",
  },
  {
    test_id: "TEST-NET-PORTSCAN",
    label: "Nmap service/port scan",
    category: "network-and-protocol",
    applicable_service_types: ["http"],
    pipeline_phase: "fingerprinting",
  },
];

const VERDICTS: VerdictRecord[] = [
  {
    verdict_id: "VD-1",
    control_id: "SA-IOT-002",
    device_id: "device-insecure",
    status: "FAIL",
    severity: "critical",
    evidence_ids: [],
    matched: "fail",
    reason: "...",
    saudi_source: "CGIoT-1:2024 §2-4-1",
    remediation: "...",
    timestamp: "2026-07-08T08:58:42Z",
    assessment_id: null,
    policy_version: "1.0.0",
    conflict_detected: false,
    conflict_reason: null,
  },
];

describe("SAIOTCompliancePage", () => {
  beforeEach(() => {
    vi.spyOn(api, "devices").mockResolvedValue([DEVICE_NO_FIRMWARE, DEVICE_WITH_FIRMWARE]);
    vi.spyOn(api, "scanTests").mockResolvedValue(SCAN_TESTS);
    vi.spyOn(api, "verdicts").mockResolvedValue(VERDICTS);
  });

  it("scopes each device's tests to sa_iot_compliance only, never fingerprinting", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <SAIOTCompliancePage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("checkbox", { name: /select all \(2\)/i }));

    expect(screen.getAllByText("Default credentials").length).toBeGreaterThan(0);
    expect(screen.queryByText("Nmap service/port scan")).not.toBeInTheDocument();
  });

  it("only offers the firmware-gated test to the device that actually has firmware uploaded", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <SAIOTCompliancePage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("checkbox", { name: /select all \(2\)/i }));

    // Only one "Version file" checkbox should exist - device-with-firmware's.
    expect(screen.getAllByRole("checkbox", { name: "Version file" })).toHaveLength(1);
    expect(screen.getByText(/1 additional firmware-based test\(s\) available/i)).toBeInTheDocument();
  });

  it("shows each selected device's current verdict counts", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <SAIOTCompliancePage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("checkbox", { name: /select all \(2\)/i }));

    expect(screen.getByText("1 fail")).toBeInTheDocument();
  });

  it("recomputes verdicts via the page-level action", async () => {
    vi.spyOn(api, "recomputeVerdicts").mockResolvedValue({ created: 2, verdicts: [] });
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <SAIOTCompliancePage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("button", { name: /recompute verdicts/i }));

    expect(await screen.findByText(/2 new verdicts generated/i)).toBeInTheDocument();
  });

  // Regression: caught live — recomputing verdicts through the real API
  // genuinely created new verdict rows (confirmed via GET /verdicts), but
  // this page's own "current verdicts" count kept showing the pre-recompute
  // numbers, since api.verdicts was only ever fetched once on mount with no
  // refetch afterward. Every other page in this codebase bumps a refreshKey
  // included in useFetch's deps after a mutation; this page didn't.
  it("refetches verdicts after a successful recompute, so the displayed counts update without a page reload", async () => {
    vi.spyOn(api, "recomputeVerdicts").mockResolvedValue({ created: 1, verdicts: [] });
    const verdictsSpy = vi.spyOn(api, "verdicts").mockResolvedValueOnce(VERDICTS).mockResolvedValueOnce([
      ...VERDICTS,
      { ...VERDICTS[0], verdict_id: "VD-2", control_id: "SA-IOT-003" },
    ]);
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <SAIOTCompliancePage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("checkbox", { name: /select all \(2\)/i }));
    expect(screen.getByText("1 fail")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /recompute verdicts/i }));
    await screen.findByText(/1 new verdict generated/i);

    expect(verdictsSpy).toHaveBeenCalledTimes(2);
    expect(await screen.findByText("2 fail")).toBeInTheDocument();
  });
});
