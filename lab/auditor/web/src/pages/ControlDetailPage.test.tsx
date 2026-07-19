import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ControlDetailPage } from "./ControlDetailPage";
import { api } from "@/lib/api";
import type { ControlRecord, ControlVerdictRollup } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const CONTROL: ControlRecord = {
  control_id: "SA-IOT-002",
  title: "No default or hard-coded credentials",
  saudi_source: [
    { framework: "CGIoT-1:2024", reference: "2-2-2", clause: "Prevent default passwords." },
  ],
  applicability: { device_type: ["smart-camera"] },
  required_evidence: [{ test_id: "TEST-AUTH-DEFAULT-CREDS" }],
  automated_test_ids: ["TEST-AUTH-DEFAULT-CREDS"],
  severity: "high",
  conditions: {
    pass: { field: "observations.default_creds", op: "equals", value: false },
    fail: { field: "observations.default_creds", op: "equals", value: true },
  },
  remediation: "Force a unique strong password on first boot.",
};

const ROLLUP: ControlVerdictRollup = {
  control_id: "SA-IOT-002",
  verdicts: [
    {
      verdict_id: "V1",
      device_id: "device-insecure",
      status: "FAIL",
      severity: "high",
      reason: "default creds accepted",
      timestamp: "2026-07-08T00:00:00Z",
    },
    {
      verdict_id: "V2",
      device_id: "device-hardened",
      status: "PASS",
      severity: "high",
      reason: "unique password set",
      timestamp: "2026-07-08T00:05:00Z",
    },
  ],
  counts: { PASS: 1, FAIL: 1, PARTIAL: 0, INCONCLUSIVE: 0 },
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/controls/SA-IOT-002"]}>
      <Routes>
        <Route path="/controls/:controlId" element={<ControlDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ControlDetailPage", () => {
  it("shows the full control plus which devices pass and fail, linking to each device", async () => {
    vi.spyOn(api, "controls").mockResolvedValue([CONTROL]);
    vi.spyOn(api, "controlVerdicts").mockResolvedValue(ROLLUP);

    renderPage();

    expect(await screen.findByText("Force a unique strong password on first boot.")).toBeInTheDocument();
    expect(screen.getByText("smart-camera")).toBeInTheDocument();
    expect(screen.getByText("TEST-AUTH-DEFAULT-CREDS")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();
    expect(screen.getByText("PASS")).toBeInTheDocument();

    const deviceLink = screen.getByRole("link", { name: /device-insecure/i });
    expect(deviceLink).toHaveAttribute("href", "/devices/device-insecure");
  });

  it("renders an error state when the control cannot be found", async () => {
    vi.spyOn(api, "controls").mockResolvedValue([]);
    vi.spyOn(api, "controlVerdicts").mockRejectedValue(new Error("control not found"));

    renderPage();

    expect(await screen.findByText(/control not found/i)).toBeInTheDocument();
  });
});
