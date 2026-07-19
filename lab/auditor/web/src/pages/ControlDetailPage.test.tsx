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

  it("renders a not-found state when the control ID does not match any known control", async () => {
    // Reflects the real backend contract (auditor-api main.py get_control_verdicts):
    // an unknown-but-syntactically-valid control_id resolves with HTTP 200 and an
    // empty rollup, it does NOT reject/404. The page must detect "not found" by
    // noticing the ID is absent from the resolved /controls list, not by an error.
    vi.spyOn(api, "controls").mockResolvedValue([]);
    vi.spyOn(api, "controlVerdicts").mockResolvedValue({
      control_id: "SA-IOT-002",
      verdicts: [],
      counts: { PASS: 0, FAIL: 0, PARTIAL: 0, INCONCLUSIVE: 0 },
    });

    renderPage();

    expect(await screen.findByText(/No control found with ID "SA-IOT-002"/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to controls/i })).toHaveAttribute("href", "/controls");
    // Must not be stuck showing the loading skeleton.
    expect(screen.queryByText(/pass \/ fail conditions/i)).not.toBeInTheDocument();
  });

  it("renders an error state when the controls fetch itself fails", async () => {
    vi.spyOn(api, "controls").mockRejectedValue(new Error("network unreachable"));
    vi.spyOn(api, "controlVerdicts").mockRejectedValue(new Error("network unreachable"));

    renderPage();

    expect(await screen.findByText(/network unreachable/i)).toBeInTheDocument();
  });
});
