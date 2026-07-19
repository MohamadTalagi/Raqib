import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ControlsPage } from "./ControlsPage";
import { api } from "@/lib/api";
import type { ControlRecord, VerdictRecord } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const CONTROLS: ControlRecord[] = [
  {
    control_id: "SA-IOT-002",
    title: "No default or hard-coded credentials",
    saudi_source: [
      { framework: "CGIoT-1:2024", reference: "2-2-2", clause: "Prevent default passwords." },
    ],
    applicability: { device_type: ["smart-camera"] },
    required_evidence: [{ test_id: "TEST-AUTH-DEFAULT-CREDS" }],
    automated_test_ids: ["TEST-AUTH-DEFAULT-CREDS"],
    severity: "high",
    conditions: {},
    remediation: "Force a unique strong password on first boot.",
  },
];

const VERDICTS: VerdictRecord[] = [
  {
    verdict_id: "V1",
    control_id: "SA-IOT-002",
    device_id: "device-insecure",
    status: "FAIL",
    severity: "high",
    evidence_ids: [],
    matched: "fail",
    reason: "default creds accepted",
    saudi_source: "CGIoT-1:2024 §2-2-2",
    remediation: "Force a unique strong password on first boot.",
    timestamp: "2026-07-08T00:00:00Z",
  },
  {
    verdict_id: "V2",
    control_id: "SA-IOT-002",
    device_id: "device-hardened",
    status: "PASS",
    severity: "high",
    evidence_ids: [],
    matched: "pass",
    reason: "unique password set",
    saudi_source: "CGIoT-1:2024 §2-2-2",
    remediation: "Force a unique strong password on first boot.",
    timestamp: "2026-07-08T00:05:00Z",
  },
];

describe("ControlsPage", () => {
  it("lists controls with their Saudi source, severity, and pass/fail counts, linking to detail", async () => {
    vi.spyOn(api, "controls").mockResolvedValue(CONTROLS);
    vi.spyOn(api, "verdicts").mockResolvedValue(VERDICTS);

    render(
      <MemoryRouter>
        <ControlsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("No default or hard-coded credentials")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("CGIoT-1:2024 §2-2-2")).toBeInTheDocument();
    expect(screen.getByText("1 pass")).toBeInTheDocument();
    expect(screen.getByText("1 fail")).toBeInTheDocument();

    const link = screen.getByRole("link", { name: /SA-IOT-002/ });
    expect(link).toHaveAttribute("href", "/controls/SA-IOT-002");
  });

  it("shows an empty state when no controls are loaded", async () => {
    vi.spyOn(api, "controls").mockResolvedValue([]);
    vi.spyOn(api, "verdicts").mockResolvedValue([]);

    render(
      <MemoryRouter>
        <ControlsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/no controls/i)).toBeInTheDocument();
  });
});
