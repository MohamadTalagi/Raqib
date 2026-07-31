import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RemediationPage } from "./RemediationPage";
import { api } from "@/lib/api";
import type { VerdictRecord } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

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
    remediation: "Force a unique password on first boot.",
    timestamp: "2026-07-08T08:58:42Z",
    assessment_id: null,
    policy_version: "1.0.0",
    conflict_detected: false,
    conflict_reason: null,
  },
  {
    verdict_id: "VD-2",
    control_id: "SA-IOT-003",
    device_id: "device-hardened",
    status: "PASS",
    severity: "high",
    evidence_ids: [],
    matched: "pass",
    reason: "...",
    saudi_source: "CGIoT-1:2024 §2-15-2",
    remediation: "Remove Telnet and any other non-essential listening service.",
    timestamp: "2026-07-08T08:58:42Z",
    assessment_id: null,
    policy_version: "1.0.0",
    conflict_detected: false,
    conflict_reason: null,
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <RemediationPage />
    </MemoryRouter>,
  );
}

describe("RemediationPage", () => {
  it("clearly states it's not built yet, never implying real AI-generated content exists", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText("Not built yet")).toBeInTheDocument();
  });

  it("shows only failing controls' existing static remediation text as a preview, not passing ones", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue(VERDICTS);
    renderPage();

    expect(await screen.findByText("Force a unique password on first boot.")).toBeInTheDocument();
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.queryByText("Remove Telnet and any other non-essential listening service.")).not.toBeInTheDocument();
    expect(screen.getByText("Currently failing controls (1)")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is currently failing", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([VERDICTS[1]]);
    renderPage();

    expect(await screen.findByText(/nothing to remediate/i)).toBeInTheDocument();
  });
});
