import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NCACompliancePage } from "./NCACompliancePage";
import { api } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";
import type { NCADeviceComplianceRow, NCADomainSummary, NCASummary } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const SUMMARY: NCASummary = {
  product_label: "NCA CGIoT-1:2024 Alignment",
  framework: "NCA-CGIoT",
  framework_version: "1:2024",
  disclaimer: "This reflects an assessment of alignment with NCA CGIoT-1:2024 guidance. It is not an NCA certification.",
  total_devices: 2,
  device_counts: { pass: 1, partial: 0, fail: 1, not_tested: 0 },
  overall_pass_percentage: 50,
  total_controls: 81,
  last_assessment_at: "2026-07-20T00:00:00Z",
};

const DOMAINS: NCADomainSummary = {
  "Cybersecurity Governance": { pass: 0, partial: 0, fail: 0, not_tested: 9 },
  "Cybersecurity Defense": { pass: 10, partial: 2, fail: 4, not_tested: 0 },
  "Cybersecurity Resilience": { pass: 1, partial: 0, fail: 0, not_tested: 1 },
  "Third-Party and Cloud Computing Cybersecurity": { pass: 0, partial: 0, fail: 0, not_tested: 11 },
};

const DEVICES: NCADeviceComplianceRow[] = [
  {
    device_id: "device-hardened",
    display_name: "Smart Camera — Hardened",
    tier: "hardened",
    vendor: "AcmeCam",
    model: "SC-3000",
    overall_status: "pass",
    score: 100,
    domain_summary: DOMAINS,
  },
  {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    tier: "insecure",
    vendor: "AcmeCam",
    model: "SC-1000",
    overall_status: "fail",
    score: 20,
    domain_summary: DOMAINS,
  },
];

function setup() {
  vi.spyOn(api, "ncaSummary").mockResolvedValue(SUMMARY);
  vi.spyOn(api, "ncaDomains").mockResolvedValue(DOMAINS);
  vi.spyOn(api, "ncaDevices").mockResolvedValue(DEVICES);
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <NCACompliancePage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("NCACompliancePage", () => {
  it("shows the product label and disclaimer, never claiming NCA certification", async () => {
    setup();
    renderPage();

    expect(await screen.findByText("NCA CGIoT-1:2024 Alignment")).toBeInTheDocument();
    expect(screen.getByText(/not an NCA certification/i)).toBeInTheDocument();
  });

  it("shows summary stat tiles and the overall pass rate as a gauge", async () => {
    setup();
    renderPage();

    expect(await screen.findByText("Devices assessed")).toBeInTheDocument();
    expect(screen.getByText("50")).toBeInTheDocument();
    expect(screen.getByText("81")).toBeInTheDocument();
  });

  it("shows the four domain groups with their counts", async () => {
    setup();
    renderPage();

    expect(await screen.findByText("Cybersecurity Governance")).toBeInTheDocument();
    expect(screen.getByText("Cybersecurity Defense")).toBeInTheDocument();
    expect(screen.getByText("Cybersecurity Resilience")).toBeInTheDocument();
    expect(screen.getByText("Third-Party and Cloud Computing Cybersecurity")).toBeInTheDocument();
  });

  it("excludes an organization-scope-only domain with zero device-scope controls of any status", async () => {
    // Governance and the mobile/supplier/cloud group have no device-scope
    // guideline at all - a real all-zero entry (not "9 not_tested" like the
    // shared DOMAINS fixture models), so it must not clutter this per-device
    // breakdown. A domain with only not_tested controls (Resilience below)
    // is a genuinely different case and must still show.
    vi.spyOn(api, "ncaSummary").mockResolvedValue(SUMMARY);
    vi.spyOn(api, "ncaDomains").mockResolvedValue({
      "Cybersecurity Governance": { pass: 0, partial: 0, fail: 0, not_tested: 0 },
      "Cybersecurity Defense": { pass: 10, partial: 2, fail: 4, not_tested: 0 },
      "Cybersecurity Resilience": { pass: 1, partial: 0, fail: 0, not_tested: 1 },
      "Third-Party and Cloud Computing Cybersecurity": { pass: 0, partial: 0, fail: 0, not_tested: 0 },
    });
    vi.spyOn(api, "ncaDevices").mockResolvedValue(DEVICES);
    renderPage();

    await screen.findByText("Cybersecurity Defense");
    expect(screen.queryByText("Cybersecurity Governance")).not.toBeInTheDocument();
    expect(screen.queryByText("Third-Party and Cloud Computing Cybersecurity")).not.toBeInTheDocument();
    expect(screen.getByText("Cybersecurity Resilience")).toBeInTheDocument();
  });

  it("lists devices with icon-and-text status badges, never color alone", async () => {
    setup();
    renderPage();

    await screen.findByText("Smart Camera — Hardened");
    const table = screen.getByRole("table");
    expect(within(table).getByText("Smart Camera — Hardened")).toBeInTheDocument();
    expect(within(table).getByText("Smart Camera — Insecure")).toBeInTheDocument();
    expect(within(table).getByText("Pass")).toBeInTheDocument();
    expect(within(table).getByText("Fail")).toBeInTheDocument();
  });

  it("filters the device table by status tab", async () => {
    const user = userEvent.setup();
    setup();
    renderPage();

    await screen.findByText("Smart Camera — Hardened");
    await user.click(screen.getByRole("tab", { name: /Failed/i }));

    const table = screen.getByRole("table");
    expect(within(table).queryByText("Smart Camera — Hardened")).not.toBeInTheDocument();
    expect(within(table).getByText("Smart Camera — Insecure")).toBeInTheDocument();
  });

  it("filters the device table by device type", async () => {
    const user = userEvent.setup();
    setup();
    renderPage();

    await screen.findByText("Smart Camera — Hardened");
    await user.selectOptions(screen.getByLabelText(/filter by device type/i), "insecure");

    const table = screen.getByRole("table");
    expect(within(table).queryByText("Smart Camera — Hardened")).not.toBeInTheDocument();
    expect(within(table).getByText("Smart Camera — Insecure")).toBeInTheDocument();
  });

  it("links to the organizational compliance view", async () => {
    setup();
    renderPage();

    const link = await screen.findByRole("link", { name: /organizational compliance/i });
    expect(link).toHaveAttribute("href", "/nca-compliance/organization");
  });

  it("offers the four NCA report export links", async () => {
    setup();
    renderPage();

    expect(await screen.findByText("Reports")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /devices \(csv\)/i })).toHaveAttribute(
      "href",
      expect.stringContaining("/nca/reports/devices.csv"),
    );
    expect(screen.getByRole("link", { name: /controls \(csv\)/i })).toHaveAttribute(
      "href",
      expect.stringContaining("/nca/reports/controls.csv"),
    );
    expect(screen.getByRole("link", { name: /evidence \(csv\)/i })).toHaveAttribute(
      "href",
      expect.stringContaining("/nca/reports/evidence.csv"),
    );
    expect(screen.getByRole("link", { name: /executive summary \(pdf\)/i })).toHaveAttribute(
      "href",
      expect.stringContaining("/nca/reports/executive.pdf"),
    );
  });

  it("shows a devices-needing-attention panel, worst-first, excluding fully passing devices", async () => {
    setup();
    renderPage();

    const heading = await screen.findByText("Devices needing attention");
    // device-insecure (fail) needs attention; device-hardened (pass) does not appear in that panel.
    const panel = heading.closest("h3")?.parentElement?.parentElement as HTMLElement;
    expect(panel).toBeTruthy();
    expect(within(panel).getByText("Smart Camera — Insecure")).toBeInTheDocument();
    expect(within(panel).queryByText("Smart Camera — Hardened")).not.toBeInTheDocument();
  });

  it("links to the full NCA controls catalog", async () => {
    setup();
    renderPage();

    const link = await screen.findByRole("link", { name: /browse all 81 controls/i });
    expect(link).toHaveAttribute("href", "/nca-compliance/controls");
  });

  it("recomputes NCA mappings from evidence and shows the result", async () => {
    setup();
    const recomputeSpy = vi
      .spyOn(api, "recomputeNcaAssessments")
      .mockResolvedValue({ created: 3, assessment_ids: ["ASM-1", "ASM-2", "ASM-3"] });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("NCA CGIoT-1:2024 Alignment");
    await user.click(screen.getByRole("button", { name: /recompute from evidence/i }));

    expect(recomputeSpy).toHaveBeenCalled();
    expect(await screen.findByText(/3 new not-tested assessment/i)).toBeInTheDocument();
  });

  it("shows a neutral message when recompute finds nothing new", async () => {
    setup();
    vi.spyOn(api, "recomputeNcaAssessments").mockResolvedValue({ created: 0, assessment_ids: [] });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("NCA CGIoT-1:2024 Alignment");
    await user.click(screen.getByRole("button", { name: /recompute from evidence/i }));

    expect(await screen.findByText(/no new automated findings/i)).toBeInTheDocument();
  });
});
