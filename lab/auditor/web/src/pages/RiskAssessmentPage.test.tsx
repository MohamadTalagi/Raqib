import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RiskAssessmentPage } from "./RiskAssessmentPage";
import { mockFetchImplementation } from "@/test/fixtures";

describe("RiskAssessmentPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("names its three real inputs explicitly in the page subtitle", async () => {
    render(
      <MemoryRouter>
        <RiskAssessmentPage />
      </MemoryRouter>,
    );

    const banner = await screen.findByRole("banner");
    expect(within(banner).getByText(/SA-IOT verdicts/)).toBeInTheDocument();
    expect(within(banner).getByText(/NCA CGIoT-1:2024 compliance/)).toBeInTheDocument();
    expect(within(banner).getByText(/Vulnerability Intelligence/)).toBeInTheDocument();
  });

  it("lists every device worst-first with its score, category, and rank", async () => {
    render(
      <MemoryRouter>
        <RiskAssessmentPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-insecure")).toBeInTheDocument();
    expect(screen.getByText("device-hardened")).toBeInTheDocument();
    expect(screen.getByText("#1")).toBeInTheDocument();
    expect(screen.getByText("#2")).toBeInTheDocument();
    expect(screen.getByText("78")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
  });

  it("expands a row to show the full per-factor breakdown", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <RiskAssessmentPage />
      </MemoryRouter>,
    );

    const row = await screen.findByText("device-insecure");
    await user.click(row.closest("button")!);

    expect(await screen.findByText("Compliance (NCA CGIoT-1:2024)")).toBeInTheDocument();
    expect(screen.getByText("Highest CVSS")).toBeInTheDocument();
    expect(screen.getByText("Exploit availability (CISA KEV)")).toBeInTheDocument();
    expect(screen.getByText(/raw: 9\.8/)).toBeInTheDocument();
    // Both cvss and exploit_availability are weighted 20% - assert there
    // are at least two "weight 20%" lines rather than requiring exactly one.
    expect(screen.getAllByText(/weight 20%/).length).toBeGreaterThanOrEqual(2);
  });

  it("collapses an expanded row on a second click", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <RiskAssessmentPage />
      </MemoryRouter>,
    );

    const row = await screen.findByText("device-insecure");
    const button = row.closest("button")!;
    await user.click(button);
    await screen.findByText("Highest CVSS");

    await user.click(button);

    await waitFor(() => expect(screen.queryByText("Highest CVSS")).not.toBeInTheDocument());
  });

  it("links each expanded row's breakdown to the device detail page", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <RiskAssessmentPage />
      </MemoryRouter>,
    );

    const row = await screen.findByText("device-insecure");
    await user.click(row.closest("button")!);

    const link = await screen.findByRole("link", { name: /view device/i });
    expect(link).toHaveAttribute("href", "/devices/device-insecure");
  });
});
