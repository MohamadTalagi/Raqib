import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OverviewPage } from "./OverviewPage";
import { mockFetchImplementation } from "@/test/fixtures";

describe("OverviewPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders summary stats once data loads", async () => {
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Evidence collected")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());
    expect(screen.getByText("Verdicts issued")).toBeInTheDocument();
  });

  it("shows highest-priority failures from verdict data", async () => {
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Highest-priority failures")).toBeInTheDocument();
  });

  it("shows per-device NCA compliance, worst first, linking to each device", async () => {
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("NCA CGIoT-1:2024 compliance by device")).toBeInTheDocument();
    const rows = screen.getAllByRole("link", { name: /device-/ });
    expect(rows.map((r) => r.textContent)).toEqual(["device-insecure", "device-hardened"]);
    expect(rows[0]).toHaveAttribute("href", "/devices/device-insecure");
    expect(screen.getByText("0%")).toBeInTheDocument();
    expect(screen.getByText("100%")).toBeInTheDocument();
  });
});
