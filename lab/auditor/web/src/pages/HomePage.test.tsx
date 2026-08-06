import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HomePage } from "./HomePage";
import { api } from "@/lib/api";
import { mockFetchImplementation } from "@/test/fixtures";
import type { AutomatedRun } from "@/lib/types";

const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const RUN: AutomatedRun = {
  id: 7,
  status: "pending",
  device_ids: null,
  current_stage: null,
  summary: {},
  error: null,
  created_at: "2026-08-06T00:00:00Z",
  started_at: null,
  completed_at: null,
};

describe("HomePage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  afterEach(() => {
    navigateMock.mockClear();
    vi.restoreAllMocks();
  });

  it("renders all three primary action buttons", () => {
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    expect(screen.getByRole("button", { name: /start a manual run/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start an automated run/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /view devices/i })).toBeInTheDocument();
  });

  it("navigates to Fingerprinting on 'Start a manual run'", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: /start a manual run/i }));
    expect(navigateMock).toHaveBeenCalledWith("/fingerprinting");
  });

  it("navigates to Devices on 'View devices'", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: /view devices/i }));
    expect(navigateMock).toHaveBeenCalledWith("/devices");
  });

  it("opens the Automated Run confirmation dialog and navigates on start", async () => {
    vi.spyOn(api, "createAutomatedRun").mockResolvedValue(RUN);
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: /start an automated run/i }));
    expect(screen.getByText(/start a fully automated run\?/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^start fully automated run$/i }));
    expect(navigateMock).toHaveBeenCalledWith("/automated-run/7");
  });

  it("shows a minimal fleet stat line once summary/devices load", async () => {
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText(/devices monitored/i)).toBeInTheDocument());
    expect(screen.getByText(/evidence collected/i)).toBeInTheDocument();
    expect(screen.getByText(/verdicts issued/i)).toBeInTheDocument();
  });
});
