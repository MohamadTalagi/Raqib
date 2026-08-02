import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AutomatedRunProgressPage } from "./AutomatedRunProgressPage";
import { api } from "@/lib/api";
import type { AutomatedRun } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

function renderPage(runId = "42") {
  return render(
    <MemoryRouter initialEntries={[`/automated-run/${runId}`]}>
      <Routes>
        <Route path="/automated-run/:runId" element={<AutomatedRunProgressPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

const RUNNING: AutomatedRun = {
  id: 42,
  status: "running",
  device_ids: null,
  current_stage: "fingerprinting_and_compliance",
  summary: { hosts_discovered: 3, devices_registered: 1, tests_run: 4 },
  error: null,
  created_at: "2026-08-02T00:00:00Z",
  started_at: "2026-08-02T00:00:01Z",
  completed_at: null,
};

const COMPLETED: AutomatedRun = {
  ...RUNNING,
  status: "completed",
  current_stage: "done",
  completed_at: "2026-08-02T00:05:00Z",
  summary: { ...RUNNING.summary, nca_assessments_recorded: 2 },
};

describe("AutomatedRunProgressPage", () => {
  it("shows the stage and live summary counts while running", async () => {
    vi.spyOn(api, "getAutomatedRun").mockResolvedValue(RUNNING);
    renderPage();

    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(screen.getByText(/fingerprinting and sa-iot compliance/i)).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument(); // hosts discovered
  });

  it("shows a cancel button while in flight and calls the cancel endpoint", async () => {
    vi.spyOn(api, "getAutomatedRun").mockResolvedValue(RUNNING);
    const cancelSpy = vi.spyOn(api, "cancelAutomatedRun").mockResolvedValue({ ...RUNNING, status: "cancelled" });
    const user = userEvent.setup();
    renderPage();

    const cancelButton = await screen.findByRole("button", { name: /cancel run/i });
    await user.click(cancelButton);

    expect(cancelSpy).toHaveBeenCalledWith(42);
    expect(await screen.findByText("Cancelled")).toBeInTheDocument();
  });

  it("shows review links and no cancel button once completed", async () => {
    vi.spyOn(api, "getAutomatedRun").mockResolvedValue(COMPLETED);
    renderPage();

    expect(await screen.findByText("Completed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /cancel run/i })).not.toBeInTheDocument();
    expect(await screen.findByText("Review the results")).toBeInTheDocument();
    const links = screen.getAllByRole("link", { name: /nca compliance/i });
    expect(links.some((link) => link.getAttribute("href") === "/nca-compliance")).toBe(true);
  });

  it("shows warnings when the summary carries errors", async () => {
    vi.spyOn(api, "getAutomatedRun").mockResolvedValue({
      ...COMPLETED,
      summary: { ...COMPLETED.summary, errors: ["could not register host-10-0-0-9: 400"] },
    });
    renderPage();

    await waitFor(() => expect(screen.getByText(/could not register host-10-0-0-9/i)).toBeInTheDocument());
  });
});
