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

  it("does not resurrect Running if a stale in-flight poll resolves after cancel completes", async () => {
    // Regression: `cancelled` used to be a closure-local useEffect variable,
    // only ever set true on unmount - handleCancel (outside the effect)
    // never set it, so a poll GET already in flight when the cancel POST
    // resolved could overwrite `run` right back to "running" afterward,
    // and since it still saw an in-flight status it would silently
    // re-arm the next poll too. Uses real timers (the page's own real
    // ~1.5s poll interval) rather than fake timers, which fought with
    // Testing Library's own internal polling.
    let resolveSecondPoll!: (run: AutomatedRun) => void;
    const secondPoll = new Promise<AutomatedRun>((resolve) => {
      resolveSecondPoll = resolve;
    });
    const getSpy = vi
      .spyOn(api, "getAutomatedRun")
      .mockResolvedValueOnce(RUNNING) // initial fetch on mount
      .mockReturnValueOnce(secondPoll); // the next scheduled poll - stays in flight
    const cancelSpy = vi.spyOn(api, "cancelAutomatedRun").mockResolvedValue({ ...RUNNING, status: "cancelled" });

    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Running")).toBeInTheDocument();

    // Wait for the real scheduled poll to actually fire and be in flight.
    await waitFor(() => expect(getSpy).toHaveBeenCalledTimes(2), { timeout: 3000 });

    // Cancel while that second poll is still unresolved.
    await user.click(screen.getByRole("button", { name: /cancel run/i }));
    expect(cancelSpy).toHaveBeenCalledWith(42);
    expect(await screen.findByText("Cancelled")).toBeInTheDocument();

    // Now the stale poll response finally arrives.
    resolveSecondPoll(RUNNING);
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Must still show Cancelled, not flip back to Running, and must not
    // have scheduled yet another poll.
    expect(screen.getByText("Cancelled")).toBeInTheDocument();
    expect(screen.queryByText("Running")).not.toBeInTheDocument();
    expect(getSpy).toHaveBeenCalledTimes(2);
  });
});
