import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AutomatedRunDialog } from "./AutomatedRunDialog";
import { api, ApiError } from "@/lib/api";
import type { AutomatedRun } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const RUN: AutomatedRun = {
  id: 42,
  status: "pending",
  device_ids: null,
  current_stage: null,
  summary: {},
  error: null,
  created_at: "2026-08-02T00:00:00Z",
  started_at: null,
  completed_at: null,
};

describe("AutomatedRunDialog", () => {
  it("does not render anything when closed", () => {
    render(<AutomatedRunDialog open={false} onCancel={vi.fn()} onStarted={vi.fn()} />);
    expect(screen.queryByText(/start a fully automated run/i)).not.toBeInTheDocument();
  });

  it("explains what will run and what is skipped", () => {
    render(<AutomatedRunDialog open onCancel={vi.fn()} onStarted={vi.fn()} />);
    expect(screen.getByText(/scans the network and registers/i)).toBeInTheDocument();
    expect(screen.getByText(/never automated/i)).toBeInTheDocument();
  });

  it("creates the run and reports it back on confirm", async () => {
    const createSpy = vi.spyOn(api, "createAutomatedRun").mockResolvedValue(RUN);
    const onStarted = vi.fn();
    const user = userEvent.setup();
    render(<AutomatedRunDialog open onCancel={vi.fn()} onStarted={onStarted} />);

    await user.click(screen.getByRole("button", { name: /start fully automated run/i }));

    expect(createSpy).toHaveBeenCalledWith();
    expect(onStarted).toHaveBeenCalledWith(RUN);
  });

  it("shows an error message and does not call onStarted when creation fails", async () => {
    vi.spyOn(api, "createAutomatedRun").mockRejectedValue(new ApiError("no lab devices found", 400));
    const onStarted = vi.fn();
    const user = userEvent.setup();
    render(<AutomatedRunDialog open onCancel={vi.fn()} onStarted={onStarted} />);

    await user.click(screen.getByRole("button", { name: /start fully automated run/i }));

    expect(await screen.findByText("no lab devices found")).toBeInTheDocument();
    expect(onStarted).not.toHaveBeenCalled();
  });

  it("calls onCancel when Cancel is clicked", async () => {
    const onCancel = vi.fn();
    const user = userEvent.setup();
    render(<AutomatedRunDialog open onCancel={onCancel} onStarted={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalled();
  });
});
