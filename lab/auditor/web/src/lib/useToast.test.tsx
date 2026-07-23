import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, useToast } from "./useToast";

function Trigger() {
  const { showToast } = useToast();
  return (
    <>
      <button type="button" onClick={() => showToast("Saved successfully.", "success")}>
        Fire success
      </button>
      <button type="button" onClick={() => showToast("Something broke.", "error")}>
        Fire error
      </button>
    </>
  );
}

describe("useToast / ToastProvider", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("throws when used outside a ToastProvider", () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Trigger />)).toThrow(/must be used within a ToastProvider/);
    consoleSpy.mockRestore();
  });

  it("shows a toast message when showToast is called", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /fire success/i }));
    expect(screen.getByText("Saved successfully.")).toBeInTheDocument();
  });

  it("stacks multiple toasts at once", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /fire success/i }));
    await user.click(screen.getByRole("button", { name: /fire error/i }));

    expect(screen.getByText("Saved successfully.")).toBeInTheDocument();
    expect(screen.getByText("Something broke.")).toBeInTheDocument();
  });

  it("auto-dismisses a toast after its timeout", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /fire success/i }));
    expect(screen.getByText("Saved successfully.")).toBeInTheDocument();

    vi.advanceTimersByTime(5000);
    await waitFor(() => expect(screen.queryByText("Saved successfully.")).not.toBeInTheDocument());
  });

  it("dismisses a toast when its close button is clicked", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    );

    await user.click(screen.getByRole("button", { name: /fire success/i }));
    await user.click(screen.getByRole("button", { name: /dismiss notification/i }));

    expect(screen.queryByText("Saved successfully.")).not.toBeInTheDocument();
  });
});
