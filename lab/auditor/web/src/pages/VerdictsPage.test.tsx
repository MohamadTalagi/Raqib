import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/lib/useToast";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { VerdictsPage } from "./VerdictsPage";
import { api } from "@/lib/api";
import { controlsFixture, mockFetchImplementation, verdictsFixture } from "@/test/fixtures";
import type { VerdictRecord } from "@/lib/types";

describe("VerdictsPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders a verdict card per record with control title from /controls", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Disable unnecessary network services")).toBeInTheDocument();
    expect(screen.getAllByText("PASS").length).toBeGreaterThan(0);
    expect(screen.getAllByText("FAIL").length).toBeGreaterThan(0);
  });

  it("filters verdicts by status", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("Disable unnecessary network services");
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: /^PASS/ }));

    expect(screen.queryByText(/SA-IOT-002/)).not.toBeInTheDocument();
  });

  it("offers a NOT_APPLICABLE filter and filters by it", async () => {
    const notApplicable: VerdictRecord = {
      ...verdictsFixture[0],
      verdict_id: "VD-2026-07-22-0001",
      control_id: "SA-IOT-004",
      status: "NOT_APPLICABLE",
      reason: "No MQTT service registered for this device.",
    };
    vi.spyOn(api, "verdicts").mockResolvedValue([...verdictsFixture, notApplicable]);
    vi.spyOn(api, "controls").mockResolvedValue(controlsFixture);

    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("Disable unnecessary network services");
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: /^NOT_APPLICABLE/ }));

    const [heading] = screen.getAllByText(/SA-IOT-004/);
    await user.click(heading.closest("button") as HTMLButtonElement);

    expect(screen.getByText(/No MQTT service registered/)).toBeInTheDocument();
    expect(screen.queryByText(/SA-IOT-002/)).not.toBeInTheDocument();
  });

  it("filters verdicts by severity", async () => {
    // fixture[0] is high (SA-IOT-003), fixture[1] is critical (SA-IOT-002).
    vi.spyOn(api, "verdicts").mockResolvedValue(verdictsFixture);
    vi.spyOn(api, "controls").mockResolvedValue(controlsFixture);

    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("Disable unnecessary network services");
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText("Filter by severity"), "critical");

    // Only the critical SA-IOT-002 verdict remains; the high SA-IOT-003 is gone.
    expect(screen.getAllByText(/SA-IOT-002/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/SA-IOT-003/)).not.toBeInTheDocument();
  });

  it("filters verdicts by device", async () => {
    const otherDevice: VerdictRecord = {
      ...verdictsFixture[0],
      verdict_id: "VD-2026-07-22-0009",
      control_id: "SA-IOT-003",
      device_id: "device-hardened",
    };
    vi.spyOn(api, "verdicts").mockResolvedValue([...verdictsFixture, otherDevice]);
    vi.spyOn(api, "controls").mockResolvedValue(controlsFixture);

    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    // Two rows share the SA-IOT-003 title pre-filter, so wait on the select itself.
    await screen.findByLabelText("Filter by device");
    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText("Filter by device"), "device-hardened");

    // Only device-hardened rows remain. SA-IOT-002 is the device-insecure
    // verdict and only ever appears in a row (not in the device dropdown), so
    // its absence proves the insecure device's verdicts are filtered out.
    expect(screen.getAllByText(/device-hardened/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/SA-IOT-002/)).not.toBeInTheDocument();
  });

  it("opens the assess dialog and assesses a new verdict for a chosen device/control/severity", async () => {
    const assessSpy = vi.spyOn(api, "assessControlVerdict").mockResolvedValue({
      ...verdictsFixture[0],
      verdict_id: "VD-NEW-0001",
      control_id: "SA-IOT-003",
      device_id: "device-insecure",
      status: "FAIL",
      severity: "low",
    });

    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /assess verdict/i }));

    const dialog = await screen.findByRole("dialog");
    // Wait for the async device/control options to load into the dialog.
    await within(dialog).findByRole("option", { name: "device-insecure" });
    await user.selectOptions(within(dialog).getByLabelText("Device"), "device-insecure");
    await user.selectOptions(within(dialog).getByLabelText("Control"), "SA-IOT-003");
    await user.selectOptions(within(dialog).getByLabelText("Severity"), "low");
    await user.click(within(dialog).getByRole("button", { name: /assess verdict/i }));

    expect(assessSpy).toHaveBeenCalledWith("device-insecure", "SA-IOT-003", "low");
  });

  it("shows the backend error inline when a control has no evidence to assess", async () => {
    vi.spyOn(api, "assessControlVerdict").mockRejectedValue(
      new (await import("@/lib/api")).ApiError("This control has no automated collector, so it can't be assessed from a scan.", 400),
    );

    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /assess verdict/i }));

    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByRole("option", { name: "device-insecure" });
    await user.selectOptions(within(dialog).getByLabelText("Device"), "device-insecure");
    await user.selectOptions(within(dialog).getByLabelText("Control"), "SA-IOT-003");
    await user.click(within(dialog).getByRole("button", { name: /assess verdict/i }));

    expect(await within(dialog).findByText(/no automated collector/i)).toBeInTheDocument();
  });

  it("shows a conflict indicator and the policy version in an expanded verdict", async () => {
    const conflicted: VerdictRecord = {
      ...verdictsFixture[0],
      verdict_id: "VD-2026-07-22-0002",
      policy_version: "1.1.0",
      conflict_detected: true,
      conflict_reason: "Automated evidence disagrees with a manually recorded finding.",
    };
    vi.spyOn(api, "verdicts").mockResolvedValue([conflicted]);
    vi.spyOn(api, "controls").mockResolvedValue(controlsFixture);

    render(
      <MemoryRouter>
        <ToastProvider>
          <VerdictsPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    const title = await screen.findByText("Disable unnecessary network services");
    expect(screen.getByText("Conflict")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(title.closest("button") as HTMLButtonElement);

    expect(screen.getByText(/Automated evidence disagrees with a manually recorded finding\./)).toBeInTheDocument();
    expect(screen.getByText("1.1.0")).toBeInTheDocument();
  });
});
