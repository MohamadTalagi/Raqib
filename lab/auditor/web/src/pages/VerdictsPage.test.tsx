import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
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
        <VerdictsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Disable unnecessary network services")).toBeInTheDocument();
    expect(screen.getAllByText("PASS").length).toBeGreaterThan(0);
    expect(screen.getAllByText("FAIL").length).toBeGreaterThan(0);
  });

  it("filters verdicts by status", async () => {
    render(
      <MemoryRouter>
        <VerdictsPage />
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
        <VerdictsPage />
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
        <VerdictsPage />
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
