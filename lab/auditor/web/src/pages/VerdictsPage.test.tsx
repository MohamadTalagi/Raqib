import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { VerdictsPage } from "./VerdictsPage";
import { mockFetchImplementation } from "@/test/fixtures";

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
    await user.click(screen.getByRole("button", { name: "PASS" }));

    expect(screen.queryByText(/SA-IOT-002/)).not.toBeInTheDocument();
  });
});
