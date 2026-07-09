import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EvidencePage } from "./EvidencePage";
import { mockFetchImplementation } from "@/test/fixtures";

describe("EvidencePage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders evidence rows and filters by search query", async () => {
    render(
      <MemoryRouter>
        <EvidencePage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("EV-2026-07-08-0013")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/search/i), "nonexistent-tool-xyz");
    expect(screen.getByText(/no evidence records match/i)).toBeInTheDocument();
  });

  it("expands a row to reveal the raw command", async () => {
    render(
      <MemoryRouter>
        <EvidencePage />
      </MemoryRouter>,
    );

    const row = await screen.findByText("EV-2026-07-08-0013");
    const user = userEvent.setup();
    await user.click(row);

    expect(await screen.findByText("nmap -sV -p- device-insecure")).toBeInTheDocument();
  });
});
