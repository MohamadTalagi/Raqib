import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DevicesPage } from "./DevicesPage";
import { mockFetchImplementation } from "@/test/fixtures";

describe("DevicesPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders a card per device with its tier badge", async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-insecure")).toBeInTheDocument();
    expect(screen.getByText("device-hardened")).toBeInTheDocument();
    expect(screen.getByText("device-partial")).toBeInTheDocument();
    expect(screen.getByText("Insecure")).toBeInTheDocument();
    expect(screen.getByText("Hardened")).toBeInTheDocument();
  });
});
