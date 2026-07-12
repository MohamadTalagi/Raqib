import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { DeviceConsolePage } from "./DeviceConsolePage";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("DeviceConsolePage", () => {
  it("renders a card with every endpoint button for each of the 3 devices", () => {
    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    expect(screen.getByText("http://localhost:8081")).toBeInTheDocument();
    expect(screen.getByText("https://localhost:8082")).toBeInTheDocument();
    expect(screen.getByText("https://localhost:8083")).toBeInTheDocument();

    // 3 devices x 8 endpoints = 24 buttons total, each label appearing 3 times
    expect(screen.getAllByRole("button", { name: "Device info" })).toHaveLength(3);
    expect(screen.getAllByRole("button", { name: "Admin reset" })).toHaveLength(3);
  });

  it("calls the real endpoint and shows the live response when a button is clicked", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        expect(url).toBe("http://localhost:8081/api/device/info");
        return Promise.resolve(jsonResponse({ device_id: "device-insecure", vendor: "AcmeCam" }));
      }),
    );

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    const [insecureInfoBtn] = screen.getAllByRole("button", { name: "Device info" });
    await user.click(insecureInfoBtn);

    expect(await screen.findByText(/"vendor": "AcmeCam"/)).toBeInTheDocument();
    expect(screen.getByText("200")).toBeInTheDocument();
    expect(screen.getByText("GET /api/device/info")).toBeInTheDocument();
  });

  it("shows a helpful cert hint when an HTTPS device fetch fails with no status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))),
    );

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    const infoButtons = screen.getAllByRole("button", { name: "Device info" });
    // second device card is device-partial (https)
    await user.click(infoButtons[1]);

    expect(await screen.findByText(/self-signed lab certificate/i)).toBeInTheDocument();
  });
});
