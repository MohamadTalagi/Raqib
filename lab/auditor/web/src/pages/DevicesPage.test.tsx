import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DevicesPage } from "./DevicesPage";
import { mockFetchImplementation } from "@/test/fixtures";

describe("DevicesPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders a card per device", async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-insecure")).toBeInTheDocument();
    expect(screen.getByText("device-hardened")).toBeInTheDocument();
    expect(screen.getByText("device-partial")).toBeInTheDocument();
  });

  it("no longer shows a security-tier badge on device cards", async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    expect(screen.queryByText("Insecure")).not.toBeInTheDocument();
    expect(screen.queryByText("Hardened")).not.toBeInTheDocument();
  });

  it("renders a device with evidence but no device record as unregistered", async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-unregistered-cam")).toBeInTheDocument();
    expect(screen.getByText("Unregistered")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^register$/i })).toBeInTheDocument();
  });

  it("makes a registered device's whole card a link to its detail page", async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    const link = await screen.findByRole("link", { name: /device-insecure/i });
    expect(link).toHaveAttribute("href", "/devices/device-insecure");
  });

  it("does not render an unregistered card as a link to the (404-ing) detail page", async () => {
    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    await screen.findByText("device-unregistered-cam");
    expect(screen.queryByRole("link", { name: /device-unregistered-cam/i })).not.toBeInTheDocument();
  });

  it("opens the registration form pre-filled with the device id when Register is clicked on an unregistered card", async () => {
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <DevicesPage />
      </MemoryRouter>,
    );

    await screen.findByText("device-unregistered-cam");
    await user.click(screen.getByRole("button", { name: /^register$/i }));

    const deviceIdInput = await screen.findByLabelText(/device id/i);
    expect(deviceIdInput).toHaveValue("device-unregistered-cam");
  });
});
