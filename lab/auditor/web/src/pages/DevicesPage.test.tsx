import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DevicesPage } from "./DevicesPage";
import { mockFetchImplementation } from "@/test/fixtures";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";
import type { NetworkScan } from "@/lib/types";

describe("DevicesPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  afterEach(() => vi.restoreAllMocks());

  it("renders a card per device", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-insecure")).toBeInTheDocument();
    expect(screen.getByText("device-hardened")).toBeInTheDocument();
    expect(screen.getByText("device-partial")).toBeInTheDocument();
  });

  it("no longer shows a security-tier badge on device cards", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    expect(screen.queryByText("Insecure")).not.toBeInTheDocument();
    expect(screen.queryByText("Hardened")).not.toBeInTheDocument();
  });

  it("renders a device with evidence but no device record as unregistered", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-unregistered-cam")).toBeInTheDocument();
    expect(screen.getByText("Unregistered")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^register$/i })).toBeInTheDocument();
  });

  it("makes a registered device's whole card a link to its detail page", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    const link = await screen.findByRole("link", { name: /device-insecure/i });
    expect(link).toHaveAttribute("href", "/devices/device-insecure");
  });

  it("does not render an unregistered card as a link to the (404-ing) detail page", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-unregistered-cam");
    expect(screen.queryByRole("link", { name: /device-unregistered-cam/i })).not.toBeInTheDocument();
  });

  it("opens the registration form pre-filled with the device id when Register is clicked on an unregistered card", async () => {
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-unregistered-cam");
    await user.click(screen.getByRole("button", { name: /^register$/i }));

    const deviceIdInput = await screen.findByLabelText(/device id/i);
    expect(deviceIdInput).toHaveValue("device-unregistered-cam");
  });

  it("reveals the network discovery panel, offering it as an alternative to manual registration", async () => {
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    expect(screen.queryByText(/discover devices on the network/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /discover devices/i }));
    expect(screen.getByText(/discover devices on the network/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /scan network/i })).toBeInTheDocument();
  });

  it("keeps the discovery panel and its results visible while registering a discovered host", async () => {
    // Registering one discovered host from a scan of several shouldn't force
    // a rescan to register the next one - the panel and its results must
    // stay mounted, not disappear the moment the form opens.
    const scan: NetworkScan = {
      id: 1,
      status: "completed",
      tool: "nmap",
      tool_version: "7.95",
      command: "nmap ...",
      raw_output: "...",
      observations: {
        subnet: "172.30.0.0/24",
        hosts: [
          {
            ip: "172.30.0.50",
            hostname: null,
            open_ports: [80],
            services: [{ port: 80, service: "http", version: null }],
            classification: "iot_device",
            confidence: "high",
            rationale: "Exposed port(s) 80.",
          },
        ],
        iot_device_count: 1,
        uncertain_count: 0,
        unknown_count: 0,
        notes: [],
      },
      error: null,
      created_at: "2026-07-23T00:00:00Z",
      updated_at: "2026-07-23T00:00:00Z",
    };
    vi.spyOn(api, "createNetworkScan").mockResolvedValue({ ...scan, status: "pending", observations: null });
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(scan);

    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findByText("device-insecure");
    await user.click(screen.getByRole("button", { name: /discover devices/i }));
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    const hostIp = await screen.findByText("172.30.0.50");
    const hostRow = hostIp.closest("div")?.parentElement as HTMLElement;
    await user.click(within(hostRow).getByRole("button", { name: /^register$/i }));

    expect(screen.getByText(/discover devices on the network/i)).toBeInTheDocument();
    expect(screen.getByText("172.30.0.50")).toBeInTheDocument();
    expect(await screen.findByLabelText(/device id/i)).toHaveValue("host-172-30-0-50");
  });
});
