import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DiscoveryPage } from "./DiscoveryPage";
import { mockFetchImplementation } from "@/test/fixtures";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";
import type { NetworkScan } from "@/lib/types";

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <DiscoveryPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function singleHostScan(): NetworkScan {
  return {
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
}

function twoHostScan(): NetworkScan {
  const scan = singleHostScan();
  return {
    ...scan,
    observations: {
      ...scan.observations!,
      hosts: [
        ...scan.observations!.hosts,
        {
          ip: "172.30.0.51",
          hostname: null,
          open_ports: [1883],
          services: [{ port: 1883, service: "mqtt", version: null }],
          classification: "iot_device",
          confidence: "high",
          rationale: "Exposed port(s) 1883.",
        },
      ],
      iot_device_count: 2,
    },
  };
}

describe("DiscoveryPage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  afterEach(() => vi.restoreAllMocks());

  it("renders the discovery panel directly, with no toggle needed", async () => {
    renderPage();
    expect(await screen.findByText(/discover devices on the network/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /scan network/i })).toBeInTheDocument();
  });

  it("registers a single discovered host through the pre-filled form", async () => {
    const scan = singleHostScan();
    vi.spyOn(api, "createNetworkScan").mockResolvedValue({ ...scan, status: "pending", observations: null });
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(scan);
    vi.spyOn(api, "createDevice").mockResolvedValue({ ...scan, id: 1 } as never);

    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    const hostIp = await screen.findByText("172.30.0.50");
    const hostRow = hostIp.closest("div")?.parentElement as HTMLElement;
    await user.click(within(hostRow).getByRole("button", { name: /^register$/i }));

    expect(screen.getByText(/discover devices on the network/i)).toBeInTheDocument();
    expect(screen.getByText("172.30.0.50")).toBeInTheDocument();
    expect(await screen.findByLabelText(/device id/i)).toHaveValue("host-172-30-0-50");
  });

  it("bulk-registers selected hosts via a confirm dialog", async () => {
    const scan = twoHostScan();
    vi.spyOn(api, "createNetworkScan").mockResolvedValue({ ...scan, status: "pending", observations: null });
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(scan);
    const createDevice = vi.spyOn(api, "createDevice").mockResolvedValue({} as never);

    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.50");

    await user.click(screen.getByRole("checkbox", { name: /select all registerable/i }));
    await user.click(screen.getByRole("button", { name: /register selected \(2\)/i }));

    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/register 2 device\(s\)\?/i)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: /^register$/i }));

    expect(await screen.findByText(/registered 2 device\(s\)/i)).toBeInTheDocument();
    expect(createDevice).toHaveBeenCalledTimes(2);
  });

  it("shows an inline error and keeps the dialog open if bulk registration fails", async () => {
    const scan = singleHostScan();
    vi.spyOn(api, "createNetworkScan").mockResolvedValue({ ...scan, status: "pending", observations: null });
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(scan);
    vi.spyOn(api, "createDevice").mockRejectedValue(new Error("device_id already exists"));

    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.50");

    await user.click(screen.getByRole("checkbox", { name: /select all registerable/i }));
    await user.click(screen.getByRole("button", { name: /register selected \(1\)/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /^register$/i }));

    expect(await screen.findByText("device_id already exists")).toBeInTheDocument();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });
});
