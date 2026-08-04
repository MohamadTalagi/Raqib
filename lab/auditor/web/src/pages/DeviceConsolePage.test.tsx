import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeviceConsolePage } from "./DeviceConsolePage";
import { api } from "@/lib/api";
import type { Device } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

// Intentionally different ports/device set than the old hardcoded devices module
// (8081/8082/8083) so this test can only pass against an API-driven implementation.
const DEVICES: Device[] = [
  {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP.",
    tier: "insecure",
    host: "device-insecure",
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 1, service_type: "http", port: 80, published_port: 9081, enabled: true }],
  },
  {
    device_id: "device-partial",
    display_name: "Smart Camera — Partially Hardened",
    description: "Telnet removed, HTTPS with a weak cert.",
    tier: "partial",
    host: "device-partial",
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 2, service_type: "https", port: 443, published_port: 9082, enabled: true }],
  },
  {
    device_id: "device-hardened",
    display_name: "Smart Camera — Hardened",
    description: "HTTPS only, strong creds.",
    tier: "hardened",
    host: "device-hardened",
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 3, service_type: "https", port: 443, published_port: 9083, enabled: true }],
  },
  {
    device_id: "mqtt-only-device",
    display_name: "MQTT-only sensor",
    description: "No browser-reachable service.",
    tier: "unknown",
    host: "mqtt-only-device",
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: true,
    evidence_count: 0,
    verdict_count: 0,
    services: [{ id: 4, service_type: "mqtt", port: 1883, published_port: null, enabled: true }],
  },
  {
    device_id: "device-unregistered-cam",
    display_name: "Unregistered Test Camera",
    description: "Has evidence but no device record yet.",
    tier: "unknown",
    host: null,
    vendor: null,
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: null,
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
    criticality: "medium",
    exposure: "internal_only",
    registered: false,
    evidence_count: 1,
    verdict_count: 0,
    services: [],
  },
];

describe("DeviceConsolePage", () => {
  it("renders a card with every endpoint button for each registered device with a published HTTP service", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("http://localhost:9081")).toBeInTheDocument();
    expect(screen.getByText("https://localhost:9082")).toBeInTheDocument();
    expect(screen.getByText("https://localhost:9083")).toBeInTheDocument();

    // 3 consoles x 8 endpoints = 24 buttons total, each label appearing 3 times
    expect(screen.getAllByRole("button", { name: "Device info" })).toHaveLength(3);
    expect(screen.getAllByRole("button", { name: "Admin reset" })).toHaveLength(3);
  });

  it("no longer shows a security-tier badge on a console card", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    await screen.findByText("http://localhost:9081");
    expect(screen.queryByText("Insecure")).not.toBeInTheDocument();
    expect(screen.queryByText("Hardened")).not.toBeInTheDocument();
  });

  it("explains itself instead of rendering an empty card for a registered device with no browser-reachable HTTP service", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/MQTT-only sensor/)).toBeInTheDocument();
    expect(screen.getByText(/no browser-reachable/i)).toBeInTheDocument();
  });

  it("does not show an unregistered device at all", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    await screen.findByText("http://localhost:9081");
    expect(screen.queryByText(/Unregistered Test Camera/)).not.toBeInTheDocument();
  });

  it("calls the real endpoint and shows the live response when a button is clicked", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        expect(url).toBe("http://localhost:9081/api/device/info");
        return Promise.resolve(jsonResponse({ device_id: "device-insecure", vendor: "Hikvision" }));
      }),
    );

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    await screen.findByText("http://localhost:9081");
    const user = userEvent.setup();
    const [insecureInfoBtn] = screen.getAllByRole("button", { name: "Device info" });
    await user.click(insecureInfoBtn);

    expect(await screen.findByText(/"vendor": "Hikvision"/)).toBeInTheDocument();
    expect(screen.getByText("200")).toBeInTheDocument();
    expect(screen.getByText("GET /api/device/info")).toBeInTheDocument();
  });

  it("opens the real login page in a new tab in addition to showing the fetch result", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response("<html><body>login form</body></html>", { status: 200 }))),
    );
    const openSpy = vi.spyOn(window, "open").mockImplementation(() => null);

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    await screen.findByText("http://localhost:9081");
    const user = userEvent.setup();
    const [insecureLoginPageBtn] = screen.getAllByRole("button", { name: "Login page" });
    await user.click(insecureLoginPageBtn);

    expect(openSpy).toHaveBeenCalledWith("http://localhost:9081/", "_blank", "noopener,noreferrer");
    expect(await screen.findByText("GET /")).toBeInTheDocument();
  });

  it("shows a helpful cert hint when an HTTPS device fetch fails with no status", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))),
    );

    render(
      <MemoryRouter>
        <DeviceConsolePage />
      </MemoryRouter>,
    );

    await screen.findByText("https://localhost:9082");
    const user = userEvent.setup();
    const infoButtons = screen.getAllByRole("button", { name: "Device info" });
    // second console card is device-partial (https)
    await user.click(infoButtons[1]);

    expect(await screen.findByText(/self-signed lab certificate/i)).toBeInTheDocument();
  });
});
