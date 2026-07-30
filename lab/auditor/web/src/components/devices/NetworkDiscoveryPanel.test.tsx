import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NetworkDiscoveryPanel, prefillFromHost } from "./NetworkDiscoveryPanel";
import { api } from "@/lib/api";
import type { Device, DiscoveredHost, NetworkScan } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const IOT_HOST: DiscoveredHost = {
  ip: "172.30.0.6",
  hostname: "kaust-iot-lab-device-insecure-1.kaust-iot-lab_audit-network",
  open_ports: [23, 80],
  services: [
    { port: 23, service: "telnet?", version: null },
    { port: 80, service: "http", version: "Uvicorn" },
  ],
  classification: "iot_device",
  confidence: "high",
  rationale: "Exposed port(s) 80 - a management UI or IoT messaging-protocol port.",
};

const UNCERTAIN_HOST: DiscoveredHost = {
  ip: "172.30.0.3",
  hostname: "kaust-iot-lab-telnet-sim-1.kaust-iot-lab_audit-network",
  open_ports: [23],
  services: [{ port: 23, service: "telnet?", version: null }],
  classification: "uncertain",
  confidence: "low",
  rationale: "Only generic remote-administration port(s) 23 were open.",
};

function makeScan(overrides: Partial<NetworkScan> = {}): NetworkScan {
  return {
    id: 1,
    status: "completed",
    tool: "nmap",
    tool_version: "7.95",
    command: "nmap -sV -p 22,23,80,443,1883,8883 --open -T4 172.30.0.0/24",
    raw_output: "...",
    observations: {
      subnet: "172.30.0.0/24",
      hosts: [IOT_HOST, UNCERTAIN_HOST],
      iot_device_count: 1,
      uncertain_count: 1,
      unknown_count: 0,
      notes: ["Classification uses only the open-port/service signature."],
    },
    error: null,
    created_at: "2026-07-23T00:00:00Z",
    updated_at: "2026-07-23T00:00:00Z",
    ...overrides,
  };
}

describe("prefillFromHost", () => {
  it("derives a friendly device id/name from a lab-style container hostname", () => {
    const prefill = prefillFromHost(IOT_HOST);
    expect(prefill.device_id).toBe("device-insecure");
    expect(prefill.display_name).toBe("device-insecure");
    expect(prefill.host).toBe("172.30.0.6");
    expect(prefill.services).toEqual([
      { service_type: "telnet", port: 23 },
      { service_type: "http", port: 80 },
    ]);
  });

  it("falls back to an IP-based slug when the hostname doesn't match the lab's naming convention", () => {
    const prefill = prefillFromHost({ ...IOT_HOST, hostname: "some-random-router.local" });
    expect(prefill.device_id).toBe("host-172-30-0-6");
    expect(prefill.display_name).toBe("Host 172.30.0.6");
  });
});

describe("NetworkDiscoveryPanel", () => {
  it("launches a scan and shows classified results once completed", async () => {
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(makeScan());

    const user = userEvent.setup();
    render(<NetworkDiscoveryPanel devices={[]} onRegisterHost={() => {}} />);

    await user.click(screen.getByRole("button", { name: /scan network/i }));

    expect(await screen.findByText("172.30.0.6")).toBeInTheDocument();
    expect(screen.getByText("172.30.0.3")).toBeInTheDocument();
    expect(screen.getByText("IoT device")).toBeInTheDocument();
    expect(screen.getByText("Uncertain")).toBeInTheDocument();
  });

  it("offers a Register button per discovered host that calls onRegisterHost with a real prefill", async () => {
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(makeScan());
    const onRegisterHost = vi.fn();

    const user = userEvent.setup();
    render(<NetworkDiscoveryPanel devices={[]} onRegisterHost={onRegisterHost} />);
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.6");

    const registerButtons = screen.getAllByRole("button", { name: /^register$/i });
    await user.click(registerButtons[0]);

    expect(onRegisterHost).toHaveBeenCalledWith(
      expect.objectContaining({ device_id: "device-insecure", host: "172.30.0.6" }),
    );
  });

  it("shows 'Already registered' instead of a Register button for a host that matches an existing device", async () => {
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(makeScan());

    const existingDevice: Device = {
      device_id: "device-insecure",
      display_name: "Smart Camera — Insecure",
      description: "",
      tier: "insecure",
      host: "172.30.0.6",
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
      services: [],
    };

    const user = userEvent.setup();
    render(<NetworkDiscoveryPanel devices={[existingDevice]} onRegisterHost={() => {}} />);
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.6");

    expect(screen.getByText(/already registered/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^register$/i })).toHaveLength(1); // only the uncertain host
  });

  it("shows 'Already registered' when the existing device's host is the container name, not the IP", async () => {
    // Regression: this lab's own seeded devices register with the container
    // name as `host` (e.g. "device-insecure"), never the IP - matching only
    // by IP missed every one of them.
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(makeScan());

    const existingDevice: Device = {
      device_id: "device-insecure",
      display_name: "Smart Camera — Insecure",
      description: "",
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
      services: [],
    };

    const user = userEvent.setup();
    render(<NetworkDiscoveryPanel devices={[existingDevice]} onRegisterHost={() => {}} />);
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.6");

    expect(screen.getByText(/already registered/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^register$/i })).toHaveLength(1); // only the uncertain host
  });

  it("shows an error message when the scan itself fails", async () => {
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(
      makeScan({ status: "failed", observations: null, error: "nmap: command not found" }),
    );

    const user = userEvent.setup();
    render(<NetworkDiscoveryPanel devices={[]} onRegisterHost={() => {}} />);
    await user.click(screen.getByRole("button", { name: /scan network/i }));

    expect(await screen.findByText("nmap: command not found")).toBeInTheDocument();
  });
});
