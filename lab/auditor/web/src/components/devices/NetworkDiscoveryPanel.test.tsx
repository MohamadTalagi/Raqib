import type { ComponentProps } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NetworkDiscoveryPanel, prefillFromHost } from "./NetworkDiscoveryPanel";
import { api } from "@/lib/api";
import type { Device, DiscoveredHost, NetworkScan } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

// The panel renders a <Link> (the "change" scope link) once its own
// activeScopes fetch resolves - wrapping in MemoryRouter here, not just in
// DiscoveryPage's own tests, matters: without a live auditor-api on the test
// host that fetch always used to fail (rendering no Link), but it must not
// depend on that accident - it should pass whether or not a real API happens
// to be reachable from wherever tests run.
function renderPanel(props: ComponentProps<typeof NetworkDiscoveryPanel>) {
  return render(
    <MemoryRouter>
      <NetworkDiscoveryPanel {...props} />
    </MemoryRouter>,
  );
}

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
  mac_address: null,
  mac_vendor: null,
  mac_vendor_source: null,
  discovery_signals: ["port_scan"],
};

const UNCERTAIN_HOST: DiscoveredHost = {
  ip: "172.30.0.3",
  hostname: "kaust-iot-lab-telnet-sim-1.kaust-iot-lab_audit-network",
  open_ports: [23],
  services: [{ port: 23, service: "telnet?", version: null }],
  classification: "uncertain",
  confidence: "low",
  rationale: "Only generic remote-administration port(s) 23 were open.",
  mac_address: null,
  mac_vendor: null,
  mac_vendor_source: null,
  discovery_signals: ["port_scan"],
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
      subnets: ["172.30.0.0/24"],
      hosts: [IOT_HOST, UNCERTAIN_HOST],
      iot_device_count: 1,
      uncertain_count: 1,
      unknown_count: 0,
      notes: ["Classification uses only the open-port/service signature."],
    },
    error: null,
    kind: "subnet_sweep",
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
    renderPanel({ devices: [], onRegisterHost: () => {}, onRegisterSelected: () => {} });

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
    renderPanel({ devices: [], onRegisterHost, onRegisterSelected: () => {} });
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.6");

    const registerButtons = screen.getAllByRole("button", { name: /^register$/i });
    await user.click(registerButtons[0]);

    expect(onRegisterHost).toHaveBeenCalledWith(
      expect.objectContaining({ device_id: "device-insecure", host: "172.30.0.6" }),
    );
  });

  it("renders a resolved MAC vendor with its source, and an honest unresolved note when there is none", async () => {
    const resolvedHost: DiscoveredHost = {
      ...IOT_HOST,
      mac_address: "28:6F:B9:11:22:33",
      mac_vendor: "Nokia Shanghai Bell Co., Ltd.",
      mac_vendor_source: "ieee_registry",
    };
    const unresolvedHost: DiscoveredHost = {
      ...UNCERTAIN_HOST,
      mac_address: "E6:4D:1A:E6:45:D7",
      mac_vendor: null,
      mac_vendor_source: null,
    };
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(
      makeScan({ status: "pending", observations: null }),
    );
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(
      makeScan({ observations: { subnets: ["172.30.0.0/24"], hosts: [resolvedHost, unresolvedHost], iot_device_count: 1, uncertain_count: 1, unknown_count: 0, notes: [] } }),
    );

    const user = userEvent.setup();
    renderPanel({ devices: [], onRegisterHost: () => {}, onRegisterSelected: () => {} });
    await user.click(screen.getByRole("button", { name: /scan network/i }));

    expect(await screen.findByText(/28:6F:B9:11:22:33/i)).toBeInTheDocument();
    expect(screen.getByText(/Nokia Shanghai Bell Co\.,? Ltd\./i)).toBeInTheDocument();
    expect(screen.getByText(/IEEE OUI registry/i)).toBeInTheDocument();
    expect(screen.getByText(/E6:4D:1A:E6:45:D7/i)).toBeInTheDocument();
    expect(screen.getByText(/vendor unknown/i)).toBeInTheDocument();
  });

  it("shows a broadcast-discovery indicator for a UDP-only host with no TCP port open", async () => {
    const udpOnlyHost: DiscoveredHost = {
      ip: "172.30.0.13",
      hostname: null,
      open_ports: [],
      services: [],
      classification: "iot_device",
      confidence: "high",
      rationale: "Responded to a broadcast discovery query with no TCP signature port open.",
      mac_address: null,
      mac_vendor: null,
      mac_vendor_source: null,
      discovery_signals: ["upnp_broadcast"],
    };
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(
      makeScan({ status: "pending", observations: null }),
    );
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(
      makeScan({ observations: { subnets: ["172.30.0.0/24"], hosts: [udpOnlyHost], iot_device_count: 1, uncertain_count: 0, unknown_count: 0, notes: [] } }),
    );

    const user = userEvent.setup();
    renderPanel({ devices: [], onRegisterHost: () => {}, onRegisterSelected: () => {} });
    await user.click(screen.getByRole("button", { name: /scan network/i }));

    expect(await screen.findByText(/found via/i)).toBeInTheDocument();
    expect(screen.getByText(/UPnP\/SSDP/i)).toBeInTheDocument();
    expect(screen.getByText(/no TCP port open/i)).toBeInTheDocument();
  });

  it("supports selecting multiple registerable hosts and registering them as a batch", async () => {
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(makeScan());
    const onRegisterSelected = vi.fn();

    const user = userEvent.setup();
    renderPanel({ devices: [], onRegisterHost: () => {}, onRegisterSelected });
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.6");

    await user.click(screen.getByRole("checkbox", { name: /select all registerable/i }));
    await user.click(screen.getByRole("button", { name: /register selected \(2\)/i }));

    expect(onRegisterSelected).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ ip: "172.30.0.6" }),
        expect.objectContaining({ ip: "172.30.0.3" }),
      ]),
    );
  });

  it("only offers a select-all/register-selected control for hosts that aren't already registered", async () => {
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(makeScan({ status: "pending", observations: null }));
    vi.spyOn(api, "getNetworkScan").mockResolvedValue(makeScan());
    const onRegisterSelected = vi.fn();

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
      firmware_version: null,
      identity_source: "manual",
      criticality: "medium",
      exposure: "internal_only",
      registered: true,
      evidence_count: 0,
      verdict_count: 0,
      services: [],
    };

    const user = userEvent.setup();
    renderPanel({ devices: [existingDevice], onRegisterHost: () => {}, onRegisterSelected });
    await user.click(screen.getByRole("button", { name: /scan network/i }));
    await screen.findByText("172.30.0.6");

    expect(screen.getByRole("checkbox", { name: /select all registerable \(1\)/i })).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: /select all registerable/i }));
    await user.click(screen.getByRole("button", { name: /register selected \(1\)/i }));

    expect(onRegisterSelected).toHaveBeenCalledWith([expect.objectContaining({ ip: "172.30.0.3" })]);
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
      firmware_version: null,
      identity_source: "manual",
      criticality: "medium",
      exposure: "internal_only",
      registered: true,
      evidence_count: 0,
      verdict_count: 0,
      services: [],
    };

    const user = userEvent.setup();
    renderPanel({ devices: [existingDevice], onRegisterHost: () => {}, onRegisterSelected: () => {} });
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
      firmware_version: null,
      identity_source: "manual",
      criticality: "medium",
      exposure: "internal_only",
      registered: true,
      evidence_count: 0,
      verdict_count: 0,
      services: [],
    };

    const user = userEvent.setup();
    renderPanel({ devices: [existingDevice], onRegisterHost: () => {}, onRegisterSelected: () => {} });
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
    renderPanel({ devices: [], onRegisterHost: () => {}, onRegisterSelected: () => {} });
    await user.click(screen.getByRole("button", { name: /scan network/i }));

    expect(await screen.findByText("nmap: command not found")).toBeInTheDocument();
  });
});
