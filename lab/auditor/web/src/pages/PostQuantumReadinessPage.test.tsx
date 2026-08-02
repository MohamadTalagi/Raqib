import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PostQuantumReadinessPage } from "./PostQuantumReadinessPage";
import { api } from "@/lib/api";
import type { Device, DevicePqcReadiness, ScanTestSpec } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICES: Device[] = [
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
    services: [{ id: 1, service_type: "https", port: 443, published_port: 8083, enabled: true }],
  },
  {
    device_id: "device-unregistered-cam",
    display_name: "Unregistered Test Camera",
    description: "Not yet registered.",
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
    evidence_count: 0,
    verdict_count: 0,
    services: [],
  },
];

const SCAN_TESTS: ScanTestSpec[] = [
  {
    test_id: "TEST-PQC-TLS-HANDSHAKE",
    label: "Post-quantum TLS readiness",
    category: "network-and-protocol",
    applicable_service_types: ["https", "mqtts"],
    pipeline_phase: "pqc_readiness",
  },
];

const NOT_APPLICABLE_READINESS: DevicePqcReadiness = {
  device_id: "device-hardened",
  known: true,
  overall_status: "not_applicable",
  fail_count: 0,
  tls_key_exchange: { status: "not_applicable", negotiated_group: null },
  certificate_signature: { status: "not_applicable", signature_algorithm: null },
  firmware_crypto: { status: "not_applicable", packages: [] },
};

describe("PostQuantumReadinessPage", () => {
  it("offers only registered devices in the cohort picker", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.spyOn(api, "scanTests").mockResolvedValue(SCAN_TESTS);
    vi.spyOn(api, "pqcReadinessDevice").mockResolvedValue(NOT_APPLICABLE_READINESS);

    render(
      <MemoryRouter>
        <PostQuantumReadinessPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("device-hardened")).toBeInTheDocument();
    expect(screen.queryByText("device-unregistered-cam")).not.toBeInTheDocument();
  });

  it("shows a DevicePqcReadinessCard for each selected device", async () => {
    vi.spyOn(api, "devices").mockResolvedValue(DEVICES);
    vi.spyOn(api, "scanTests").mockResolvedValue(SCAN_TESTS);
    vi.spyOn(api, "pqcReadinessDevice").mockResolvedValue(NOT_APPLICABLE_READINESS);
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <PostQuantumReadinessPage />
      </MemoryRouter>,
    );

    await screen.findByText("device-hardened");
    await user.click(screen.getByRole("checkbox", { name: /select all \(1\)/i }));

    expect(await screen.findByRole("checkbox", { name: "Post-quantum TLS readiness" })).toBeInTheDocument();
  });
});
