import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DevicePqcReadinessCard } from "./DevicePqcReadinessCard";
import { api } from "@/lib/api";
import type { Device, DevicePqcReadiness, ScanTestSpec } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DEVICE_HARDENED_NO_FIRMWARE: Device = {
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
};

const DEVICE_HARDENED_WITH_FIRMWARE: Device = {
  ...DEVICE_HARDENED_NO_FIRMWARE,
  firmware_filename: "cam-fw-1.2.0.tar.gz",
  firmware_sha256: "b".repeat(64),
  firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
};

const DEVICE_NO_TLS: Device = {
  ...DEVICE_HARDENED_NO_FIRMWARE,
  device_id: "device-insecure",
  display_name: "Smart Camera — Insecure",
  host: "device-insecure",
  services: [{ id: 2, service_type: "http", port: 80, published_port: 8081, enabled: true }],
};

const SCAN_TESTS: ScanTestSpec[] = [
  {
    test_id: "TEST-PQC-TLS-HANDSHAKE",
    label: "Post-quantum TLS readiness",
    category: "network-and-protocol",
    applicable_service_types: ["https", "mqtts"],
    pipeline_phase: "pqc_readiness",
  },
  {
    test_id: "TEST-PQC-FIRMWARE-CRYPTO",
    label: "Post-quantum firmware crypto currency",
    category: "firmware",
    applicable_service_types: [],
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

function renderCard(device: Device) {
  return render(
    <MemoryRouter>
      <DevicePqcReadinessCard device={device} scanTests={SCAN_TESTS} />
    </MemoryRouter>,
  );
}

describe("DevicePqcReadinessCard", () => {
  it("shows the TLS handshake test for a device with an HTTPS service", async () => {
    vi.spyOn(api, "pqcReadinessDevice").mockResolvedValue(NOT_APPLICABLE_READINESS);
    renderCard(DEVICE_HARDENED_NO_FIRMWARE);

    expect(await screen.findByRole("checkbox", { name: "Post-quantum TLS readiness" })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: "Post-quantum firmware crypto currency" })).not.toBeInTheDocument();
  });

  it("also shows the firmware crypto test once firmware is uploaded", async () => {
    vi.spyOn(api, "pqcReadinessDevice").mockResolvedValue(NOT_APPLICABLE_READINESS);
    renderCard(DEVICE_HARDENED_WITH_FIRMWARE);

    expect(await screen.findByRole("checkbox", { name: "Post-quantum TLS readiness" })).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Post-quantum firmware crypto currency" })).toBeInTheDocument();
  });

  it("explains there's nothing to check for a device with no TLS service", async () => {
    vi.spyOn(api, "pqcReadinessDevice").mockResolvedValue({
      ...NOT_APPLICABLE_READINESS,
      device_id: "device-insecure",
    });
    renderCard(DEVICE_NO_TLS);

    expect(await screen.findByText(/no tls-capable service/i)).toBeInTheDocument();
    expect(screen.getByText(/upload firmware/i)).toBeInTheDocument();
  });

  it("renders the live 3-criterion breakdown once evidence exists", async () => {
    vi.spyOn(api, "pqcReadinessDevice").mockResolvedValue({
      device_id: "device-hardened",
      known: true,
      overall_status: "fail",
      fail_count: 1,
      tls_key_exchange: { status: "pass", negotiated_group: "X25519MLKEM768" },
      certificate_signature: {
        status: "fail",
        signature_algorithm: "sha256WithRSAEncryption",
        tip: "Deploy an ML-DSA or SLH-DSA certificate once your CA supports it.",
      },
      firmware_crypto: { status: "not_applicable", packages: [] },
    });
    renderCard(DEVICE_HARDENED_NO_FIRMWARE);

    expect(await screen.findByText("Negotiated group: X25519MLKEM768")).toBeInTheDocument();
    expect(screen.getByText("sha256WithRSAEncryption")).toBeInTheDocument();
    expect(screen.getByText(/deploy an ml-dsa or slh-dsa certificate/i)).toBeInTheDocument();
  });
});
