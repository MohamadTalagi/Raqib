import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DevicesPage } from "./DevicesPage";
import { mockFetchImplementation } from "@/test/fixtures";
import { ToastProvider } from "@/lib/useToast";
import { api } from "@/lib/api";

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

    // Each registered device id now also appears a second time in the
    // cohort picker below the grid - getAllByText, not getByText.
    expect((await screen.findAllByText("device-insecure")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("device-hardened").length).toBeGreaterThan(0);
    expect(screen.getAllByText("device-partial").length).toBeGreaterThan(0);
  });

  it("no longer shows a security-tier badge on device cards", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findAllByText("device-insecure");
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

  it("links to the Discovery page instead of embedding the discovery panel itself", async () => {
    // Discovery is now its own pipeline page (Phase 5) - this page only
    // points at it, rather than embedding NetworkDiscoveryPanel directly.
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findAllByText("device-insecure");
    expect(screen.queryByText(/discover devices on the network/i)).not.toBeInTheDocument();
    const link = screen.getByRole("link", { name: /try discovery/i });
    expect(link).toHaveAttribute("href", "/discovery");
  });

  it("shows each device's furthest-reached pipeline phase as a badge", async () => {
    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findAllByText("device-insecure");
    const main = screen.getByRole("main");
    // device-insecure has real evidence/verdict/NCA/vuln/risk fixture data
    // reaching every phase, so its furthest badge is the pipeline's last step.
    expect(within(main).getAllByText("Risk Assessment").length).toBeGreaterThan(0);
  });

  // Regression: caught live. GET /risk/devices/{id}'s `known` flag and a
  // NOT_APPLICABLE verdict (created by the fleet-wide recompute for every
  // device regardless of whether any test ever ran) are both trivially true
  // the instant a device is registered - neither means "a real assessment
  // happened." device-hardened in this fixture has zero evidence and only a
  // NOT_APPLICABLE verdict, so its badge must stay "Devices," not jump ahead
  // to "NCA Compliance" or "Risk Assessment."
  it("does not advance a device's phase badge from a NOT_APPLICABLE-only verdict", async () => {
    vi.spyOn(api, "verdicts").mockResolvedValue([
      {
        verdict_id: "VD-2026-07-31-0005",
        control_id: "SA-IOT-004",
        device_id: "device-hardened",
        status: "NOT_APPLICABLE",
        severity: "high",
        evidence_ids: [],
        matched: "not_applicable",
        reason: "no required_evidence test_id applies to this device's registered services",
        saudi_source: "CGIoT-1:2024 §2-4-3",
        remediation: "Route all MQTT telemetry through the TLS-secured, authenticated broker; retire the plaintext broker.",
        timestamp: "2026-07-31T21:55:06Z",
        assessment_id: null,
        policy_version: "1.0.0",
        conflict_detected: false,
        conflict_reason: null,
      },
    ]);

    render(
      <MemoryRouter>
        <ToastProvider>
          <DevicesPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findAllByText("device-hardened");
    const hardenedCard = screen.getByRole("link", { name: /device-hardened/i });
    expect(within(hardenedCard).getByText("Devices")).toBeInTheDocument();
  });

  it("lets the auditor select registered devices and advance them to Fingerprinting", async () => {
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={["/devices"]}>
        <ToastProvider>
          <Routes>
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/fingerprinting" element={<div>Fingerprinting stub</div>} />
          </Routes>
        </ToastProvider>
      </MemoryRouter>,
    );

    await screen.findAllByText("device-insecure");
    expect(screen.getByRole("button", { name: /advance to fingerprinting/i })).toBeDisabled();

    // 3 registered devices in the fixture (hardened/insecure/partial) -
    // the unregistered card is excluded from the cohort picker entirely.
    await user.click(screen.getByRole("checkbox", { name: /select all \(3\)/i }));
    const advanceButton = screen.getByRole("button", { name: /advance to fingerprinting \(3\)/i });
    expect(advanceButton).toBeEnabled();

    await user.click(advanceButton);
    expect(await screen.findByText("Fingerprinting stub")).toBeInTheDocument();
  });
});
