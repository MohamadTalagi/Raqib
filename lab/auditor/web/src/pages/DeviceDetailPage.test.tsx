import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeviceDetailPage } from "./DeviceDetailPage";
import { api, ApiError } from "@/lib/api";
import type { DeviceDetail } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const DETAIL: DeviceDetail = {
  device: {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP.",
    tier: "insecure",
    host: "device-insecure",
    vendor: "AcmeCam",
    model: null,
    location: null,
    owner: null,
    notes: null,
    source: "seeded",
    firmware_filename: null,
    firmware_sha256: null,
    firmware_uploaded_at: null,
  },
  services: [{ id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true }],
  evidence: [
    {
      evidence_id: "EV-1",
      test_id: "TEST-NET-PORTSCAN",
      tool: "nmap",
      finding: "Telnet exposed",
      confidence: "high",
      timestamp: "2026-07-08T10:00:00+00:00",
    },
  ],
  verdicts: [
    {
      verdict_id: "V-1",
      control_id: "SA-IOT-002",
      status: "FAIL",
      severity: "high",
      reason: "default creds accepted",
      timestamp: "2026-07-08T10:05:00+00:00",
    },
  ],
  scan_jobs: [],
  compliance: { framework: "CGIoT-1:2024", tested_controls: 1, passing_controls: 0, percentage: 0 },
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/devices/device-insecure"]}>
      <Routes>
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("DeviceDetailPage", () => {
  it("shows the device's NCA compliance percentage", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("0%")).toBeInTheDocument();
    expect(screen.getByText(/CGIoT-1:2024:/)).toBeInTheDocument();
  });

  it("shows 'not assessed' when no controls have been tested for this device", async () => {
    vi.spyOn(api, "device").mockResolvedValue({
      ...DETAIL,
      compliance: { framework: "CGIoT-1:2024", tested_controls: 0, passing_controls: 0, percentage: null },
    });
    renderPage();

    expect(await screen.findByText("NOT ASSESSED")).toBeInTheDocument();
  });

  it("shows the device, its evidence and verdicts together", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByText("Smart Camera — Insecure")).toBeInTheDocument();
    expect(screen.getByText("AcmeCam")).toBeInTheDocument();
    expect(screen.getByText("Telnet exposed")).toBeInTheDocument();
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();
  });

  it("renders an error state when the device is missing", async () => {
    vi.spyOn(api, "device").mockRejectedValue(new Error("device not found"));
    renderPage();
    await waitFor(() => expect(screen.getByText(/device not found/i)).toBeInTheDocument());
  });

  it("offers a download link to the device report", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL as never);
    renderPage();

    const link = await screen.findByRole("link", { name: /download report/i });
    expect(link).toHaveAttribute("href", expect.stringContaining("/devices/device-insecure/report.pdf"));
  });

  it("shows a Deregister control on the detail page", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByRole("button", { name: /deregister/i })).toBeInTheDocument();
  });

  it("does not call deleteDevice immediately on click — a confirmation appears first", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const deleteSpy = vi.spyOn(api, "deleteDevice").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));

    expect(deleteSpy).not.toHaveBeenCalled();
    expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
  });

  it("calls deleteDevice with the correct device id when the confirmation is confirmed", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const deleteSpy = vi.spyOn(api, "deleteDevice").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /deregister device/i }));

    await waitFor(() => expect(deleteSpy).toHaveBeenCalledWith("device-insecure"));
  });

  it("does not call deleteDevice when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const deleteSpy = vi.spyOn(api, "deleteDevice").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));

    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(deleteSpy).not.toHaveBeenCalled();
  });

  it("states in the confirmation that evidence and verdicts are kept, not deleted", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /deregister/i }));
    const dialog = await screen.findByRole("alertdialog");

    expect(within(dialog).getByText(/evidence.*(kept|preserved|retained|not deleted)/i)).toBeInTheDocument();
  });

  it("shows an upload control when no firmware has been uploaded yet", async () => {
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    renderPage();

    expect(await screen.findByLabelText(/firmware archive/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /upload firmware/i })).toBeDisabled();
  });

  it("uploads firmware and then shows its filename and hash", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    const uploadSpy = vi.spyOn(api, "uploadFirmware").mockResolvedValue({
      ...DETAIL.device,
      firmware_filename: "cam-fw-1.2.0.tar.gz",
      firmware_sha256: "b".repeat(64),
      firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
      services: DETAIL.services,
    });
    renderPage();

    const file = new File(["dummy"], "cam-fw-1.2.0.tar.gz", { type: "application/gzip" });
    const input = await screen.findByLabelText(/firmware archive/i);
    await user.upload(input, file);

    const uploadButton = screen.getByRole("button", { name: /upload firmware/i });
    expect(uploadButton).toBeEnabled();
    await user.click(uploadButton);

    await waitFor(() => expect(uploadSpy).toHaveBeenCalledWith("device-insecure", file));
    expect(await screen.findByText("cam-fw-1.2.0.tar.gz")).toBeInTheDocument();
    expect(screen.getByText(/b{16}…/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /remove firmware/i })).toBeInTheDocument();
  });

  it("surfaces the API's error message when a firmware upload is rejected", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "device").mockResolvedValue(DETAIL);
    vi.spyOn(api, "uploadFirmware").mockRejectedValue(
      new ApiError("not a valid .tar.gz archive", 400),
    );
    renderPage();

    const file = new File(["dummy"], "cam-fw.tar.gz", { type: "application/gzip" });
    const input = await screen.findByLabelText(/firmware archive/i);
    await user.upload(input, file);
    await user.click(screen.getByRole("button", { name: /upload firmware/i }));

    expect(await screen.findByText(/not a valid \.tar\.gz archive/i)).toBeInTheDocument();
  });

  it("removes firmware and reverts to the upload control", async () => {
    const user = userEvent.setup();
    const withFirmware: DeviceDetail = {
      ...DETAIL,
      device: {
        ...DETAIL.device,
        firmware_filename: "cam-fw-1.2.0.tar.gz",
        firmware_sha256: "b".repeat(64),
        firmware_uploaded_at: "2026-07-21T12:00:00+00:00",
      },
    };
    vi.spyOn(api, "device").mockResolvedValue(withFirmware);
    const deleteSpy = vi.spyOn(api, "deleteFirmware").mockResolvedValue(undefined);
    renderPage();

    await user.click(await screen.findByRole("button", { name: /remove firmware/i }));

    await waitFor(() => expect(deleteSpy).toHaveBeenCalledWith("device-insecure"));
    expect(await screen.findByLabelText(/firmware archive/i)).toBeInTheDocument();
  });
});
