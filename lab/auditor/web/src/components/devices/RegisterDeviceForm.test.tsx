import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RegisterDeviceForm } from "./RegisterDeviceForm";
import { api, ApiError } from "@/lib/api";
import { ToastProvider } from "@/lib/useToast";

afterEach(() => vi.restoreAllMocks());

describe("RegisterDeviceForm", () => {
  it("submits the device with its services", async () => {
    const createDevice = vi
      .spyOn(api, "createDevice")
      .mockResolvedValue({ device_id: "test-camera", display_name: "Test Camera", services: [] } as never);
    const onRegistered = vi.fn();

    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={onRegistered} onCancel={() => {}} />
      </ToastProvider>,
    );

    fireEvent.change(screen.getByLabelText(/device id/i), {
      target: { value: "test-camera" },
    });
    fireEvent.change(screen.getByLabelText(/display name/i), {
      target: { value: "Test Camera" },
    });
    fireEvent.change(screen.getByLabelText(/host/i), {
      target: { value: "test-camera" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register device/i }));

    await waitFor(() => expect(createDevice).toHaveBeenCalled());
    const payload = createDevice.mock.calls[0][0];
    expect(payload.device_id).toBe("test-camera");
    expect(payload.services.length).toBeGreaterThan(0);
    // No security-tier control is offered any more - every device
    // registers as "unknown", matching the backend's own default.
    expect(payload.tier).toBe("unknown");
    await waitFor(() => expect(onRegistered).toHaveBeenCalled());
  });

  it("does not offer a security-tier control", () => {
    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );
    expect(screen.queryByLabelText(/security tier/i)).not.toBeInTheDocument();
  });

  it("does not offer service quick-pick buttons", () => {
    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );
    expect(screen.queryByText(/smart camera \(http\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/mqtt broker/i)).not.toBeInTheDocument();
  });

  it("shows the API error against the field that caused it", async () => {
    vi.spyOn(api, "createDevice").mockRejectedValue(
      new ApiError("IP must be inside 172.30.0.0/24", 400, "host"),
    );

    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );
    fireEvent.change(screen.getByLabelText(/device id/i), {
      target: { value: "bad" },
    });
    fireEvent.change(screen.getByLabelText(/display name/i), {
      target: { value: "Bad" },
    });
    fireEvent.change(screen.getByLabelText(/host/i), {
      target: { value: "10.0.0.5" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register device/i }));

    expect(await screen.findByText(/172\.30\.0\.0\/24/)).toBeInTheDocument();
  });

  it("shows a service-row API error even though the backend doesn't say which row", async () => {
    vi.spyOn(api, "createDevice").mockRejectedValue(
      new ApiError("port must be between 1 and 65535", 400, "port"),
    );

    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );
    fireEvent.change(screen.getByLabelText(/device id/i), {
      target: { value: "test-camera" },
    });
    fireEvent.change(screen.getByLabelText(/display name/i), {
      target: { value: "Test Camera" },
    });
    fireEvent.change(screen.getByLabelText(/host/i), {
      target: { value: "test-camera" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register device/i }));

    expect(await screen.findByText(/port must be between 1 and 65535/)).toBeInTheDocument();
  });

  it("still surfaces the message for a field name the frontend does not recognize", async () => {
    vi.spyOn(api, "createDevice").mockRejectedValue(
      new ApiError("some future validation failed", 400, "some_future_field"),
    );

    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );
    fireEvent.change(screen.getByLabelText(/device id/i), {
      target: { value: "test-camera" },
    });
    fireEvent.change(screen.getByLabelText(/display name/i), {
      target: { value: "Test Camera" },
    });
    fireEvent.change(screen.getByLabelText(/host/i), {
      target: { value: "test-camera" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register device/i }));

    expect(await screen.findByText(/some future validation failed/)).toBeInTheDocument();
  });

  it("pre-fills the device id field when an initialDeviceId is given", () => {
    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} initialDeviceId="device-unregistered-cam" />
      </ToastProvider>,
    );

    expect(screen.getByLabelText(/device id/i)).toHaveValue("device-unregistered-cam");
  });

  it("leaves the device id field empty when no initialDeviceId is given", () => {
    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );

    expect(screen.getByLabelText(/device id/i)).toHaveValue("");
  });

  it("pre-fills display name, host, and services from a network-discovery prefill", () => {
    render(
      <ToastProvider>
        <RegisterDeviceForm
          onRegistered={() => {}}
          onCancel={() => {}}
          initialDeviceId="device-insecure"
          initialDisplayName="device-insecure"
          initialHost="172.30.0.6"
          initialServices={[
            { service_type: "telnet", port: 23 },
            { service_type: "http", port: 80 },
          ]}
        />
      </ToastProvider>,
    );

    expect(screen.getByLabelText(/device id/i)).toHaveValue("device-insecure");
    expect(screen.getByLabelText(/display name/i)).toHaveValue("device-insecure");
    expect(screen.getByLabelText(/^host/i)).toHaveValue("172.30.0.6");
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(2);
    expect(screen.getByLabelText("Port 1")).toHaveValue("23");
    expect(screen.getByLabelText("Port 2")).toHaveValue("80");
  });

  it("can add and remove service rows", async () => {
    render(
      <ToastProvider>
        <RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />
      </ToastProvider>,
    );
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /add service/i }));
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(2);
    fireEvent.click(screen.getAllByRole("button", { name: /remove service/i })[1]);
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(1);
  });
});
