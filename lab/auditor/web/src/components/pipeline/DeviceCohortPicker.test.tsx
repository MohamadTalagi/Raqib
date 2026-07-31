import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DeviceCohortPicker } from "./DeviceCohortPicker";
import type { Device } from "@/lib/types";

function makeDevice(deviceId: string, displayName: string): Device {
  return {
    device_id: deviceId, display_name: displayName, description: "", tier: "unknown",
    host: deviceId, vendor: null, model: null, location: null, owner: null, notes: null,
    source: "manual", firmware_filename: null, firmware_sha256: null, firmware_uploaded_at: null,
    criticality: "medium", exposure: "internal_only", registered: true,
    evidence_count: 0, verdict_count: 0, services: [],
  };
}

const DEVICES = [makeDevice("device-a", "Device A"), makeDevice("device-b", "Device B")];

describe("DeviceCohortPicker", () => {
  it("shows an empty state when there are no devices", () => {
    render(<DeviceCohortPicker devices={[]} selected={new Set()} onChange={vi.fn()} />);
    expect(screen.getByText(/no devices registered/i)).toBeInTheDocument();
  });

  it("checking one device calls onChange with just that device added", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<DeviceCohortPicker devices={DEVICES} selected={new Set()} onChange={onChange} />);

    await user.click(screen.getByRole("checkbox", { name: /device a/i }));
    expect(onChange).toHaveBeenCalledWith(new Set(["device-a"]));
  });

  it("unchecking a selected device removes just that one from the set", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(
      <DeviceCohortPicker
        devices={DEVICES}
        selected={new Set(["device-a", "device-b"])}
        onChange={onChange}
      />,
    );

    await user.click(screen.getByRole("checkbox", { name: /device a/i }));
    expect(onChange).toHaveBeenCalledWith(new Set(["device-b"]));
  });

  it("select-all selects every device, and unchecking it clears the selection", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(
      <DeviceCohortPicker devices={DEVICES} selected={new Set()} onChange={onChange} />,
    );

    await user.click(screen.getByRole("checkbox", { name: /select all/i }));
    expect(onChange).toHaveBeenCalledWith(new Set(["device-a", "device-b"]));

    rerender(
      <DeviceCohortPicker devices={DEVICES} selected={new Set(["device-a", "device-b"])} onChange={onChange} />,
    );
    expect(screen.getByRole("checkbox", { name: /select all/i })).toBeChecked();

    await user.click(screen.getByRole("checkbox", { name: /select all/i }));
    expect(onChange).toHaveBeenCalledWith(new Set());
  });

  it("select-all is unchecked when only some devices are selected", () => {
    render(
      <DeviceCohortPicker devices={DEVICES} selected={new Set(["device-a"])} onChange={vi.fn()} />,
    );
    expect(screen.getByRole("checkbox", { name: /select all/i })).not.toBeChecked();
  });
});
