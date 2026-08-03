import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NetworkScopePage } from "./NetworkScopePage";
import { ToastProvider } from "@/lib/useToast";
import { api, ApiError } from "@/lib/api";
import type { InterfaceDetectObservations, NetworkScan, NetworkScope } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <NetworkScopePage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

const LAB_PRESET: NetworkScope = {
  id: 1,
  label: "Lab environment (Docker audit-network)",
  cidr: "172.30.0.0/24",
  kind: "lab_preset",
  source: "manual",
  is_active: true,
  added_by: "system:migration",
  reason: null,
  created_at: "2026-08-03T00:00:00Z",
  deactivated_at: null,
  deactivated_by: null,
};

describe("NetworkScopePage", () => {
  it("lists the lab preset scope by default", async () => {
    vi.spyOn(api, "listNetworkScopes").mockResolvedValue([LAB_PRESET]);

    renderPage();

    expect(await screen.findByText("172.30.0.0/24")).toBeInTheDocument();
    expect(screen.getByText("Built-in lab preset")).toBeInTheDocument();
  });

  it("adds a custom subnet and refreshes the list", async () => {
    vi.spyOn(api, "listNetworkScopes")
      .mockResolvedValueOnce([LAB_PRESET])
      .mockResolvedValueOnce([
        LAB_PRESET,
        { ...LAB_PRESET, id: 2, cidr: "10.5.0.0/24", label: "New VLAN", kind: "custom", added_by: "auditor" },
      ]);
    const create = vi.spyOn(api, "createNetworkScope").mockResolvedValue({
      ...LAB_PRESET,
      id: 2,
      cidr: "10.5.0.0/24",
      label: "New VLAN",
      kind: "custom",
      added_by: "auditor",
    });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("172.30.0.0/24");

    await user.type(screen.getByLabelText("Label"), "New VLAN");
    await user.type(screen.getByLabelText("Subnet (CIDR)"), "10.5.0.0/24");
    await user.type(screen.getByLabelText("Added by"), "auditor");
    await user.click(screen.getByRole("button", { name: /add scope/i }));

    await waitFor(() => expect(create).toHaveBeenCalledWith({
      label: "New VLAN",
      cidr: "10.5.0.0/24",
      added_by: "auditor",
      reason: undefined,
    }));
    expect(await screen.findByText("10.5.0.0/24")).toBeInTheDocument();
  });

  it("shows a field-specific error when adding an invalid subnet", async () => {
    vi.spyOn(api, "listNetworkScopes").mockResolvedValue([LAB_PRESET]);
    vi.spyOn(api, "createNetworkScope").mockRejectedValue(
      new ApiError("must be a private range", 400, "cidr"),
    );

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("172.30.0.0/24");

    await user.type(screen.getByLabelText("Label"), "Bad");
    await user.type(screen.getByLabelText("Subnet (CIDR)"), "8.8.8.0/24");
    await user.type(screen.getByLabelText("Added by"), "auditor");
    await user.click(screen.getByRole("button", { name: /add scope/i }));

    expect(await screen.findByText("must be a private range")).toBeInTheDocument();
  });

  it("shows the affected-device count before deactivating, and requires a name to confirm", async () => {
    vi.spyOn(api, "listNetworkScopes").mockResolvedValue([LAB_PRESET]);
    vi.spyOn(api, "networkScopeDeactivationImpact").mockResolvedValue({ affected_device_count: 3 });
    const deactivate = vi.spyOn(api, "deactivateNetworkScope").mockResolvedValue({
      ...LAB_PRESET,
      is_active: false,
      deactivated_by: "auditor",
      affected_device_count: 3,
    });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("172.30.0.0/24");

    await user.click(screen.getByRole("button", { name: "Deactivate" }));

    const dialog = await screen.findByRole("alertdialog");
    expect(await within(dialog).findByText(/3 registered device\(s\)/)).toBeInTheDocument();
    const confirmButton = within(dialog).getByRole("button", { name: "Deactivate" });
    expect(confirmButton).toBeDisabled();

    await user.type(within(dialog).getByLabelText("Your name"), "auditor");
    expect(confirmButton).not.toBeDisabled();
    await user.click(confirmButton);

    await waitFor(() =>
      expect(deactivate).toHaveBeenCalledWith(1, { actor: "auditor", reason: undefined }),
    );
  });

  it("reactivates an inactive scope", async () => {
    const inactive: NetworkScope = { ...LAB_PRESET, is_active: false, deactivated_by: "auditor" };
    vi.spyOn(api, "listNetworkScopes").mockResolvedValue([inactive]);
    const reactivate = vi.spyOn(api, "reactivateNetworkScope").mockResolvedValue({
      ...LAB_PRESET,
      is_active: true,
    });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("172.30.0.0/24");

    await user.click(screen.getByRole("button", { name: /reactivate/i }));

    await waitFor(() => expect(reactivate).toHaveBeenCalledWith(1));
  });

  it("detects candidate subnets and adds the selected ones", async () => {
    vi.spyOn(api, "listNetworkScopes").mockResolvedValue([LAB_PRESET]);

    const detectObservations: InterfaceDetectObservations = {
      candidates: [{ interface: "eth0", cidr: "172.30.0.0/24" }],
      excluded_backend_subnet: "172.31.0.0/24",
    };
    const pendingScan: NetworkScan = {
      id: 9,
      status: "pending",
      tool: null,
      tool_version: null,
      command: null,
      raw_output: null,
      observations: null,
      error: null,
      kind: "interface_detect",
      created_at: "2026-08-03T00:00:00Z",
      updated_at: "2026-08-03T00:00:00Z",
    };
    vi.spyOn(api, "createNetworkScan").mockResolvedValue(pendingScan);
    vi.spyOn(api, "getNetworkScan").mockResolvedValue({
      ...pendingScan,
      status: "completed",
      observations: detectObservations,
    });
    const create = vi.spyOn(api, "createNetworkScope").mockResolvedValue({
      ...LAB_PRESET,
      id: 3,
      source: "detected",
    });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("172.30.0.0/24");

    await user.click(screen.getByRole("button", { name: /detect automatically/i }));

    expect(await screen.findByText(/172.31.0.0\/24/)).toBeInTheDocument();
    // Both the Detect panel and the "Add a subnet" form below it have their
    // own "Added by" field once a detection has completed - the detect
    // panel's is the first one in DOM order.
    await user.type(screen.getAllByLabelText("Added by")[0], "auditor");
    await user.click(screen.getByRole("button", { name: /add selected/i }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        label: "Detected: eth0 (172.30.0.0/24)",
        cidr: "172.30.0.0/24",
        added_by: "auditor",
        source: "detected",
      }),
    );
  });
});
