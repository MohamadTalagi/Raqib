import { useState } from "react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { RegisterDeviceForm } from "@/components/devices/RegisterDeviceForm";
import {
  NetworkDiscoveryPanel,
  prefillFromHost,
  type DeviceRegistrationPrefill,
} from "@/components/devices/NetworkDiscoveryPanel";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import type { DiscoveredHost } from "@/lib/types";

function bulkRegisterError(caught: unknown): string {
  if (caught instanceof ApiError || caught instanceof Error) {
    return caught.message;
  }
  return "Could not register the selected devices.";
}

/**
 * The first pipeline page - a fleet-wide sweep of the network, not tied to
 * any one device. Registering (one at a time, reviewing the pre-filled
 * form, or several at once via the bulk-confirm dialog below) is what moves
 * a discovered host into the durable Devices registry, where it can then be
 * selected to advance further down the pipeline.
 */
export function DiscoveryPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const devices = useFetch(api.devices, [refreshKey]);
  const { showToast } = useToast();

  const [showForm, setShowForm] = useState(false);
  const [prefill, setPrefill] = useState<DeviceRegistrationPrefill | null>(null);

  const [bulkHosts, setBulkHosts] = useState<DiscoveredHost[] | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);

  function openFormWithPrefill(fromHost: DeviceRegistrationPrefill) {
    setPrefill(fromHost);
    setShowForm(true);
  }

  function closeForm() {
    setShowForm(false);
    setPrefill(null);
  }

  function handleRegistered() {
    closeForm();
    setRefreshKey((key) => key + 1);
    showToast("Device registered.", "success");
  }

  function openBulkConfirm(hosts: DiscoveredHost[]) {
    setBulkError(null);
    setBulkHosts(hosts);
  }

  async function handleConfirmBulkRegister() {
    if (!bulkHosts || bulkHosts.length === 0) return;
    setBulkBusy(true);
    setBulkError(null);
    try {
      for (const host of bulkHosts) {
        const hostPrefill = prefillFromHost(host);
        await api.createDevice({
          device_id: hostPrefill.device_id,
          display_name: hostPrefill.display_name,
          tier: "unknown",
          host: hostPrefill.host,
          services: hostPrefill.services.map((s) => ({ ...s, published_port: null })),
        });
      }
      showToast(`Registered ${bulkHosts.length} device(s).`, "success");
      setBulkHosts(null);
      setRefreshKey((key) => key + 1);
    } catch (err) {
      setBulkError(bulkRegisterError(err));
    } finally {
      setBulkBusy(false);
    }
  }

  return (
    <Shell title="Discovery" subtitle="Sweep the network to find candidate devices">
      <NetworkDiscoveryPanel
        devices={devices.data ?? []}
        onRegisterHost={openFormWithPrefill}
        onRegisterSelected={openBulkConfirm}
      />

      {showForm && (
        <Card className="mb-6">
          <CardContent className="pt-5">
            <RegisterDeviceForm
              key={prefill?.device_id ?? "new"}
              initialDeviceId={prefill?.device_id}
              initialDisplayName={prefill?.display_name}
              initialHost={prefill?.host}
              initialServices={prefill?.services}
              onRegistered={handleRegistered}
              onCancel={closeForm}
            />
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={bulkHosts !== null}
        title={`Register ${bulkHosts?.length ?? 0} device(s)?`}
        description={
          <>
            <p className="mb-2">
              Each host below will be registered with its suggested device ID and services -
              you can edit any of these later from its own device page.
            </p>
            <ul className="space-y-1">
              {(bulkHosts ?? []).map((host) => {
                const hostPrefill = prefillFromHost(host);
                return (
                  <li key={host.ip} className="font-mono text-xs text-[var(--color-text)]">
                    {hostPrefill.device_id} ({hostPrefill.host})
                  </li>
                );
              })}
            </ul>
            {bulkError && <p className="mt-2 text-[var(--color-critical)]">{bulkError}</p>}
          </>
        }
        confirmLabel="Register"
        pending={bulkBusy}
        onConfirm={handleConfirmBulkRegister}
        onCancel={() => setBulkHosts(null)}
      />
    </Shell>
  );
}
