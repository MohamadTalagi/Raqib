import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { Skeleton } from "@/components/ui/skeleton";
import { DeviceCohortPicker } from "@/components/pipeline/DeviceCohortPicker";
import { PhaseRunnerCard } from "@/components/pipeline/PhaseRunnerCard";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { ServiceType } from "@/lib/types";

interface FingerprintingLocationState {
  deviceIds?: string[];
}

/**
 * First real assessment phase: reachability, port/service identification -
 * "what is this device?" - not yet a compliance judgment. Scoped to
 * pipeline_phase === "fingerprinting" tests only (see
 * policies/catalog/scan_tests.py); NCA Compliance covers the rest of
 * what Run Scan used to call "Web and Auth"/"Network and Protocol".
 */
export function FingerprintingPage() {
  const location = useLocation();
  const devices = useFetch(api.devices, []);
  const scanTests = useFetch(api.scanTests, []);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Seeded once from a cohort passed in via Devices' "Advance to
  // Fingerprinting" action - a direct visit (no route state) just starts
  // with nothing selected, since this is a real page, not a wizard step.
  useEffect(() => {
    const state = location.state as FingerprintingLocationState | null;
    if (state?.deviceIds?.length) {
      setSelected(new Set(state.deviceIds));
    }
    // Only ever consumed once, on mount - re-visiting this page after
    // changing the selection shouldn't keep snapping back to the original cohort.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loading = devices.loading || scanTests.loading;
  const error = devices.error ?? scanTests.error;
  const registeredDevices = (devices.data ?? []).filter((d) => d.registered);
  const fingerprintingTests = (scanTests.data ?? []).filter((t) => t.pipeline_phase === "fingerprinting");

  return (
    <Shell
      title="Fingerprinting"
      subtitle="Identify what a device is - reachability, open ports, exposed services"
      phase="discovery"
    >
      {error ? (
        <ErrorState message={error} />
      ) : loading ? (
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-44" />
        </div>
      ) : registeredDevices.length === 0 ? (
        <EmptyState message="No registered devices yet - register one from the Devices page first." />
      ) : (
        <div className="space-y-6">
          <DeviceCohortPicker devices={registeredDevices} selected={selected} onChange={setSelected} />

          {Array.from(selected).map((deviceId) => {
            const device = registeredDevices.find((d) => d.device_id === deviceId);
            if (!device) return null;
            const deviceServiceTypes = new Set<ServiceType>(
              device.services.filter((s) => s.enabled).map((s) => s.service_type),
            );
            const testsForDevice = fingerprintingTests.filter((t) =>
              t.applicable_service_types.some((st) => deviceServiceTypes.has(st)),
            );
            return <PhaseRunnerCard key={deviceId} device={device} tests={testsForDevice} />;
          })}
        </div>
      )}
    </Shell>
  );
}
