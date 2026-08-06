import { useState } from "react";
import { Shell } from "@/components/layout/Shell";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { Skeleton } from "@/components/ui/skeleton";
import { DeviceCohortPicker } from "@/components/pipeline/DeviceCohortPicker";
import { DevicePqcReadinessCard } from "@/components/pipeline/DevicePqcReadinessCard";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";

/**
 * A bonus stage beyond IoTGuard's original 10, sitting after AI Remediation
 * and before the AI Executive Summary so its findings flow into the
 * executive rollup - explicitly informational only, never feeds
 * policies/risk/risk_engine.py or any compliance verdict/sign-off.
 */
export function PostQuantumReadinessPage() {
  const devices = useFetch(api.devices, []);
  const scanTests = useFetch(api.scanTests, []);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const loading = devices.loading || scanTests.loading;
  const error = devices.error ?? scanTests.error;
  const registeredDevices = (devices.data ?? []).filter((d) => d.registered);

  return (
    <Shell
      title="Post-Quantum Readiness"
      subtitle="TLS key exchange, certificate signature, and firmware crypto library currency - informational only, never affects risk scoring or compliance"
      phase="intelligence"
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
          <p className="text-xs text-[var(--color-text-muted)]">
            Checks 3 named technical criteria grounded in real NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS
            205 SLH-DSA) - no enforceable IoT post-quantum regulation exists yet, so this is not a compliance
            framework and needs no sign-off.
          </p>
          <DeviceCohortPicker devices={registeredDevices} selected={selected} onChange={setSelected} />

          {Array.from(selected).map((deviceId) => {
            const device = registeredDevices.find((d) => d.device_id === deviceId);
            if (!device) return null;
            return <DevicePqcReadinessCard key={deviceId} device={device} scanTests={scanTests.data ?? []} />;
          })}
        </div>
      )}
    </Shell>
  );
}
