import { useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { PhaseRunnerCard } from "@/components/pipeline/PhaseRunnerCard";
import { PqcReadinessPanel } from "@/components/pipeline/PqcReadinessPanel";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { Device, ScanTestSpec, ServiceType } from "@/lib/types";

interface DevicePqcReadinessCardProps {
  device: Device;
  /** The full catalog - this component finds its own 2 tests
   * (TEST-PQC-TLS-HANDSHAKE, TEST-PQC-FIRMWARE-CRYPTO) by id, the same
   * pattern DeviceVulnerabilityCard already uses for TEST-FW-MANIFEST. */
  scanTests: ScanTestSpec[];
}

/**
 * One device's Post-Quantum Readiness check - informational only, never
 * feeds risk_engine.py or any compliance verdict/score. Mirrors
 * DeviceVulnerabilityCard's shape (a PhaseRunnerCard to trigger the real
 * collectors + a live-computed results panel below it), but firmware
 * upload itself stays on the Vulnerability Intelligence page - this card
 * only links there when firmware hasn't been uploaded yet, never
 * duplicates the upload control.
 */
export function DevicePqcReadinessCard({ device, scanTests }: DevicePqcReadinessCardProps) {
  const [refreshKey, setRefreshKey] = useState(0);
  const readiness = useFetch(() => api.pqcReadinessDevice(device.device_id), [device.device_id, refreshKey]);

  const deviceServiceTypes = new Set<ServiceType>(
    device.services.filter((s) => s.enabled).map((s) => s.service_type),
  );
  const hasFirmware = Boolean(device.firmware_sha256);
  const tlsTests = scanTests.filter(
    (t) =>
      t.test_id === "TEST-PQC-TLS-HANDSHAKE" && t.applicable_service_types.some((st) => deviceServiceTypes.has(st)),
  );
  const firmwareTests = scanTests.filter((t) => t.test_id === "TEST-PQC-FIRMWARE-CRYPTO");
  const testsForDevice = hasFirmware ? [...tlsTests, ...firmwareTests] : tlsTests;

  return (
    <Card>
      <CardHeader>
        <CardTitle>{device.display_name}</CardTitle>
        <span className="font-mono text-xs text-[var(--color-text-muted)]">{device.device_id}</span>
      </CardHeader>
      <CardContent className="space-y-4 pt-2">
        <PhaseRunnerCard
          device={device}
          tests={testsForDevice}
          emptyHint={
            tlsTests.length === 0 ? (
              <p className="text-xs text-[var(--color-text-muted)]">
                No TLS-capable service (HTTPS/MQTTS) on this device — nothing to check for the key-exchange or
                certificate-signature criteria.
                {!hasFirmware && firmwareTests.length > 0 && (
                  <>
                    {" "}
                    <Link to="/vulnerability-intelligence" className="text-[var(--color-brand)] underline">
                      Upload firmware
                    </Link>{" "}
                    to check the firmware crypto-library criterion instead.
                  </>
                )}
              </p>
            ) : undefined
          }
        />
        {!hasFirmware && firmwareTests.length > 0 && tlsTests.length > 0 && (
          <p className="text-xs text-[var(--color-text-muted)]">
            {firmwareTests.length} additional firmware crypto-library check available once{" "}
            <Link to="/vulnerability-intelligence" className="text-[var(--color-brand)] underline">
              firmware is uploaded
            </Link>
            .
          </p>
        )}

        <div className="space-y-3 border-t border-[var(--color-border)] pt-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
              Post-quantum readiness
            </p>
            <button
              type="button"
              onClick={() => setRefreshKey((k) => k + 1)}
              className="inline-flex cursor-pointer items-center gap-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)]"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>
          {readiness.loading ? (
            <Skeleton className="h-16" />
          ) : readiness.data ? (
            <PqcReadinessPanel readiness={readiness.data} />
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">No data yet.</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
