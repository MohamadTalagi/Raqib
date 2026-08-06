import { useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, Loader2 } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge, SeverityBadge } from "@/components/ui/severity-badge";
import { DeviceCohortPicker } from "@/components/pipeline/DeviceCohortPicker";
import { PhaseRunnerCard } from "@/components/pipeline/PhaseRunnerCard";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import type { ControlRecord, ServiceType, VerdictRecord } from "@/lib/types";

function verdictCounts(deviceVerdicts: VerdictRecord[]) {
  return {
    pass: deviceVerdicts.filter((v) => v.status === "PASS").length,
    fail: deviceVerdicts.filter((v) => v.status === "FAIL").length,
    other: deviceVerdicts.filter((v) => v.status !== "PASS" && v.status !== "FAIL").length,
  };
}

/** The most recent verdict per control_id - a control can be re-tested and
 * would otherwise double-count / show a stale result, same dedup rule this
 * codebase already applies to every other verdict rollup (e.g. the
 * device-compliance percentage on Overview). */
function latestVerdictByControl(deviceVerdicts: VerdictRecord[]): Map<string, VerdictRecord> {
  const latest = new Map<string, VerdictRecord>();
  for (const v of deviceVerdicts) {
    const existing = latest.get(v.control_id);
    if (!existing || v.timestamp > existing.timestamp) {
      latest.set(v.control_id, v);
    }
  }
  return latest;
}

/** Per-clause breakdown for one device - the individual pass/fail/finding
 * for each of the 5 SA-IOT-* controls, not just the aggregate count. */
function ControlResultsList({ controls, latestByControl }: { controls: ControlRecord[]; latestByControl: Map<string, VerdictRecord> }) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)]">
      <ul className="divide-y divide-[var(--color-border)]">
        {controls.map((control) => {
          const v = latestByControl.get(control.control_id);
          return (
            <li key={control.control_id} className="p-3">
              <div className="flex flex-wrap items-center gap-2">
                {v ? (
                  <StatusBadge status={v.status} />
                ) : (
                  <span className="inline-flex items-center rounded-md bg-[var(--color-surface-hover)] px-2 py-0.5 text-xs font-semibold tracking-wide text-[var(--color-text-muted)]">
                    NOT TESTED
                  </span>
                )}
                {v ? <SeverityBadge severity={v.severity} /> : null}
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{control.control_id}</span>
                <span className="text-sm text-[var(--color-text)]">{control.title}</span>
              </div>
              <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
                {v ? v.reason : "No verdict recorded yet for this control - run its test(s) below, or recompute."}
              </p>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * The original 5-control SA-IOT-* pilot's tests (pipeline_phase ==
 * "sa_iot_compliance") - everything Run Scan used to call "Web and Auth" /
 * "Network and Protocol" plus the firmware misconfiguration checks, scoped
 * to a device cohort instead of one device at a time. NCA Compliance is a
 * separate, later phase - this page is only the original pilot's own tests.
 */
export function SAIOTCompliancePage() {
  const devices = useFetch(api.devices, []);
  const scanTests = useFetch(api.scanTests, []);
  const controls = useFetch(api.controls, []);
  const [refreshKey, setRefreshKey] = useState(0);
  const verdicts = useFetch(api.verdicts, [refreshKey]);
  const { showToast } = useToast();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [recomputing, setRecomputing] = useState(false);

  const loading = devices.loading || scanTests.loading || verdicts.loading || controls.loading;
  const error = devices.error ?? scanTests.error ?? verdicts.error ?? controls.error;
  const registeredDevices = (devices.data ?? []).filter((d) => d.registered);
  const complianceTests = (scanTests.data ?? []).filter((t) => t.pipeline_phase === "sa_iot_compliance");
  const pilotControls = controls.data ?? [];

  async function handleRecompute() {
    setRecomputing(true);
    try {
      const result = await api.recomputeVerdicts();
      const message =
        result.created === 0
          ? "No new verdicts (evidence didn't map to a new control result)."
          : `${result.created} new verdict${result.created === 1 ? "" : "s"} generated — check the Verdicts page.`;
      showToast(message, "success");
      setRefreshKey((k) => k + 1);
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : "Could not recompute verdicts.", "error");
    } finally {
      setRecomputing(false);
    }
  }

  return (
    <Shell
      title="SA-IOT Compliance"
      subtitle="The original 5-control pilot assessment (default creds, insecure services, TLS, firmware misconfiguration)"
      phase="compliance"
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
          <div className="flex items-center justify-between gap-2">
            <DeviceCohortPicker devices={registeredDevices} selected={selected} onChange={setSelected} />
          </div>

          <div className="flex items-center justify-between">
            <Link to="/verdicts" className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline">
              View all verdicts →
            </Link>
            <button
              type="button"
              onClick={handleRecompute}
              disabled={recomputing}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
            >
              {recomputing ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Recompute verdicts
            </button>
          </div>

          {Array.from(selected).map((deviceId) => {
            const device = registeredDevices.find((d) => d.device_id === deviceId);
            if (!device) return null;

            const deviceServiceTypes = new Set<ServiceType>(
              device.services.filter((s) => s.enabled).map((s) => s.service_type),
            );
            const hasFirmware = Boolean(device.firmware_sha256);
            const serviceTests = complianceTests.filter(
              (t) => t.applicable_service_types.length > 0 && t.applicable_service_types.some((st) => deviceServiceTypes.has(st)),
            );
            const firmwareTests = complianceTests.filter((t) => t.applicable_service_types.length === 0);
            const testsForDevice = hasFirmware ? [...serviceTests, ...firmwareTests] : serviceTests;

            const deviceVerdicts = (verdicts.data ?? []).filter((v) => v.device_id === deviceId);
            const counts = verdictCounts(deviceVerdicts);
            const latestByControl = latestVerdictByControl(deviceVerdicts);

            return (
              <div key={deviceId} className="space-y-2">
                <p className="text-xs text-[var(--color-text-muted)]">
                  Current verdicts for <span className="font-mono text-[var(--color-text)]">{deviceId}</span>:{" "}
                  <span className="text-[var(--color-pass)]">{counts.pass} pass</span> ·{" "}
                  <span className="text-[var(--color-critical)]">{counts.fail} fail</span>
                  {counts.other > 0 && <> · {counts.other} other</>}
                </p>
                <ControlResultsList controls={pilotControls} latestByControl={latestByControl} />
                <PhaseRunnerCard
                  device={device}
                  tests={testsForDevice}
                  emptyHint={
                    !hasFirmware && firmwareTests.length > 0 ? (
                      <p className="text-xs text-[var(--color-text-muted)]">
                        No applicable network/auth tests for this device's services.{" "}
                        <Link to={`/devices/${deviceId}`} className="text-[var(--color-brand)] underline">
                          Upload firmware
                        </Link>{" "}
                        to unlock {firmwareTests.length} more test(s).
                      </p>
                    ) : undefined
                  }
                />
                {hasFirmware === false && firmwareTests.length > 0 && testsForDevice.length > 0 && (
                  <p className="text-xs text-[var(--color-text-muted)]">
                    {firmwareTests.length} additional firmware-based test(s) available once{" "}
                    <Link to={`/devices/${deviceId}`} className="text-[var(--color-brand)] underline">
                      firmware is uploaded
                    </Link>
                    .
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Shell>
  );
}
