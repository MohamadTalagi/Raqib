import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Plus, X, CheckCircle2, CircleDashed, ArrowUpRight, HardDrive } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { StatusBadge } from "@/components/ui/severity-badge";
import { RegisterDeviceForm } from "@/components/devices/RegisterDeviceForm";
import { getTierBadge } from "@/lib/deviceTier";
import { serviceIcon } from "@/lib/serviceIcons";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { VerdictRecord } from "@/lib/types";

function verdictCounts(deviceVerdicts: VerdictRecord[]) {
  return {
    pass: deviceVerdicts.filter((v) => v.status === "PASS").length,
    fail: deviceVerdicts.filter((v) => v.status === "FAIL").length,
  };
}

export function DevicesPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const devices = useFetch(api.devices, [refreshKey]);
  const verdicts = useFetch(api.verdicts, []);
  const [selected, setSelected] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  const loading = devices.loading || verdicts.loading;
  const error = devices.error ?? verdicts.error;

  const selectedVerdicts = useMemo(
    () => (verdicts.data ?? []).filter((v) => v.device_id === selected),
    [verdicts.data, selected],
  );

  function handleRegistered() {
    setShowForm(false);
    setRefreshKey((key) => key + 1);
  }

  return (
    <Shell title="Devices" subtitle="Simulated IoT device profiles in the lab">
      <div className="mb-4 flex items-center justify-end">
        <button
          type="button"
          onClick={() => setShowForm((current) => !current)}
          className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showForm ? "Cancel" : "Register device"}
        </button>
      </div>

      {showForm && (
        <Card className="mb-6">
          <CardContent className="pt-5">
            <RegisterDeviceForm onRegistered={handleRegistered} onCancel={() => setShowForm(false)} />
          </CardContent>
        </Card>
      )}

      {error ? (
        <ErrorState message={error} />
      ) : loading || !devices.data ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Skeleton className="h-44" />
          <Skeleton className="h-44" />
          <Skeleton className="h-44" />
        </div>
      ) : devices.data.length === 0 ? (
        <EmptyState message="No devices have generated evidence yet." />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {devices.data.map((device) => {
            const tier = getTierBadge(device.tier);
            const TierIcon = tier.icon;
            const Icon = device.services[0] ? serviceIcon(device.services[0].service_type) : HardDrive;
            const counts = verdictCounts((verdicts.data ?? []).filter((v) => v.device_id === device.device_id));
            const isSelected = selected === device.device_id;

            return (
              <Card
                key={device.device_id}
                className={cn(
                  "cursor-pointer hover:border-[var(--color-border-strong)]",
                  isSelected && "border-[var(--color-brand)]",
                  !device.registered && "opacity-60",
                )}
                onClick={() => setSelected(isSelected ? null : device.device_id)}
              >
                <CardContent className="pt-5">
                  <div className="flex items-start justify-between">
                    <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[var(--color-surface-hover)]">
                      <Icon className="h-5 w-5 text-[var(--color-text-secondary)]" strokeWidth={1.75} />
                    </div>
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium",
                        tier.className,
                      )}
                    >
                      <TierIcon className="h-3 w-3" />
                      {tier.label}
                    </span>
                  </div>
                  <div className="mt-3 flex items-center justify-between gap-2">
                    <Link
                      to={`/devices/${device.device_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex items-center gap-0.5 font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
                    >
                      {device.device_id}
                      <ArrowUpRight className="h-3 w-3" />
                    </Link>
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 text-[10px] font-medium tracking-wide uppercase",
                        device.registered ? "text-[var(--color-pass)]" : "text-[var(--color-text-muted)]",
                      )}
                    >
                      {device.registered ? (
                        <CheckCircle2 className="h-3 w-3" />
                      ) : (
                        <CircleDashed className="h-3 w-3" />
                      )}
                      {device.registered ? "Registered" : "Unregistered"}
                    </span>
                  </div>
                  <p className="mt-0.5 text-sm font-medium text-[var(--color-text)]">{device.display_name}</p>
                  <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                    {device.description}
                  </p>
                  <div className="mt-4 flex items-center gap-4 border-t border-[var(--color-border)] pt-3 text-xs">
                    <span className="text-[var(--color-text-muted)]">
                      Evidence <span className="font-mono-tabular text-[var(--color-text)]">{device.evidence_count}</span>
                    </span>
                    <span className="text-[var(--color-text-muted)]">
                      Verdicts <span className="font-mono-tabular text-[var(--color-text)]">{device.verdict_count}</span>
                    </span>
                    <span className="ml-auto flex items-center gap-3">
                      {counts.fail > 0 && (
                        <span className="font-mono-tabular text-[var(--color-critical)]">{counts.fail} fail</span>
                      )}
                      {!device.registered && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setShowForm(true);
                          }}
                          className="font-medium text-[var(--color-brand)] hover:underline"
                        >
                          Register
                        </button>
                      )}
                    </span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {selected && (
        <Card className="mt-6">
          <CardContent className="pt-5">
            <p className="mb-3 font-mono text-xs tracking-wide text-[var(--color-text-muted)] uppercase">
              Verdicts for {selected}
            </p>
            {selectedVerdicts.length === 0 ? (
              <p className="text-sm text-[var(--color-text-muted)]">No verdicts recorded for this device.</p>
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {selectedVerdicts.map((v) => (
                  <li key={v.verdict_id} className="flex items-center gap-4 py-2.5 text-sm">
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.control_id}</span>
                    <span className="flex-1 truncate text-[var(--color-text-secondary)]">{v.reason}</span>
                    <StatusBadge status={v.status} />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}
    </Shell>
  );
}
