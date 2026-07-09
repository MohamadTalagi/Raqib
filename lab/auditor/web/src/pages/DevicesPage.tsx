import { useMemo, useState } from "react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { StatusBadge } from "@/components/ui/severity-badge";
import { getDeviceMeta, getTierBadge } from "@/lib/deviceMeta";
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
  const devices = useFetch(api.devices, []);
  const verdicts = useFetch(api.verdicts, []);
  const [selected, setSelected] = useState<string | null>(null);

  const loading = devices.loading || verdicts.loading;
  const error = devices.error ?? verdicts.error;

  const selectedVerdicts = useMemo(
    () => (verdicts.data ?? []).filter((v) => v.device_id === selected),
    [verdicts.data, selected],
  );

  return (
    <Shell title="Devices" subtitle="Simulated IoT device profiles in the lab">
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
            const meta = getDeviceMeta(device.device_id);
            const tier = getTierBadge(meta.tier);
            const TierIcon = tier.icon;
            const Icon = meta.icon;
            const counts = verdictCounts((verdicts.data ?? []).filter((v) => v.device_id === device.device_id));
            const isSelected = selected === device.device_id;

            return (
              <Card
                key={device.device_id}
                className={cn(
                  "cursor-pointer hover:border-[var(--color-border-strong)]",
                  isSelected && "border-[var(--color-brand)]",
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
                  <p className="mt-3 font-mono text-xs text-[var(--color-text-muted)]">{device.device_id}</p>
                  <p className="mt-0.5 text-sm font-medium text-[var(--color-text)]">{meta.label}</p>
                  <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                    {meta.description}
                  </p>
                  <div className="mt-4 flex items-center gap-4 border-t border-[var(--color-border)] pt-3 text-xs">
                    <span className="text-[var(--color-text-muted)]">
                      Evidence <span className="font-mono-tabular text-[var(--color-text)]">{device.evidence_count}</span>
                    </span>
                    <span className="text-[var(--color-text-muted)]">
                      Verdicts <span className="font-mono-tabular text-[var(--color-text)]">{device.verdict_count}</span>
                    </span>
                    {counts.fail > 0 && (
                      <span className="ml-auto font-mono-tabular text-[var(--color-critical)]">{counts.fail} fail</span>
                    )}
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
