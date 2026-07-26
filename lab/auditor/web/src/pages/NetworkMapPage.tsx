import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Boxes, Cable, HardDrive, ShieldAlert, ArrowUpRight, RotateCcw } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { StatTile } from "@/components/ui/stat-tile";
import { NetworkGraph, TIER_LABEL, INFRA_NODES, type InfraNode } from "@/components/network/NetworkGraph";
import { serviceIcon } from "@/lib/serviceIcons";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { Device, DeviceTier, VerdictRecord } from "@/lib/types";

const TIER_ORDER: DeviceTier[] = ["hardened", "partial", "insecure", "unknown"];

function failCountByDevice(verdicts: VerdictRecord[] | null): Map<string, number> {
  const counts = new Map<string, number>();
  for (const v of verdicts ?? []) {
    if (v.status !== "FAIL") continue;
    counts.set(v.device_id, (counts.get(v.device_id) ?? 0) + 1);
  }
  return counts;
}

function DeviceDetail({ device, failCount }: { device: Device; failCount: number }) {
  return (
    <div className="space-y-4">
      <div>
        <p className="font-mono text-xs text-[var(--color-text-muted)]">{device.device_id}</p>
        <p className="mt-0.5 text-base font-semibold text-[var(--color-text)]">{device.display_name}</p>
        <p className="mt-1 text-xs leading-relaxed text-[var(--color-text-secondary)]">{device.description}</p>
      </div>

      <dl className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Posture</dt>
          <dd className="mt-0.5 font-medium text-[var(--color-text)]">{TIER_LABEL[device.tier]}</dd>
        </div>
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Host</dt>
          <dd className="mt-0.5 truncate font-mono text-[var(--color-text)]">{device.host ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Evidence</dt>
          <dd className="font-mono-tabular mt-0.5 text-[var(--color-text)]">{device.evidence_count}</dd>
        </div>
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Verdicts</dt>
          <dd className="font-mono-tabular mt-0.5 text-[var(--color-text)]">
            {device.verdict_count}
            {failCount > 0 && <span className="ml-1.5 text-[var(--color-critical)]">({failCount} fail)</span>}
          </dd>
        </div>
      </dl>

      <div>
        <p className="mb-2 text-[10px] font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
          Exposed services
        </p>
        {device.services.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)]">No registered services.</p>
        ) : (
          <ul className="space-y-1.5">
            {device.services.map((service) => {
              const Icon = serviceIcon(service.service_type);
              return (
                <li
                  key={service.id}
                  className="flex items-center gap-2 rounded-md border border-[var(--color-border)] px-2.5 py-1.5 text-xs"
                >
                  <Icon className="h-3.5 w-3.5 text-[var(--color-text-secondary)]" strokeWidth={2} />
                  <span className="font-mono text-[var(--color-text)] uppercase">{service.service_type}</span>
                  <span className="ml-auto font-mono-tabular text-[var(--color-text-muted)]">:{service.port}</span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {device.registered && (
        <Link
          to={`/devices/${device.device_id}`}
          className="inline-flex items-center gap-1 text-xs font-medium text-[var(--color-brand)] hover:underline"
        >
          View full device page
          <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      )}
    </div>
  );
}

function InfraDetail({ infra }: { infra: InfraNode }) {
  const Icon = infra.icon;
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-[var(--color-surface-hover)]">
          <Icon className="h-4.5 w-4.5 text-[var(--color-low)]" strokeWidth={2} />
        </span>
        <div>
          <p className="font-mono text-xs text-[var(--color-text-muted)]">{infra.id}</p>
          <p className="text-sm font-semibold text-[var(--color-text)]">
            {infra.zone === "audit" ? "Audit network" : "Trusted backend"}
          </p>
        </div>
      </div>
      <p className="text-xs leading-relaxed text-[var(--color-text-secondary)]">{infra.description}</p>
      {infra.id === "auditor-worker" && (
        <p className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-hover)] px-3 py-2 text-xs text-[var(--color-text-secondary)]">
          This is the only service with a network interface on both <code className="font-mono">audit-network</code>{" "}
          and <code className="font-mono">internal-network</code> — the trust boundary between scan targets and the
          backend runs straight through it.
        </p>
      )}
    </div>
  );
}

function FleetSummary({ devices, failCounts }: { devices: Device[]; failCounts: Map<string, number> }) {
  const totalServices = devices.reduce((sum, d) => sum + d.services.length, 0);
  const totalFailing = [...failCounts.values()].filter((n) => n > 0).length;

  return (
    <div className="space-y-4">
      <div>
        <p className="text-sm font-medium text-[var(--color-text)]">Two real Docker networks</p>
        <p className="mt-1 text-xs leading-relaxed text-[var(--color-text-secondary)]">
          Devices sit on the sandboxed <code className="font-mono">audit-network</code>. The API and database sit on{" "}
          <code className="font-mono">internal-network</code>, which has no route out. <code className="font-mono">
            auditor-worker
          </code>{" "}
          is the only thing bridging the two. Click any node to inspect it.
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Devices</dt>
          <dd className="font-mono-tabular mt-0.5 text-[var(--color-text)]">{devices.length}</dd>
        </div>
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Services</dt>
          <dd className="font-mono-tabular mt-0.5 text-[var(--color-text)]">{totalServices}</dd>
        </div>
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">Links</dt>
          <dd className="font-mono-tabular mt-0.5 text-[var(--color-text)]">{devices.length}</dd>
        </div>
        <div>
          <dt className="text-[var(--color-text-muted)] uppercase">With failures</dt>
          <dd className="font-mono-tabular mt-0.5 text-[var(--color-critical)]">{totalFailing}</dd>
        </div>
      </dl>

      <div>
        <p className="mb-2 text-[10px] font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
          Posture legend
        </p>
        <ul className="space-y-1.5 text-xs">
          {TIER_ORDER.map((tier) => (
            <li key={tier} className="flex items-center gap-2 text-[var(--color-text-secondary)]">
              <span
                className="h-2.5 w-2.5 rounded-full"
                style={{
                  backgroundColor:
                    tier === "hardened"
                      ? "var(--color-pass)"
                      : tier === "partial"
                        ? "var(--color-medium)"
                        : tier === "insecure"
                          ? "var(--color-critical)"
                          : "var(--color-inconclusive)",
                }}
              />
              {TIER_LABEL[tier]}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function NetworkMapPage() {
  const devices = useFetch(api.devices, []);
  const verdicts = useFetch(api.verdicts, []);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const failCounts = useMemo(() => failCountByDevice(verdicts.data), [verdicts.data]);

  const selectedDevice = useMemo(
    () => (selectedId ? (devices.data ?? []).find((d) => d.device_id === selectedId) ?? null : null),
    [selectedId, devices.data],
  );
  const selectedInfra = useMemo(
    () => (selectedId ? (INFRA_NODES.find((n) => n.id === selectedId) ?? null) : null),
    [selectedId],
  );

  const loading = devices.loading;
  const error = devices.error;

  const failingCount = [...failCounts.values()].filter((n) => n > 0).length;
  const totalServices = (devices.data ?? []).reduce((sum, d) => sum + d.services.length, 0);

  return (
    <Shell title="Network Map" subtitle="Live topology of registered lab devices">
      {error ? (
        <ErrorState message={error} />
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {loading || !devices.data ? (
              <>
                <Skeleton className="h-28" />
                <Skeleton className="h-28" />
                <Skeleton className="h-28" />
                <Skeleton className="h-28" />
              </>
            ) : (
              <>
                <StatTile label="Devices" value={devices.data.length} icon={HardDrive} accent="neutral" />
                <StatTile label="Services" value={totalServices} icon={Boxes} accent="neutral" />
                <StatTile label="Links" value={devices.data.length} icon={Cable} accent="brand" />
                <StatTile
                  label="With failures"
                  value={failingCount}
                  icon={ShieldAlert}
                  accent={failingCount > 0 ? "critical" : "pass"}
                />
              </>
            )}
          </div>

          {loading || !devices.data ? (
            <Skeleton className="h-96" />
          ) : devices.data.length === 0 ? (
            <EmptyState message="No devices have generated evidence yet." />
          ) : (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <Card className="xl:col-span-2">
                <CardHeader>
                  <div>
                    <CardTitle>Topology</CardTitle>
                    <CardDescription>Click a node to inspect it</CardDescription>
                  </div>
                  {selectedId && (
                    <button
                      type="button"
                      onClick={() => setSelectedId(null)}
                      className="inline-flex shrink-0 cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      Reset view
                    </button>
                  )}
                </CardHeader>
                <CardContent>
                  <NetworkGraph devices={devices.data} selectedId={selectedId} onSelect={(id) => setSelectedId(id || null)} />
                </CardContent>
              </Card>

              <Card className="xl:col-span-1">
                <CardHeader>
                  <CardTitle>{selectedDevice ? "Device details" : selectedInfra ? "Infrastructure" : "Fleet overview"}</CardTitle>
                </CardHeader>
                <CardContent>
                  {selectedDevice ? (
                    <DeviceDetail device={selectedDevice} failCount={failCounts.get(selectedDevice.device_id) ?? 0} />
                  ) : selectedInfra ? (
                    <InfraDetail infra={selectedInfra} />
                  ) : (
                    <FleetSummary devices={devices.data} failCounts={failCounts} />
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      )}
    </Shell>
  );
}
