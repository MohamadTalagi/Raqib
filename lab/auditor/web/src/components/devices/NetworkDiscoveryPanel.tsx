import { useEffect, useState } from "react";
import { CheckCircle2, HelpCircle, Loader2, RadioTower, ShieldQuestion } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Device, DiscoveredHost, HostClassification, NetworkScan, ServiceType } from "@/lib/types";

const POLL_INTERVAL_MS = 1500;

const PORT_SERVICE_TYPE: Record<number, ServiceType> = {
  80: "http",
  443: "https",
  1883: "mqtt",
  8883: "mqtts",
  23: "telnet",
  22: "ssh",
};

export interface DeviceRegistrationPrefill {
  device_id: string;
  display_name: string;
  host: string;
  services: Array<{ service_type: ServiceType; port: number }>;
}

// Matches this lab's own Docker Compose container naming
// (kaust-iot-lab-<name>-<index>.<network>) to recover the real, friendly
// device id/name a discovered host already has elsewhere in the app -
// falls back to an IP-based slug for anything that doesn't match (i.e. any
// real, non-lab network).
function suggestNameFromHost(host: DiscoveredHost): { deviceId: string; displayName: string } {
  const match = host.hostname?.match(/^kaust-iot-lab-(.+?)-\d+\./);
  if (match) {
    return { deviceId: match[1], displayName: match[1] };
  }
  const slug = `host-${host.ip.replace(/\./g, "-")}`;
  return { deviceId: slug, displayName: `Host ${host.ip}` };
}

export function prefillFromHost(host: DiscoveredHost): DeviceRegistrationPrefill {
  const { deviceId, displayName } = suggestNameFromHost(host);
  const services = host.open_ports
    .filter((port) => port in PORT_SERVICE_TYPE)
    .map((port) => ({ service_type: PORT_SERVICE_TYPE[port], port }));
  return { device_id: deviceId, display_name: displayName, host: host.ip, services };
}

// A discovered host can already be registered under either its IP or a
// container name (this lab's own seeded devices register with the
// container name as `host`, e.g. "device-insecure", not an IP) - checking
// the IP alone missed every already-registered lab device, since none of
// them actually use their IP as `host`.
function isAlreadyRegistered(host: DiscoveredHost, devices: Device[]): boolean {
  const { deviceId } = suggestNameFromHost(host);
  return devices.some(
    (d) => d.registered && (d.host === host.ip || d.host === deviceId || d.device_id === deviceId),
  );
}

const CLASSIFICATION_COPY: Record<
  HostClassification,
  { label: string; icon: typeof CheckCircle2; className: string }
> = {
  iot_device: {
    label: "IoT device",
    icon: CheckCircle2,
    className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)]",
  },
  uncertain: {
    label: "Uncertain",
    icon: ShieldQuestion,
    className: "text-[var(--color-medium)] bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)]",
  },
  unknown: {
    label: "Unknown",
    icon: HelpCircle,
    className: "text-[var(--color-text-muted)] bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)]",
  },
};

function ClassificationBadge({ classification }: { classification: HostClassification }) {
  const { label, icon: Icon, className } = CLASSIFICATION_COPY[classification];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide",
        className,
      )}
    >
      <Icon className="h-3.5 w-3.5" strokeWidth={2} />
      {label}
    </span>
  );
}

function useNetworkScan(scanId: number | null): [NetworkScan | null, (scan: NetworkScan) => void] {
  const [scan, setScan] = useState<NetworkScan | null>(null);

  useEffect(() => {
    if (scanId === null) {
      setScan(null);
      return;
    }
    let cancelled = false;
    let timer: number | undefined;

    async function poll() {
      try {
        const latest = await api.getNetworkScan(scanId as number);
        if (cancelled) return;
        setScan(latest);
        if (latest.status === "pending" || latest.status === "running") {
          timer = window.setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch {
        if (!cancelled) timer = window.setTimeout(poll, POLL_INTERVAL_MS);
      }
    }
    poll();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [scanId]);

  return [scan, setScan];
}

interface NetworkDiscoveryPanelProps {
  devices: Device[];
  onRegisterHost: (prefill: DeviceRegistrationPrefill) => void;
  /** Raises the selected not-yet-registered hosts up to the page, which owns
   * the bulk-confirm dialog and the actual registration calls - this panel
   * only ever handles scanning and selection. */
  onRegisterSelected: (hosts: DiscoveredHost[]) => void;
}

export function NetworkDiscoveryPanel({ devices, onRegisterHost, onRegisterSelected }: NetworkDiscoveryPanelProps) {
  const [scanId, setScanId] = useState<number | null>(null);
  const [scan, setScan] = useNetworkScan(scanId);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const inFlight = scan !== null && (scan.status === "pending" || scan.status === "running");

  async function handleScan() {
    setLaunchError(null);
    setLaunching(true);
    setSelected(new Set());
    try {
      const created = await api.createNetworkScan();
      setScan(created);
      setScanId(created.id);
    } catch (err) {
      setLaunchError(err instanceof ApiError ? err.message : "Could not start the network scan.");
    } finally {
      setLaunching(false);
    }
  }

  const registerableHosts = (scan?.observations?.hosts ?? []).filter(
    (host) => !isAlreadyRegistered(host, devices),
  );
  const allSelected = registerableHosts.length > 0 && registerableHosts.every((h) => selected.has(h.ip));

  function toggleAll(checked: boolean) {
    setSelected(checked ? new Set(registerableHosts.map((h) => h.ip)) : new Set());
  }

  function toggleOne(ip: string, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(ip);
      } else {
        next.delete(ip);
      }
      return next;
    });
  }

  return (
    <Card className="mb-6">
      <CardHeader className="flex-col items-start gap-2">
        <CardTitle>Discover devices on the network</CardTitle>
        <p className="text-xs text-[var(--color-text-secondary)]">
          Sweeps the audit-network subnet and classifies each live host from its open-port signature,
          so you can register real discovered devices instead of typing every field in by hand. A
          shared VLAN can carry other, non-IoT network gear too — hosts that don't look like a
          purpose-built IoT appliance are flagged "uncertain" or "unknown" rather than assumed.
        </p>
      </CardHeader>
      <CardContent className="space-y-4 pt-2">
        <button
          type="button"
          onClick={handleScan}
          disabled={launching || inFlight}
          className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
        >
          {launching || inFlight ? <Loader2 className="h-4 w-4 animate-spin" /> : <RadioTower className="h-4 w-4" />}
          {inFlight ? "Scanning…" : "Scan network"}
        </button>

        {launchError && <p className="text-sm text-[var(--color-critical)]">{launchError}</p>}

        {scan?.status === "failed" && (
          <p className="text-sm text-[var(--color-critical)]">
            {scan.error ?? "The network scan failed."}
          </p>
        )}

        {scan?.status === "completed" && scan.observations && (
          <div className="space-y-3">
            <p className="text-xs text-[var(--color-text-muted)]">
              {scan.observations.hosts.length} live host(s) found on {scan.observations.subnet}:{" "}
              {scan.observations.iot_device_count} IoT device(s), {scan.observations.uncertain_count} uncertain,{" "}
              {scan.observations.unknown_count} unknown.
            </p>
            {registerableHosts.length > 0 && (
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex cursor-pointer items-center gap-2 text-xs font-medium text-[var(--color-text-secondary)]">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={(e) => toggleAll(e.target.checked)}
                    className="h-4 w-4 accent-[var(--color-brand)]"
                  />
                  Select all registerable ({registerableHosts.length})
                </label>
                {selected.size > 0 && (
                  <button
                    type="button"
                    onClick={() =>
                      onRegisterSelected(registerableHosts.filter((h) => selected.has(h.ip)))
                    }
                    className="ml-auto inline-flex cursor-pointer items-center rounded-md bg-[var(--color-brand)] px-3 py-1.5 text-xs font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
                  >
                    Register selected ({selected.size})
                  </button>
                )}
              </div>
            )}
            <div className="overflow-hidden rounded-md border border-[var(--color-border)]">
              <div className="divide-y divide-[var(--color-border)]">
                {scan.observations.hosts.map((host) => {
                  const alreadyRegistered = isAlreadyRegistered(host, devices);
                  return (
                    <div key={host.ip} className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
                      {!alreadyRegistered && (
                        <input
                          type="checkbox"
                          aria-label={`Select ${host.ip}`}
                          checked={selected.has(host.ip)}
                          onChange={(e) => toggleOne(host.ip, e.target.checked)}
                          className="h-4 w-4 shrink-0 accent-[var(--color-brand)]"
                        />
                      )}
                      <div className="min-w-0 flex-1">
                        <p className="font-mono text-xs text-[var(--color-text)]">{host.ip}</p>
                        {host.hostname && (
                          <p className="truncate text-[11px] text-[var(--color-text-muted)]">{host.hostname}</p>
                        )}
                        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{host.rationale}</p>
                      </div>
                      <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                        ports: {host.open_ports.join(", ") || "—"}
                      </span>
                      <ClassificationBadge classification={host.classification} />
                      {alreadyRegistered ? (
                        <span className="text-xs font-medium text-[var(--color-text-muted)]">
                          Already registered
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onRegisterHost(prefillFromHost(host))}
                          className="inline-flex cursor-pointer items-center rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-brand)] hover:text-[var(--color-brand)]"
                        >
                          Register
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
            {scan.observations.notes.map((note, i) => (
              <p key={i} className="text-[11px] leading-relaxed text-[var(--color-text-muted)]">
                {note}
              </p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
