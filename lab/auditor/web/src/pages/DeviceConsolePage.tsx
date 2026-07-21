import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Device, DeviceService } from "@/lib/types";

// Console-viewable endpoints exposed by every smart-camera-like HTTP(S)
// service the brief requires. This is generic frontend behavior, not
// hardcoded device identity - unlike the old CONSOLE_DEVICES list this page
// used to import from a now-deleted per-device module, it names no
// specific device.
interface ConsoleEndpoint {
  key: string;
  label: string;
  method: "GET" | "POST";
  path: string;
  body?: string;
  contentType?: string;
  // HTML pages meant to be viewed, not just fetched for their raw body.
  // Clicking these also opens the real page in a new tab.
  viewable?: boolean;
}

const CONSOLE_ENDPOINTS: ConsoleEndpoint[] = [
  { key: "login-page", label: "Login page", method: "GET", path: "/", viewable: true },
  {
    key: "login",
    label: "Login (admin / admin)",
    method: "POST",
    path: "/login",
    body: "username=admin&password=admin",
    contentType: "application/x-www-form-urlencoded",
  },
  { key: "device-info", label: "Device info", method: "GET", path: "/api/device/info" },
  { key: "config", label: "Config", method: "GET", path: "/api/config" },
  { key: "firmware", label: "Firmware version", method: "GET", path: "/api/firmware/version" },
  { key: "admin-reset", label: "Admin reset", method: "GET", path: "/api/admin/reset" },
  { key: "privacy", label: "Privacy doc", method: "GET", path: "/privacy", viewable: true },
  { key: "health", label: "Health", method: "GET", path: "/health" },
];

interface ConsoleResult {
  endpointKey: string;
  ok: boolean;
  status: number | null;
  body: string;
  timestamp: Date;
}

async function callConsoleEndpoint(baseUrl: string, ep: ConsoleEndpoint): Promise<ConsoleResult> {
  const timestamp = new Date();
  try {
    const res = await fetch(baseUrl + ep.path, {
      method: ep.method,
      headers: ep.contentType ? { "Content-Type": ep.contentType } : undefined,
      body: ep.body,
    });
    const text = await res.text();
    let body = text;
    try {
      body = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      // not JSON (the login page and /privacy are HTML/plain text) - show as-is
    }
    return { endpointKey: ep.key, ok: res.ok, status: res.status, body, timestamp };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { endpointKey: ep.key, ok: false, status: null, body: message, timestamp };
  }
}

// Same runtime-host-derivation pattern as ERR-020: never hardcode a host,
// always derive from wherever the dashboard itself was loaded from.
function consoleBaseUrl(service: DeviceService): string {
  return `${service.service_type}://${window.location.hostname}:${service.published_port}`;
}

function isConsoleService(service: DeviceService): boolean {
  return (service.service_type === "http" || service.service_type === "https") && service.published_port !== null;
}

interface DeviceConsoleCardProps {
  device: Device;
  service: DeviceService;
}

function DeviceConsoleCard({ device, service }: DeviceConsoleCardProps) {
  const baseUrl = consoleBaseUrl(service);
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [result, setResult] = useState<ConsoleResult | null>(null);

  async function handleClick(epKey: string) {
    const ep = CONSOLE_ENDPOINTS.find((e) => e.key === epKey);
    if (!ep) return;
    if (ep.viewable) {
      window.open(baseUrl + ep.path, "_blank", "noopener,noreferrer");
    }
    setPendingKey(epKey);
    const r = await callConsoleEndpoint(baseUrl, ep);
    setResult(r);
    setPendingKey(null);
  }

  const activeEndpoint = result ? CONSOLE_ENDPOINTS.find((e) => e.key === result.endpointKey) : null;
  const isCertLikelyIssue = result && !result.ok && result.status === null && service.service_type === "https";

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{device.display_name}</CardTitle>
          <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">{baseUrl}</p>
        </div>
      </CardHeader>
      <CardContent className="pt-2">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {CONSOLE_ENDPOINTS.map((ep) => (
            <button
              key={ep.key}
              type="button"
              onClick={() => handleClick(ep.key)}
              disabled={pendingKey !== null}
              className={cn(
                "flex items-center justify-center gap-1.5 rounded-md border px-2.5 py-2 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
                result?.endpointKey === ep.key
                  ? "border-[var(--color-brand)] bg-[color-mix(in_oklab,var(--color-brand)_14%,transparent)] text-[var(--color-text)]"
                  : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]",
              )}
            >
              {pendingKey === ep.key && <Loader2 className="h-3 w-3 animate-spin" />}
              {ep.label}
            </button>
          ))}
        </div>

        {result && (
          <div className="mt-4 border-t border-[var(--color-border)] pt-3">
            <div className="mb-1.5 flex items-center gap-2 text-xs">
              <span className="font-mono text-[var(--color-text-muted)]">
                {activeEndpoint?.method} {activeEndpoint?.path}
              </span>
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold",
                  result.ok
                    ? "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)]"
                    : "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)]",
                )}
              >
                {result.status ?? "ERR"}
              </span>
              <span className="ml-auto font-mono text-[10px] text-[var(--color-text-muted)]">
                {result.timestamp.toLocaleTimeString()}
              </span>
            </div>
            <pre className="max-h-52 overflow-auto rounded-md bg-black/30 px-3 py-2 font-mono text-[11px] leading-relaxed text-[var(--color-text-secondary)]">
              {result.body}
            </pre>
            {isCertLikelyIssue && (
              <p className="mt-2 text-xs text-[var(--color-medium)]">
                This device uses a self-signed lab certificate. If your browser hasn't trusted it
                yet, open{" "}
                <a href={baseUrl} target="_blank" rel="noreferrer" className="underline">
                  {baseUrl}
                </a>{" "}
                directly once, accept the warning, then retry the button above.
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface NoConsoleCardProps {
  device: Device;
}

function NoConsoleCard({ device }: NoConsoleCardProps) {
  return (
    <Card>
      <CardContent className="pt-5 text-sm text-[var(--color-text-secondary)]">
        <span className="font-medium text-[var(--color-text)]">{device.display_name}</span> has no
        browser-reachable HTTP service published for the console.
      </CardContent>
    </Card>
  );
}

export function DeviceConsolePage() {
  const devices = useFetch(api.devices, []);

  const registeredDevices = (devices.data ?? []).filter((d) => d.registered);

  return (
    <Shell
      title="Device Console"
      subtitle="Every service the brief requires, one live button per device"
    >
      {devices.error ? (
        <ErrorState message={devices.error} />
      ) : devices.loading || !devices.data ? (
        <div className="space-y-5">
          <Skeleton className="h-56" />
          <Skeleton className="h-56" />
          <Skeleton className="h-56" />
        </div>
      ) : registeredDevices.length === 0 ? (
        <EmptyState message="No registered devices yet." />
      ) : (
        <div className="space-y-5">
          {registeredDevices.map((device) => {
            const consoleServices = device.services.filter(isConsoleService);
            if (consoleServices.length === 0) {
              return <NoConsoleCard key={device.device_id} device={device} />;
            }
            return consoleServices.map((service) => (
              <DeviceConsoleCard key={`${device.device_id}-${service.id}`} device={device} service={service} />
            ));
          })}
        </div>
      )}
    </Shell>
  );
}
