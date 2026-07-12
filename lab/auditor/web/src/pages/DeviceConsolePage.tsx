import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDeviceMeta, getTierBadge } from "@/lib/deviceMeta";
import {
  CONSOLE_DEVICES,
  CONSOLE_ENDPOINTS,
  callConsoleEndpoint,
  consoleBaseUrl,
  type ConsoleDevice,
  type ConsoleResult,
} from "@/lib/consoleDevices";
import { cn } from "@/lib/utils";

function DeviceConsoleCard({ device }: { device: ConsoleDevice }) {
  const meta = getDeviceMeta(device.device_id);
  const tier = getTierBadge(meta.tier);
  const baseUrl = consoleBaseUrl(device);
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
  const isCertLikelyIssue =
    result && !result.ok && result.status === null && device.scheme === "https";

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{meta.label}</CardTitle>
          <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">{baseUrl}</p>
        </div>
        <span
          className={cn(
            "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium",
            tier.className,
          )}
        >
          {tier.label}
        </span>
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

export function DeviceConsolePage() {
  return (
    <Shell
      title="Device Console"
      subtitle="Every service the brief requires, one live button per device"
    >
      <div className="space-y-5">
        {CONSOLE_DEVICES.map((device) => (
          <DeviceConsoleCard key={device.device_id} device={device} />
        ))}
      </div>
    </Shell>
  );
}
