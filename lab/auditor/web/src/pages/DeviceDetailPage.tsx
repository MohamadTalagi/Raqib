import type { LucideIcon } from "lucide-react";
import { HelpCircle, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useParams } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { ConfidenceLabel, SeverityBadge, StatusBadge } from "@/components/ui/severity-badge";
import { serviceIcon } from "@/lib/serviceIcons";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Confidence, DeviceTier, Severity, VerdictStatus } from "@/lib/types";

interface TierMeta {
  label: string;
  icon: LucideIcon;
  className: string;
}

const TIER_META: Record<DeviceTier, TierMeta> = {
  insecure: {
    label: "Insecure",
    icon: ShieldAlert,
    className: "text-[var(--color-critical)] bg-[color-mix(in_oklab,var(--color-critical)_14%,transparent)]",
  },
  partial: {
    label: "Partial",
    icon: ShieldQuestion,
    className: "text-[var(--color-medium)] bg-[color-mix(in_oklab,var(--color-medium)_14%,transparent)]",
  },
  hardened: {
    label: "Hardened",
    icon: ShieldCheck,
    className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_14%,transparent)]",
  },
  unknown: {
    label: "Unknown",
    icon: HelpCircle,
    className: "text-[var(--color-text-muted)] bg-[var(--color-surface-hover)]",
  },
};

const VERDICT_STATUSES: readonly VerdictStatus[] = ["PASS", "FAIL", "PARTIAL", "INCONCLUSIVE"];
const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];
const CONFIDENCES: readonly Confidence[] = ["high", "medium", "low"];

function isVerdictStatus(value: string): value is VerdictStatus {
  return (VERDICT_STATUSES as readonly string[]).includes(value);
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

function isConfidence(value: string): value is Confidence {
  return (CONFIDENCES as readonly string[]).includes(value);
}

interface MetaFieldProps {
  label: string;
  value: string | null;
}

function MetaField({ label, value }: MetaFieldProps) {
  return (
    <div>
      <p className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">{label}</p>
      <p className="mt-1 text-sm text-[var(--color-text)]">
        {value ?? <span className="text-[var(--color-text-muted)]">Not recorded</span>}
      </p>
    </div>
  );
}

export function DeviceDetailPage() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const detail = useFetch(() => api.device(deviceId ?? ""), [deviceId]);

  if (detail.error) {
    return (
      <Shell title="Device" subtitle={deviceId}>
        <ErrorState message={detail.error} />
      </Shell>
    );
  }

  if (detail.loading || !detail.data) {
    return (
      <Shell title="Device">
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </Shell>
    );
  }

  const { device, services, evidence, verdicts, scan_jobs } = detail.data;
  const tier = TIER_META[device.tier];
  const TierIcon = tier.icon;

  return (
    <Shell title={device.display_name} subtitle={device.description}>
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 pt-5">
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium",
                tier.className,
              )}
            >
              <TierIcon className="h-3 w-3" />
              {tier.label}
            </span>
            <span className="font-mono text-xs text-[var(--color-text-secondary)]">
              {device.host ?? <span className="text-[var(--color-text-muted)]">No host configured</span>}
            </span>
            <span className="ml-auto text-xs text-[var(--color-text-muted)]">
              Source: {device.source ?? "unknown"}
            </span>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Inventory</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 pt-2 sm:grid-cols-3">
            <MetaField label="Vendor" value={device.vendor} />
            <MetaField label="Model" value={device.model} />
            <MetaField label="Location" value={device.location} />
            <MetaField label="Owner" value={device.owner} />
            <MetaField label="Notes" value={device.notes} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Services</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {services.length === 0 ? (
              <EmptyState message="No services registered for this device." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {services.map((service) => {
                  const Icon = serviceIcon(service.service_type);
                  return (
                    <li key={service.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                      <Icon className="h-4 w-4 text-[var(--color-text-secondary)]" />
                      <span className="font-mono text-xs tracking-wide text-[var(--color-text-secondary)] uppercase">
                        {service.service_type}
                      </span>
                      {!service.enabled && (
                        <span className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                          disabled
                        </span>
                      )}
                      <span className="ml-auto flex items-center gap-4 font-mono text-xs text-[var(--color-text-muted)]">
                        <span>Internal port: {service.port}</span>
                        <span>
                          Published port:{" "}
                          {service.published_port !== null ? (
                            service.published_port
                          ) : (
                            <span className="italic">not browser-reachable</span>
                          )}
                        </span>
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {evidence.length === 0 ? (
              <EmptyState message="No evidence recorded for this device." />
            ) : (
              <div className="overflow-hidden rounded-md border border-[var(--color-border)]">
                <div className="grid grid-cols-[1fr_1fr_2fr_0.7fr_1.1fr] gap-4 border-b border-[var(--color-border)] px-4 py-2 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                  <span>Evidence</span>
                  <span>Test / Tool</span>
                  <span>Finding</span>
                  <span>Confidence</span>
                  <span>Timestamp</span>
                </div>
                <div className="divide-y divide-[var(--color-border)]">
                  {evidence.map((e) => (
                    <div
                      key={e.evidence_id}
                      className="grid grid-cols-[1fr_1fr_2fr_0.7fr_1.1fr] items-center gap-4 px-4 py-2.5 text-sm"
                    >
                      <span className="truncate font-mono text-xs text-[var(--color-text-secondary)]">
                        {e.evidence_id}
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-[11px] text-[var(--color-text-muted)]">
                          {e.test_id}
                        </span>
                        <span className="block truncate text-[var(--color-text-secondary)]">{e.tool}</span>
                      </span>
                      <span className="truncate text-[var(--color-text)]">{e.finding}</span>
                      {isConfidence(e.confidence) ? (
                        <ConfidenceLabel confidence={e.confidence} />
                      ) : (
                        <span className="font-mono text-xs text-[var(--color-text-muted)]">{e.confidence}</span>
                      )}
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{e.timestamp}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Verdicts</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {verdicts.length === 0 ? (
              <EmptyState message="No verdicts recorded for this device." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {verdicts.map((v) => (
                  <li key={v.verdict_id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    {isVerdictStatus(v.status) ? (
                      <StatusBadge status={v.status} />
                    ) : (
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.status}</span>
                    )}
                    {isSeverity(v.severity) ? (
                      <SeverityBadge severity={v.severity} />
                    ) : (
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.severity}</span>
                    )}
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.control_id}</span>
                    <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">{v.reason}</span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.timestamp}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan history</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {scan_jobs.length === 0 ? (
              <EmptyState message="No scans have been run against this device yet." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {scan_jobs.map((job) => (
                  <li key={job.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">#{job.id}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-[var(--color-text-secondary)]">
                      {job.test_id}
                    </span>
                    <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                      {job.status}
                    </span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{job.created_at}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
