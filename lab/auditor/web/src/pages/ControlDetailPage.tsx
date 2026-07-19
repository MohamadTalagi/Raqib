import { Link, useParams } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { SeverityBadge, StatusBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { ControlRecord, VerdictStatus } from "@/lib/types";

const VERDICT_STATUSES: readonly VerdictStatus[] = ["PASS", "FAIL", "PARTIAL", "INCONCLUSIVE"];

function isVerdictStatus(value: string): value is VerdictStatus {
  return (VERDICT_STATUSES as readonly string[]).includes(value);
}

function controlFrom(controls: ControlRecord[] | null, controlId: string): ControlRecord | undefined {
  return controls?.find((c) => c.control_id === controlId);
}

export function ControlDetailPage() {
  const { controlId } = useParams<{ controlId: string }>();
  const controls = useFetch(api.controls, []);
  const rollup = useFetch(() => api.controlVerdicts(controlId ?? ""), [controlId]);

  const control = controlFrom(controls.data, controlId ?? "");
  const loading = controls.loading || rollup.loading;
  const error = controls.error ?? rollup.error;

  if (error) {
    return (
      <Shell title="Control" subtitle={controlId}>
        <ErrorState message={error} />
      </Shell>
    );
  }

  if (loading || !control || !rollup.data) {
    return (
      <Shell title="Control">
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </Shell>
    );
  }

  return (
    <Shell title={control.control_id} subtitle={control.title}>
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 pt-5">
            <SeverityBadge severity={control.severity} />
            {control.saudi_source.map((source) => (
              <span
                key={`${source.framework}-${source.reference}`}
                className="font-mono text-xs text-[var(--color-text-secondary)]"
              >
                {source.framework} §{source.reference}
              </span>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Applicability</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {control.applicability.device_type.length === 0 ? (
              <EmptyState message="No device types listed." />
            ) : (
              <div className="flex flex-wrap gap-2">
                {control.applicability.device_type.map((type) => (
                  <span
                    key={type}
                    className="rounded-md bg-[var(--color-surface-hover)] px-2 py-0.5 font-mono text-xs text-[var(--color-text-secondary)]"
                  >
                    {type}
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Required evidence</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {control.required_evidence.length === 0 ? (
              <EmptyState message="No required evidence tests listed." />
            ) : (
              <ul className="space-y-1.5">
                {control.required_evidence.map((req) => (
                  <li key={req.test_id} className="font-mono text-xs text-[var(--color-text-secondary)]">
                    {req.test_id}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Pass / fail conditions</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            <pre className="overflow-x-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-[var(--color-text-secondary)]">
              {JSON.stringify(control.conditions, null, 2)}
            </pre>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Remediation</CardTitle>
          </CardHeader>
          <CardContent className="pt-2 text-sm text-[var(--color-text-secondary)]">
            {control.remediation}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Verdicts by device</CardTitle>
            <span className="flex items-center gap-3 text-xs">
              <span className="font-mono-tabular text-[var(--color-pass)]">{rollup.data.counts.PASS} pass</span>
              <span className="font-mono-tabular text-[var(--color-critical)]">{rollup.data.counts.FAIL} fail</span>
            </span>
          </CardHeader>
          <CardContent className="pt-2">
            {rollup.data.verdicts.length === 0 ? (
              <EmptyState message="No verdicts recorded for this control yet." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {rollup.data.verdicts.map((v) => (
                  <li key={v.verdict_id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    {isVerdictStatus(v.status) ? (
                      <StatusBadge status={v.status} />
                    ) : (
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.status}</span>
                    )}
                    <Link
                      to={`/devices/${v.device_id}`}
                      className="inline-flex items-center gap-0.5 font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
                    >
                      {v.device_id}
                      <ArrowUpRight className="h-3 w-3" />
                    </Link>
                    <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">{v.reason}</span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.timestamp}</span>
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
