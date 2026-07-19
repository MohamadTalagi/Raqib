import { Link } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { ControlRecord, VerdictRecord } from "@/lib/types";

interface ControlCounts {
  pass: number;
  fail: number;
}

function countsFor(verdicts: VerdictRecord[], controlId: string): ControlCounts {
  const forControl = verdicts.filter((v) => v.control_id === controlId);
  return {
    pass: forControl.filter((v) => v.status === "PASS").length,
    fail: forControl.filter((v) => v.status === "FAIL").length,
  };
}

function sourceLabel(control: ControlRecord): string | null {
  const first = control.saudi_source[0];
  if (!first) return null;
  return `${first.framework} §${first.reference}`;
}

export function ControlsPage() {
  const controls = useFetch(api.controls, []);
  const verdicts = useFetch(api.verdicts, []);

  const loading = controls.loading || verdicts.loading;
  const error = controls.error ?? verdicts.error;

  return (
    <Shell title="Controls" subtitle="NCA CGIoT-1:2024 controls mapped to automated and manual evidence">
      {error ? (
        <ErrorState message={error} />
      ) : loading || !controls.data ? (
        <div className="space-y-3">
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </div>
      ) : controls.data.length === 0 ? (
        <EmptyState message="No controls loaded." />
      ) : (
        <div className="space-y-3">
          {controls.data.map((control) => {
            const counts = countsFor(verdicts.data ?? [], control.control_id);
            const source = sourceLabel(control);
            return (
              <Link key={control.control_id} to={`/controls/${control.control_id}`} className="block">
                <Card className="flex flex-wrap items-center gap-4 px-5 py-3.5 transition-colors hover:border-[var(--color-border-strong)]">
                  <span className="font-mono text-xs text-[var(--color-text-muted)]">{control.control_id}</span>
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-[var(--color-text)]">
                    {control.title}
                  </span>
                  <SeverityBadge severity={control.severity} />
                  {source && (
                    <span className="font-mono text-xs text-[var(--color-text-secondary)]">{source}</span>
                  )}
                  <span className="flex items-center gap-3 text-xs">
                    <span className="font-mono-tabular text-[var(--color-pass)]">{counts.pass} pass</span>
                    <span className="font-mono-tabular text-[var(--color-critical)]">{counts.fail} fail</span>
                  </span>
                  <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-muted)]" />
                </Card>
              </Link>
            );
          })}
        </div>
      )}
    </Shell>
  );
}
