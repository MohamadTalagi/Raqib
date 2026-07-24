import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, Ban } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { NCAScopeType } from "@/lib/types";

const SCOPE_LABELS: Record<NCAScopeType, string> = {
  device: "Device",
  organization: "Organization",
  mobile: "Mobile app",
  supplier: "Supplier",
  cloud: "Cloud",
};

/** The full 81-guideline catalog, browsable directly - previously only
 * reachable one control at a time via a device's or the organizational
 * page's own (already-relevant-to-that-scope) controls list. */
export function NCAControlsPage() {
  const controls = useFetch(api.ncaControls, []);
  const [domainFilter, setDomainFilter] = useState<string>("all");
  const [scopeFilter, setScopeFilter] = useState<string>("all");

  const domains = useMemo(() => {
    const set = new Set((controls.data ?? []).map((c) => c.domain_name));
    return Array.from(set).sort();
  }, [controls.data]);

  const filtered = useMemo(() => {
    return (controls.data ?? []).filter(
      (c) =>
        (domainFilter === "all" || c.domain_name === domainFilter) &&
        (scopeFilter === "all" || c.scope_type === scopeFilter),
    );
  }, [controls.data, domainFilter, scopeFilter]);

  return (
    <Shell
      title="NCA Controls"
      subtitle="All 81 CGIoT-1:2024 guidelines — browse, filter, and record an assessment for any of them"
    >
      <div className="mb-4 flex flex-wrap gap-3">
        <select
          aria-label="Filter by domain"
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1.5 text-xs text-[var(--color-text-secondary)]"
        >
          <option value="all">All domains</option>
          {domains.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by scope"
          value={scopeFilter}
          onChange={(e) => setScopeFilter(e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1.5 text-xs text-[var(--color-text-secondary)]"
        >
          <option value="all">All scopes</option>
          {(Object.entries(SCOPE_LABELS) as Array<[NCAScopeType, string]>).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        {controls.data && (
          <span className="self-center font-mono-tabular text-xs text-[var(--color-text-muted)]">
            {filtered.length} of {controls.data.length}
          </span>
        )}
      </div>

      {controls.error ? (
        <ErrorState message={controls.error} />
      ) : controls.loading || !controls.data ? (
        <div className="space-y-3">
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState message="No controls match the current filters." />
      ) : (
        <div className="space-y-3">
          {filtered.map((control) => (
            <Link key={control.id} to={`/nca-compliance/controls/${encodeURIComponent(control.id)}`} className="block">
              <Card className="flex flex-wrap items-center gap-4 px-5 py-3.5 transition-colors hover:border-[var(--color-border-strong)]">
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{control.guideline_id}</span>
                <span className="min-w-0 flex-1 truncate text-sm font-medium text-[var(--color-text)]">
                  {control.implementation_summary}
                </span>
                <span className="rounded-md bg-[var(--color-surface-hover)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">
                  {SCOPE_LABELS[control.scope_type]}
                </span>
                <SeverityBadge severity={control.severity} />
                {!control.required && (
                  <span className="font-mono text-[10px] text-[var(--color-text-muted)] uppercase">optional</span>
                )}
                {control.blocking && (
                  <span
                    className="inline-flex items-center gap-1 rounded-md bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-critical)]"
                    title="A failure of this control alone forces the device's overall readiness classification to Failed."
                  >
                    <Ban className="h-3 w-3" />
                    blocking
                  </span>
                )}
                <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-muted)]" />
              </Card>
            </Link>
          ))}
        </div>
      )}
    </Shell>
  );
}
