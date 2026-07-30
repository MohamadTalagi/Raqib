import { useMemo, useState } from "react";
import { ChevronDown, AlertTriangle } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { SeverityBadge, StatusBadge } from "@/components/ui/severity-badge";
import { Tabs } from "@/components/ui/tabs";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { ControlRecord, Severity, VerdictStatus } from "@/lib/types";

const FILTERS: Array<VerdictStatus | "ALL"> = [
  "ALL",
  "PASS",
  "FAIL",
  "PARTIAL",
  "INCONCLUSIVE",
  "NOT_APPLICABLE",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const SELECT_CLASS =
  "rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 text-xs text-[var(--color-text-secondary)]";

function controlFor(controls: ControlRecord[] | null, controlId: string): ControlRecord | undefined {
  return controls?.find((c) => c.control_id === controlId);
}

export function VerdictsPage() {
  const verdicts = useFetch(api.verdicts, []);
  const controls = useFetch(api.controls, []);
  const [filter, setFilter] = useState<VerdictStatus | "ALL">("ALL");
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [deviceFilter, setDeviceFilter] = useState<string>("ALL");
  const [expanded, setExpanded] = useState<string | null>(null);

  const deviceOptions = useMemo(() => {
    const set = new Set((verdicts.data ?? []).map((v) => v.device_id));
    return Array.from(set).sort();
  }, [verdicts.data]);

  const filtered = useMemo(() => {
    return (verdicts.data ?? []).filter(
      (v) =>
        (filter === "ALL" || v.status === filter) &&
        (severityFilter === "ALL" || v.severity === severityFilter) &&
        (deviceFilter === "ALL" || v.device_id === deviceFilter),
    );
  }, [verdicts.data, filter, severityFilter, deviceFilter]);

  // Status-tab counts reflect the current severity + device selection, so the
  // numbers always match what the list below actually shows.
  const filterCounts = useMemo(() => {
    const counts: Record<VerdictStatus | "ALL", number> = {
      ALL: 0,
      PASS: 0,
      FAIL: 0,
      PARTIAL: 0,
      INCONCLUSIVE: 0,
      NOT_APPLICABLE: 0,
    };
    for (const v of verdicts.data ?? []) {
      if (severityFilter !== "ALL" && v.severity !== severityFilter) continue;
      if (deviceFilter !== "ALL" && v.device_id !== deviceFilter) continue;
      counts.ALL += 1;
      counts[v.status] += 1;
    }
    return counts;
  }, [verdicts.data, severityFilter, deviceFilter]);

  const loading = verdicts.loading || controls.loading;
  const error = verdicts.error ?? controls.error;

  return (
    <Shell title="Verdicts" subtitle="Deterministic policy-engine results mapped to CGIoT-1:2024">
      <Tabs
        className="mb-3"
        items={FILTERS.map((status) => ({ value: status, label: status, count: filterCounts[status] }))}
        value={filter}
        onChange={(v) => setFilter(v as VerdictStatus | "ALL")}
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-xs text-[var(--color-text-muted)]">
          Severity
          <select
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Severity | "ALL")}
            className={SELECT_CLASS}
          >
            <option value="ALL">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-xs text-[var(--color-text-muted)]">
          Device
          <select
            aria-label="Filter by device"
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
            className={SELECT_CLASS}
          >
            <option value="ALL">All devices</option>
            {deviceOptions.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </label>
        {(severityFilter !== "ALL" || deviceFilter !== "ALL" || filter !== "ALL") && (
          <button
            type="button"
            onClick={() => {
              setFilter("ALL");
              setSeverityFilter("ALL");
              setDeviceFilter("ALL");
            }}
            className="text-xs text-[var(--color-brand)] hover:underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {error ? (
        <ErrorState message={error} />
      ) : loading ? (
        <Skeleton className="h-96" />
      ) : filtered.length === 0 ? (
        <EmptyState message="No verdicts match this filter." />
      ) : (
        <div className="space-y-3">
          {filtered.map((v) => {
            const control = controlFor(controls.data, v.control_id);
            const isOpen = expanded === v.verdict_id;
            return (
              <Card key={v.verdict_id} className="overflow-hidden py-0">
                <button
                  type="button"
                  onClick={() => setExpanded(isOpen ? null : v.verdict_id)}
                  className="flex w-full cursor-pointer items-center gap-4 px-5 py-3.5 text-left transition-colors hover:bg-[var(--color-surface-hover)]"
                >
                  <StatusBadge status={v.status} />
                  <SeverityBadge severity={v.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-[var(--color-text)]">
                      {control?.title ?? v.control_id}
                    </p>
                    <p className="truncate font-mono text-xs text-[var(--color-text-muted)]">
                      {v.control_id} · {v.device_id}
                    </p>
                  </div>
                  {v.conflict_detected ? (
                    <span
                      title="Conflicting evidence was found for this verdict"
                      className="flex shrink-0 items-center gap-1 rounded-md bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] px-2 py-0.5 text-xs font-medium text-[var(--color-medium)]"
                    >
                      <AlertTriangle className="h-3.5 w-3.5" />
                      Conflict
                    </span>
                  ) : null}
                  <ChevronDown
                    className={cn(
                      "h-4 w-4 shrink-0 text-[var(--color-text-muted)] transition-transform",
                      isOpen && "rotate-180",
                    )}
                  />
                </button>
                {isOpen && (
                  <div className="space-y-3 border-t border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 text-sm">
                    {v.conflict_detected ? (
                      <p className="flex items-start gap-2 rounded-md border border-[color-mix(in_oklab,var(--color-medium)_35%,transparent)] bg-[color-mix(in_oklab,var(--color-medium)_10%,transparent)] px-3 py-2 text-[var(--color-medium)]">
                        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                        <span>{v.conflict_reason ?? "Conflicting evidence records were found for this verdict."}</span>
                      </p>
                    ) : null}
                    <p>
                      <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Reason{" "}
                      </span>
                      <span className="text-[var(--color-text-secondary)]">{v.reason}</span>
                    </p>
                    <p>
                      <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Saudi source{" "}
                      </span>
                      <span className="text-[var(--color-text-secondary)]">{v.saudi_source}</span>
                    </p>
                    <p>
                      <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Remediation{" "}
                      </span>
                      <span className="text-[var(--color-text-secondary)]">{v.remediation}</span>
                    </p>
                    <p>
                      <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Policy version{" "}
                      </span>
                      <span className="font-mono text-xs text-[var(--color-text-secondary)]">
                        {v.policy_version ?? "unknown"}
                      </span>
                    </p>
                    <p>
                      <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Evidence{" "}
                      </span>
                      {v.evidence_ids.map((id) => (
                        <span
                          key={id}
                          className="mr-1.5 inline-block rounded bg-black/30 px-1.5 py-0.5 font-mono text-xs text-[var(--color-text-secondary)]"
                        >
                          {id}
                        </span>
                      ))}
                    </p>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </Shell>
  );
}
