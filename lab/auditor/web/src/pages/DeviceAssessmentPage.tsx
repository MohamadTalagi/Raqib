import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowUpRight, ClipboardCheck, Eye, Plus, RefreshCw, Sparkles } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { AutoRecordedBadge, BlockingBadge, NCAReadinessBadge, NCAStatusBadge } from "@/components/ui/severity-badge";
import { RecordAssessmentDialog } from "@/components/nca/RecordAssessmentDialog";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import type { NCAAssessment, NCADeviceControlRow, NCADeviceSuggestion } from "@/lib/types";

type Filter = "all" | "unassessed" | "failing" | "suggested" | "auto_recorded";

const FILTERS: Array<{ value: Filter; label: string }> = [
  { value: "all", label: "All" },
  { value: "unassessed", label: "Unassessed" },
  { value: "failing", label: "Failing" },
  { value: "suggested", label: "Has suggestion" },
  { value: "auto_recorded", label: "Auto-recorded" },
];

/** A control counts as assessed once a real verdict is recorded against it -
 * a `not_tested` placeholder (e.g. from recompute) still needs a human. */
function isAssessed(row: NCADeviceControlRow): boolean {
  return Boolean(row.assessment) && row.assessment?.status !== "not_tested";
}

export function DeviceAssessmentPage() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const { showToast } = useToast();
  const [refreshKey, setRefreshKey] = useState(0);

  const detail = useFetch(() => api.ncaDevice(deviceId ?? ""), [deviceId, refreshKey]);
  const suggestionsData = useFetch(() => api.ncaDeviceSuggestions(deviceId ?? ""), [deviceId, refreshKey]);
  const devices = useFetch(api.devices, []);

  const [filter, setFilter] = useState<Filter>("all");
  const [dialog, setDialog] = useState<{ row: NCADeviceControlRow; suggestion: NCADeviceSuggestion | null } | null>(
    null,
  );

  const suggestions = useMemo(
    () => suggestionsData.data?.suggestions ?? {},
    [suggestionsData.data],
  );

  const controls = useMemo(() => detail.data?.controls ?? [], [detail.data]);

  const progress = useMemo(() => {
    const total = controls.length;
    const done = controls.filter(isAssessed).length;
    return { total, done, pct: total === 0 ? 0 : Math.round((done / total) * 100) };
  }, [controls]);

  const filteredByDomain = useMemo(() => {
    const rows = controls.filter((row) => {
      switch (filter) {
        case "unassessed":
          return !isAssessed(row);
        case "failing":
          return row.assessment?.status === "fail";
        case "suggested":
          return Boolean(suggestions[row.control.id]);
        case "auto_recorded":
          return Boolean(row.assessment?.auto_recorded);
        default:
          return true;
      }
    });
    const groups = new Map<string, NCADeviceControlRow[]>();
    for (const row of rows) {
      const key = row.control.domain_name;
      const list = groups.get(key) ?? [];
      list.push(row);
      groups.set(key, list);
    }
    return Array.from(groups.entries());
  }, [controls, filter, suggestions]);

  const loading = detail.loading || suggestionsData.loading;

  if (detail.error) {
    return (
      <Shell title="Assess device" subtitle={deviceId}>
        <ErrorState message={detail.error} />
      </Shell>
    );
  }

  return (
    <Shell
      title={detail.data ? `Assess: ${detail.data.display_name}` : "Assess device"}
      subtitle={`${deviceId} · NCA CGIoT-1:2024 device-scope controls`}
    >
      <div className="space-y-6">
        <div className="flex flex-wrap items-center gap-3">
          <Link
            to={`/devices/${deviceId}`}
            className="inline-flex items-center gap-1 text-xs text-[var(--color-brand)] hover:underline"
          >
            Open full device detail <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
          <Link
            to="/nca-compliance"
            className="inline-flex items-center gap-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
          >
            Back to NCA Compliance
          </Link>
        </div>

        {/* Progress + readiness */}
        <Card>
          <CardContent className="space-y-4 pt-5">
            {loading || !detail.data ? (
              <Skeleton className="h-20" />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-4">
                  <NCAStatusBadge status={detail.data.overall_status} />
                  <NCAReadinessBadge classification={detail.data.readiness.classification} />
                  <span className="font-mono-tabular text-sm text-[var(--color-text-secondary)]">
                    {detail.data.score === null ? "not assessed" : `${detail.data.score}% score`}
                  </span>
                  <span className="ml-auto inline-flex items-center gap-1.5 text-sm font-medium text-[var(--color-text)]">
                    <ClipboardCheck className="h-4 w-4 text-[var(--color-brand)]" />
                    {progress.done} / {progress.total} controls assessed
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--color-surface-hover)]">
                  <div
                    className="h-full rounded-full bg-[var(--color-brand)] transition-all"
                    style={{ width: `${progress.pct}%` }}
                    role="progressbar"
                    aria-valuenow={progress.pct}
                    aria-valuemin={0}
                    aria-valuemax={100}
                  />
                </div>
                {detail.data.readiness.blocking_control_ids.length > 0 && (
                  <p className="text-xs text-[var(--color-critical)]">
                    Blocking control(s) failing: {detail.data.readiness.blocking_control_ids.join(", ")}
                  </p>
                )}
              </>
            )}
          </CardContent>
        </Card>

        {/* Checklist */}
        <Card>
          <CardHeader className="flex-col items-start gap-3">
            <CardTitle>Assessment checklist</CardTitle>
            <div className="flex flex-wrap gap-2">
              {FILTERS.map((f) => {
                const count =
                  f.value === "all"
                    ? controls.length
                    : f.value === "unassessed"
                      ? controls.filter((r) => !isAssessed(r)).length
                      : f.value === "failing"
                        ? controls.filter((r) => r.assessment?.status === "fail").length
                        : f.value === "auto_recorded"
                          ? controls.filter((r) => r.assessment?.auto_recorded).length
                          : controls.filter((r) => suggestions[r.control.id]).length;
                return (
                  <button
                    key={f.value}
                    type="button"
                    onClick={() => setFilter(f.value)}
                    className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                      filter === f.value
                        ? "border-[var(--color-brand)] bg-[color-mix(in_oklab,var(--color-brand)_10%,transparent)] text-[var(--color-brand)]"
                        : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                    }`}
                  >
                    {f.label}
                    <span className="font-mono-tabular text-[10px] text-[var(--color-text-muted)]">{count}</span>
                  </button>
                );
              })}
            </div>
          </CardHeader>
          <CardContent className="pt-2">
            {loading || !detail.data ? (
              <div className="space-y-2">
                <Skeleton className="h-12" />
                <Skeleton className="h-12" />
                <Skeleton className="h-12" />
              </div>
            ) : filteredByDomain.length === 0 ? (
              <EmptyState message="No controls match this filter." />
            ) : (
              <div className="space-y-6">
                {filteredByDomain.map(([domainName, rows]) => (
                  <div key={domainName}>
                    <h3 className="mb-1 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
                      {domainName}
                    </h3>
                    <ul className="divide-y divide-[var(--color-border)]">
                      {rows.map((row) => {
                        const suggestion = suggestions[row.control.id] ?? null;
                        const assessed = isAssessed(row);
                        return (
                          <li key={row.control.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                            <Link
                              to={`/nca-compliance/controls/${encodeURIComponent(row.control.id)}?device_id=${encodeURIComponent(deviceId ?? "")}`}
                              className="font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
                            >
                              {row.control.guideline_id}
                            </Link>
                            <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                              {row.control.implementation_summary}
                            </span>
                            {suggestion && !assessed && (
                              <span
                                className="inline-flex items-center gap-1 rounded-md border border-[var(--color-brand)]/40 bg-[color-mix(in_oklab,var(--color-brand)_8%,transparent)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-brand)]"
                                title={suggestion.reasons.join("\n")}
                              >
                                <Sparkles className="h-3 w-3" />
                                suggests {suggestion.suggested_status.replace("_", " ")}
                              </span>
                            )}
                            {row.control.blocking && <BlockingBadge size="xs" />}
                            {row.assessment?.auto_recorded && <AutoRecordedBadge size="xs" />}
                            <NCAStatusBadge status={row.assessment?.status ?? "not_tested"} />
                            <button
                              type="button"
                              onClick={() => setDialog({ row, suggestion })}
                              className="inline-flex shrink-0 items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                            >
                              {row.assessment?.auto_recorded ? (
                                <>
                                  <Eye className="h-3 w-3" />
                                  Review &amp; confirm
                                </>
                              ) : row.assessment && row.assessment.status !== "not_tested" ? (
                                <>
                                  <RefreshCw className="h-3 w-3" />
                                  Retest
                                </>
                              ) : (
                                <>
                                  <Plus className="h-3 w-3" />
                                  Record
                                </>
                              )}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {dialog && (
        <RecordAssessmentDialog
          open={Boolean(dialog)}
          control={dialog.row.control}
          devices={devices.data ?? []}
          initialDeviceId={deviceId}
          // Retest an existing real assessment; otherwise a brand-new one that
          // can be pre-filled from the auto-verdict suggestion.
          existingAssessment={
            dialog.row.assessment && dialog.row.assessment.status !== "not_tested"
              ? dialog.row.assessment
              : null
          }
          suggestion={dialog.suggestion}
          onCancel={() => setDialog(null)}
          onSaved={(saved: NCAAssessment) => {
            setDialog(null);
            showToast(`Assessment ${saved.id} recorded (${saved.status}).`, "success");
            setRefreshKey((k) => k + 1);
          }}
        />
      )}
    </Shell>
  );
}
