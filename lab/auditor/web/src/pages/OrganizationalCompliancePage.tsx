import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, ClipboardCheck, Plus, RefreshCw } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { BlockingBadge, NCAReadinessBadge, NCAStatusBadge } from "@/components/ui/severity-badge";
import { DomainSummaryGrid } from "@/components/nca/DomainSummaryGrid";
import { ChecklistAssessmentPanel } from "@/components/nca/ChecklistAssessmentPanel";
import { RecordAssessmentDialog } from "@/components/nca/RecordAssessmentDialog";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import type { NCAAssessment, NCAAssessmentSuggestion, NCADeviceControlRow } from "@/lib/types";

type Filter = "all" | "unassessed" | "failing";

const FILTERS: Array<{ value: Filter; label: string }> = [
  { value: "all", label: "All" },
  { value: "unassessed", label: "Unassessed" },
  { value: "failing", label: "Failing" },
];

/** A control counts as assessed once a real verdict is recorded against it -
 * a `not_tested` placeholder (e.g. from recompute) still needs a human. */
function isAssessed(row: NCADeviceControlRow): boolean {
  return Boolean(row.assessment) && row.assessment?.status !== "not_tested";
}

/**
 * Organizational-scope controls - domain 1 (governance) plus the mobile,
 * supplier, and cloud guideline groups. These are manual-assessment-only by
 * design: no automated mapping ever targets them, because a network or
 * device scan cannot demonstrate policy approval, personnel training, audit
 * outcomes, or supplier/cloud contract terms (see
 * policies/nca/finding_mappings.py's own docstring for the same rule
 * enforced server-side). A guided checklist (where one has been authored -
 * see policies/nca/seed_checklists.py) still only ever *suggests*; the
 * auditor reviews and signs in RecordAssessmentDialog before anything is
 * recorded - same "AI-assisted, not AI-decided" contract as a device's own
 * automated-evidence suggestions.
 *
 * There is exactly one organizational scope ("default"), unlike devices
 * (many, each with its own workspace route) - so this page doubles as both
 * the org-wide dashboard (readiness/domain-summary) and the guided
 * assessment workspace, rather than splitting those into two routes the
 * way DeviceAssessmentPage is split from the org-wide NCACompliancePage.
 */
export function OrganizationalCompliancePage() {
  const { showToast } = useToast();
  const [refreshKey, setRefreshKey] = useState(0);
  const org = useFetch(api.ncaOrganization, [refreshKey]);
  const coverage = useFetch(api.ncaCoverage, [refreshKey]);
  const [filter, setFilter] = useState<Filter>("all");
  const [checklistFor, setChecklistFor] = useState<NCADeviceControlRow | null>(null);
  const [recordDialog, setRecordDialog] = useState<{
    row: NCADeviceControlRow;
    suggestion: NCAAssessmentSuggestion | null;
  } | null>(null);

  const controls = useMemo(() => org.data?.controls ?? [], [org.data]);

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
  }, [controls, filter]);

  return (
    <Shell
      title="Organizational Compliance"
      subtitle="Governance, personnel, supplier, and cloud controls — guided review where a checklist exists"
    >
      {org.error ? (
        <ErrorState message={org.error} />
      ) : org.loading || !org.data ? (
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-64" />
        </div>
      ) : (
        <div className="space-y-6">
          <Card>
            <CardContent className="space-y-4 pt-5">
              <div className="flex flex-wrap items-center gap-4">
                <NCAStatusBadge status={org.data.overall_status} />
                <span className="font-mono-tabular text-sm text-[var(--color-text-secondary)]">
                  {org.data.score === null ? "not assessed" : `${org.data.score}% informational score`}
                </span>
                <span className="ml-auto inline-flex items-center gap-1.5 text-sm font-medium text-[var(--color-text)]">
                  <ClipboardCheck className="h-4 w-4 text-[var(--color-brand)]" />
                  {progress.done} / {progress.total} controls assessed
                </span>
              </div>
              {coverage.data && (
                <p className="text-xs text-[var(--color-text-muted)]">
                  {coverage.data.guided_or_automated_count} of {coverage.data.total_guidelines} guidelines framework-wide
                  have collector or guided-checklist support today ({coverage.data.checklist_count} checklists authored).
                </p>
              )}
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
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Compliance readiness</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 pt-2">
              <div className="flex flex-wrap items-center gap-3">
                <NCAReadinessBadge classification={org.data.readiness.classification} />
                <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                  pass ≥{org.data.readiness.pass_threshold}% &middot; fail &lt;{org.data.readiness.partial_threshold}%
                </span>
              </div>
              <ul className="space-y-1 text-xs text-[var(--color-text-secondary)]">
                {org.data.readiness.reasons.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
              {org.data.readiness.blocking_control_ids.length > 0 && (
                <p className="text-xs text-[var(--color-critical)]">
                  Blocking control(s): {org.data.readiness.blocking_control_ids.join(", ")}
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Domain summary</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <DomainSummaryGrid domains={Object.entries(org.data.domain_summary)} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex-col items-start gap-3">
              <CardTitle>Controls</CardTitle>
              <div className="flex flex-wrap gap-2">
                {FILTERS.map((f) => {
                  const count =
                    f.value === "all"
                      ? controls.length
                      : f.value === "unassessed"
                        ? controls.filter((r) => !isAssessed(r)).length
                        : controls.filter((r) => r.assessment?.status === "fail").length;
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
              {filteredByDomain.length === 0 ? (
                <EmptyState message="No controls match this filter." />
              ) : (
                <div className="space-y-6">
                  {filteredByDomain.map(([domainName, rows]) => (
                    <div key={domainName}>
                      <h3 className="mb-1 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
                        {domainName}
                      </h3>
                      <ul className="divide-y divide-[var(--color-border)]">
                        {rows.map((row) => (
                          <li key={row.control.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                            <Link
                              to={`/nca-compliance/controls/${encodeURIComponent(row.control.id)}`}
                              className="inline-flex items-center gap-1 font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
                            >
                              {row.control.guideline_id}
                              <ArrowUpRight className="h-3 w-3" />
                            </Link>
                            <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                              {row.control.implementation_summary}
                            </span>
                            {row.control.blocking && <BlockingBadge size="xs" />}
                            <NCAStatusBadge status={row.assessment?.status ?? "not_tested"} />
                            <button
                              type="button"
                              onClick={() => setChecklistFor(row)}
                              className="inline-flex shrink-0 items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                            >
                              {isAssessed(row) ? (
                                <>
                                  <RefreshCw className="h-3 w-3" />
                                  Retest
                                </>
                              ) : (
                                <>
                                  <Plus className="h-3 w-3" />
                                  Assess
                                </>
                              )}
                            </button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {checklistFor && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={() => setChecklistFor(null)}
        >
          <div
            className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-6 shadow-xl"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 className="text-sm font-semibold text-[var(--color-text)]">
              {checklistFor.control.guideline_id} &middot; {checklistFor.control.domain_name}
            </h2>
            <p className="mt-2 text-xs text-[var(--color-text-secondary)]">
              {checklistFor.control.canonical_requirement}
            </p>
            <div className="mt-4">
              <ChecklistAssessmentPanel
                control={checklistFor.control}
                onContinue={(suggestion) => {
                  setRecordDialog({ row: checklistFor, suggestion });
                  setChecklistFor(null);
                }}
              />
            </div>
          </div>
        </div>
      )}

      {recordDialog && (
        <RecordAssessmentDialog
          open={Boolean(recordDialog)}
          control={recordDialog.row.control}
          devices={[]}
          existingAssessment={isAssessed(recordDialog.row) ? recordDialog.row.assessment : null}
          suggestion={recordDialog.suggestion}
          onCancel={() => setRecordDialog(null)}
          onSaved={(saved: NCAAssessment) => {
            setRecordDialog(null);
            showToast(`Assessment ${saved.id} recorded (${saved.status}).`, "success");
            setRefreshKey((k) => k + 1);
          }}
        />
      )}
    </Shell>
  );
}
