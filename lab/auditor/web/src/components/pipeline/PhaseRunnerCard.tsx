import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { PlayCircle, Loader2, Ban } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AssessmentStatusBadge } from "@/components/ui/severity-badge";
import { ScanJobCard } from "@/components/pipeline/ScanJobCard";
import { api, ApiError } from "@/lib/api";
import { SCAN_JOB_IN_FLIGHT_STATUSES } from "@/lib/useScanJob";
import type { AssessmentStatus, Device, ScanJob, ScanTestSpec } from "@/lib/types";

const POLL_INTERVAL_MS = 1200;
const IN_FLIGHT_ASSESSMENT_STATUSES = new Set<AssessmentStatus>(["queued", "running"]);

interface RunningJob {
  jobId: number;
  testId: string;
  testLabel: string;
}

interface PhaseRunnerCardProps {
  device: Device;
  /** Already scoped to the calling phase page's own test filter (pipeline
   * phase + this device's applicability) - this component never re-derives
   * which tests belong to which phase. */
  tests: ScanTestSpec[];
  /** Shown next to the test list when there's nothing to check yet, e.g.
   * "No firmware uploaded" - lets a phase page explain its own gating. */
  emptyHint?: ReactNode;
  /** Extra controls rendered once real jobs exist, e.g. NCA Compliance's
   * "Recompute verdicts" button. */
  resultsActions?: ReactNode;
}

/**
 * One device's real scan-test run, for one pipeline phase - the same
 * "select tests -> create one Assessment -> watch each ScanJobCard" flow
 * Run Scan already built, just scoped to a single device and a single
 * phase's tests instead of a whole-catalog picker. Self-contained per
 * device so a cohort of several devices can run in parallel without
 * cross-talk between their state.
 */
export function PhaseRunnerCard({ device, tests, emptyHint, resultsActions }: PhaseRunnerCardProps) {
  const [selectedTestIds, setSelectedTestIds] = useState<Set<string>>(new Set());
  const [jobs, setJobs] = useState<RunningJob[]>([]);
  const [jobStatuses, setJobStatuses] = useState<Record<number, ScanJob["status"]>>({});
  const [launchErrors, setLaunchErrors] = useState<Record<string, string>>({});
  const [launching, setLaunching] = useState(false);
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [assessmentStatus, setAssessmentStatus] = useState<AssessmentStatus | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const hasRunningJob = Object.values(jobStatuses).some((status) => SCAN_JOB_IN_FLIGHT_STATUSES.has(status));
  const allChecked = tests.length > 0 && tests.every((t) => selectedTestIds.has(t.test_id));

  useEffect(() => {
    if (assessmentId === null || assessmentStatus === null || !IN_FLIGHT_ASSESSMENT_STATUSES.has(assessmentStatus)) {
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const latest = await api.getAssessment(assessmentId);
        if (!cancelled) setAssessmentStatus(latest.status);
      } catch {
        // Transient poll failure - the next tick will retry.
      }
    }, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [assessmentId, assessmentStatus]);

  function toggleTest(testId: string, checked: boolean) {
    setSelectedTestIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(testId);
      else next.delete(testId);
      return next;
    });
  }

  function toggleAll(checked: boolean) {
    setSelectedTestIds(checked ? new Set(tests.map((t) => t.test_id)) : new Set());
  }

  function handleJobStatusChange(jobId: number, status: ScanJob["status"]) {
    setJobStatuses((prev) => (prev[jobId] === status ? prev : { ...prev, [jobId]: status }));
  }

  async function handleCancelAssessment() {
    if (assessmentId === null) return;
    setCancelling(true);
    try {
      const updated = await api.cancelAssessment(assessmentId);
      setAssessmentStatus(updated.status);
    } finally {
      setCancelling(false);
    }
  }

  async function handleRunSelected() {
    setLaunchErrors({});
    setLaunching(true);
    const testIds = Array.from(selectedTestIds);

    try {
      const result = await api.createAssessment(device.device_id, testIds);
      setAssessmentId(result.id);
      setAssessmentStatus(result.status);

      const newJobs: RunningJob[] = result.jobs.map((job) => ({
        jobId: job.id,
        testId: job.test_id,
        testLabel: tests.find((t) => t.test_id === job.test_id)?.label ?? job.test_id,
      }));
      const newStatuses: Record<number, ScanJob["status"]> = {};
      for (const job of result.jobs) {
        newStatuses[job.id] = job.status;
      }

      setJobs((prev) => [...newJobs, ...prev]);
      setJobStatuses((prev) => ({ ...prev, ...newStatuses }));
      setLaunchErrors(result.errors);
    } catch (err) {
      setLaunchErrors({ _assessment: err instanceof ApiError ? err.message : "Could not create the assessment." });
    } finally {
      setLaunching(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{device.display_name}</CardTitle>
        <span className="font-mono text-xs text-[var(--color-text-muted)]">{device.device_id}</span>
      </CardHeader>
      <CardContent className="space-y-4 pt-2">
        {tests.length === 0 ? (
          emptyHint ?? <p className="text-xs text-[var(--color-text-muted)]">No applicable tests for this device.</p>
        ) : (
          <>
            <div className="space-y-1">
              <label className="mb-1 flex cursor-pointer items-center gap-2 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                <input
                  type="checkbox"
                  checked={allChecked}
                  onChange={(e) => toggleAll(e.target.checked)}
                  className="h-4 w-4 accent-[var(--color-brand)]"
                />
                Select all
              </label>
              {tests.map((t) => (
                <label
                  key={t.test_id}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
                >
                  <input
                    type="checkbox"
                    checked={selectedTestIds.has(t.test_id)}
                    onChange={(e) => toggleTest(t.test_id, e.target.checked)}
                    className="h-4 w-4 accent-[var(--color-brand)]"
                  />
                  {t.label}
                </label>
              ))}
            </div>

            <div className="flex flex-col gap-2">
              <button
                type="button"
                onClick={handleRunSelected}
                disabled={selectedTestIds.size === 0 || launching || hasRunningJob}
                title={hasRunningJob ? "Wait for the current scan to finish before starting another." : undefined}
                className="inline-flex w-fit cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
              >
                {launching ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
                Run selected ({selectedTestIds.size})
              </button>
              {hasRunningJob && (
                <p className="text-xs text-[var(--color-text-muted)]">
                  A scan is already running for this device — wait for it to finish before starting another.
                </p>
              )}
              {Object.entries(launchErrors).map(([testId, message]) => (
                <p key={testId} className="text-sm text-[var(--color-critical)]">
                  {testId === "_assessment" ? message : `${testId}: ${message}`}
                </p>
              ))}
            </div>
          </>
        )}

        {jobs.length > 0 && (
          <div className="space-y-4 border-t border-[var(--color-border)] pt-4">
            {resultsActions && <div className="flex justify-end">{resultsActions}</div>}
            {assessmentId && assessmentStatus && (
              <div className="flex flex-wrap items-center gap-3 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
                {IN_FLIGHT_ASSESSMENT_STATUSES.has(assessmentStatus) && (
                  <Loader2 className="h-4 w-4 animate-spin text-[var(--color-low)]" />
                )}
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{assessmentId}</span>
                <AssessmentStatusBadge status={assessmentStatus} />
                {IN_FLIGHT_ASSESSMENT_STATUSES.has(assessmentStatus) && (
                  <button
                    type="button"
                    onClick={handleCancelAssessment}
                    disabled={cancelling}
                    className="ml-auto inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-critical)] hover:text-[var(--color-critical)] disabled:opacity-50"
                  >
                    <Ban className="h-3.5 w-3.5" />
                    Cancel assessment
                  </button>
                )}
              </div>
            )}
            {jobs.map((j) => (
              <ScanJobCard key={j.jobId} jobId={j.jobId} testLabel={j.testLabel} onStatusChange={handleJobStatusChange} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
