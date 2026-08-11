import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  Ban,
  CheckCircle2,
  Loader2,
  Radar,
  HardDrive,
  Fingerprint,
  Bug,
  ClipboardCheck,
  Flame,
  ShieldCheck,
} from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState } from "@/components/ui/state";
import { Skeleton } from "@/components/ui/skeleton";
import { StatTile } from "@/components/ui/stat-tile";
import { api } from "@/lib/api";
import type { AutomatedRun, AutomatedRunStatus } from "@/lib/types";

const POLL_INTERVAL_MS = 1500;
const IN_FLIGHT_STATUSES = new Set<AutomatedRunStatus>(["pending", "running"]);

const STAGE_LABEL: Record<string, string> = {
  discovery: "Discovery: scanning the network and registering new devices",
  fingerprinting_and_compliance: "Running Fingerprinting and NCA compliance collectors",
  vulnerability_intelligence: "Running Vulnerability Intelligence on devices with firmware",
  pqc_readiness: "Checking Post-Quantum Readiness (informational only)",
  nca_compliance: "Auto-recording NCA compliance assessments",
  done: "Done",
};

const STATUS_LABEL: Record<AutomatedRunStatus, string> = {
  pending: "Pending",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function AutomatedRunProgressPage() {
  const { runId } = useParams<{ runId: string }>();
  const [run, setRun] = useState<AutomatedRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  // Refs, not the useScanJob.ts-style closure-local `cancelled` boolean
  // this codebase otherwise uses for polling: handleCancel (outside the
  // effect below) needs to be able to stop the poll loop too, which a
  // variable scoped inside the effect's own closure can't support.
  const cancelledRef = useRef(false);
  const timerRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!runId) return;
    cancelledRef.current = false;

    async function fetchOnce() {
      try {
        const latest = await api.getAutomatedRun(Number(runId));
        if (cancelledRef.current) return;
        setRun(latest);
        if (IN_FLIGHT_STATUSES.has(latest.status)) {
          timerRef.current = window.setTimeout(fetchOnce, POLL_INTERVAL_MS);
        }
      } catch (err) {
        if (!cancelledRef.current) setError(err instanceof Error ? err.message : "Could not load this run.");
      }
    }

    fetchOnce();
    return () => {
      cancelledRef.current = true;
      window.clearTimeout(timerRef.current);
    };
  }, [runId]);

  async function handleCancel() {
    if (!runId) return;
    setCancelling(true);
    try {
      const updated = await api.cancelAutomatedRun(Number(runId));
      // Stop trusting any poll response still in flight, and stop the next
      // scheduled poll - otherwise a stale "running" response that
      // resolves after this cancel call can overwrite `run` right back to
      // "Running" and silently resume polling, since it would still see an
      // in-flight status and re-arm its own timeout.
      cancelledRef.current = true;
      window.clearTimeout(timerRef.current);
      setRun(updated);
    } finally {
      setCancelling(false);
    }
  }

  const summary = run?.summary ?? {};
  const inFlight = run ? IN_FLIGHT_STATUSES.has(run.status) : false;

  return (
    <Shell title="Fully Automated Run" subtitle="Discovery through NCA sign-off, end to end">
      {error ? (
        <ErrorState message={error} />
      ) : !run ? (
        <Skeleton className="h-64" />
      ) : (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Run #{run.id}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 pt-2">
              <div className="flex flex-wrap items-center gap-3">
                {inFlight && <Loader2 className="h-4 w-4 animate-spin text-[var(--color-low)]" />}
                {run.status === "completed" && <CheckCircle2 className="h-4 w-4 text-[var(--color-pass)]" />}
                {run.status === "failed" && <Ban className="h-4 w-4 text-[var(--color-critical)]" />}
                <span className="text-sm font-medium text-[var(--color-text)]">{STATUS_LABEL[run.status]}</span>
                {run.current_stage && (
                  <span className="text-xs text-[var(--color-text-secondary)]">
                    {STAGE_LABEL[run.current_stage] ?? run.current_stage}
                  </span>
                )}
                {inFlight && (
                  <button
                    type="button"
                    onClick={handleCancel}
                    disabled={cancelling}
                    className="ml-auto inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-critical)] hover:text-[var(--color-critical)] disabled:opacity-50"
                  >
                    <Ban className="h-3.5 w-3.5" />
                    Cancel run
                  </button>
                )}
              </div>
              {run.error && <p className="text-sm text-[var(--color-critical)]">{run.error}</p>}
              {run.status === "cancelled" && (
                <p className="text-xs text-[var(--color-text-muted)]">
                  Cancelled - any step already dispatched before the cancellation was still left to finish.
                </p>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-8">
            <StatTile label="Hosts discovered" value={summary.hosts_discovered ?? 0} icon={Radar} accent="neutral" />
            <StatTile label="Devices registered" value={summary.devices_registered ?? 0} icon={HardDrive} accent="brand" />
            <StatTile label="Tests run" value={summary.tests_run ?? 0} icon={Fingerprint} accent="neutral" />
            <StatTile label="Evidence recorded" value={summary.evidence_recorded ?? 0} icon={Fingerprint} accent="neutral" />
            <StatTile label="Firmware CVE scans" value={summary.vuln_intel_devices_scanned ?? 0} icon={Bug} accent="neutral" />
            <StatTile label="Device CVE lookups" value={summary.device_cve_devices_scanned ?? 0} icon={Bug} accent="neutral" />
            <StatTile label="Post-quantum checks" value={summary.pqc_devices_scanned ?? 0} icon={ShieldCheck} accent="neutral" />
            <StatTile
              label="NCA assessments auto-recorded"
              value={summary.nca_assessments_recorded ?? 0}
              icon={ClipboardCheck}
              accent="neutral"
            />
          </div>

          {summary.errors && summary.errors.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Warnings</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 pt-2">
                {summary.errors.map((message, i) => (
                  <p key={i} className="text-xs text-[var(--color-text-secondary)]">
                    {message}
                  </p>
                ))}
              </CardContent>
            </Card>
          )}

          {run.status === "completed" && (
            <Card>
              <CardHeader>
                <CardTitle>Review the results</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-3 pt-2">
                <Link
                  to="/devices"
                  className="inline-flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
                >
                  <HardDrive className="h-4 w-4" /> Devices
                </Link>
                <Link
                  to="/nca-compliance"
                  className="inline-flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
                >
                  <ClipboardCheck className="h-4 w-4" /> NCA Compliance
                </Link>
                <Link
                  to="/nca-compliance"
                  className="inline-flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
                >
                  <ClipboardCheck className="h-4 w-4" /> NCA Compliance
                </Link>
                <Link
                  to="/risk"
                  className="inline-flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
                >
                  <Flame className="h-4 w-4" /> Risk Assessment
                </Link>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </Shell>
  );
}
