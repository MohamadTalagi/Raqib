import { useEffect, useState } from "react";
import { PlayCircle, RefreshCw, Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState } from "@/components/ui/state";
import { api, ApiError } from "@/lib/api";
import { useFetch } from "@/lib/useFetch";
import type { ScanJob } from "@/lib/types";
import { cn } from "@/lib/utils";

const POLL_INTERVAL_MS = 1200;
const IN_FLIGHT_STATUSES = new Set(["pending", "running"]);

function useScanJob(jobId: number | null): [ScanJob | null, (job: ScanJob) => void] {
  const [job, setJob] = useState<ScanJob | null>(null);

  useEffect(() => {
    if (jobId === null) {
      setJob(null);
      return;
    }
    let cancelled = false;
    let timer: number | undefined;

    async function poll() {
      try {
        const latest = await api.getScanJob(jobId as number);
        if (cancelled) return;
        setJob(latest);
        if (IN_FLIGHT_STATUSES.has(latest.status)) {
          timer = window.setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch {
        if (!cancelled) timer = window.setTimeout(poll, POLL_INTERVAL_MS);
      }
    }
    poll();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [jobId]);

  return [job, setJob];
}

const STATUS_COPY: Record<ScanJob["status"], { label: string; tone: string }> = {
  pending: { label: "Queued", tone: "text-[var(--color-text-muted)]" },
  running: { label: "Running on auditor-worker…", tone: "text-[var(--color-low)]" },
  awaiting_finding: { label: "Awaiting your finding", tone: "text-[var(--color-medium)]" },
  recorded: { label: "Recorded as evidence", tone: "text-[var(--color-pass)]" },
  failed: { label: "Failed", tone: "text-[var(--color-critical)]" },
};

export function RunScanPage() {
  const scanTests = useFetch(api.scanTests, []);
  const [deviceId, setDeviceId] = useState<string>("");
  const [testId, setTestId] = useState<string>("");
  const [jobId, setJobId] = useState<number | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [finding, setFinding] = useState("");
  const [confidence, setConfidence] = useState<"high" | "medium" | "low">("high");
  const [recordError, setRecordError] = useState<string | null>(null);
  const [recomputeResult, setRecomputeResult] = useState<number | null>(null);
  const [recomputing, setRecomputing] = useState(false);

  const [job, setJob] = useScanJob(jobId);

  const availableDevices = Array.from(
    new Set((scanTests.data ?? []).flatMap((t) => t.allowed_devices)),
  );
  const testsForDevice = (scanTests.data ?? []).filter((t) => t.allowed_devices.includes(deviceId));

  async function handleRun() {
    setLaunchError(null);
    setRecordError(null);
    setFinding("");
    setRecomputeResult(null);
    try {
      const created = await api.createScanJob(deviceId, testId);
      setJobId(created.id);
    } catch (err) {
      setLaunchError(err instanceof ApiError ? err.message : "Could not start the scan.");
    }
  }

  async function handleRecord() {
    if (job === null) return;
    setRecordError(null);
    try {
      await api.recordScanJob(job.id, finding, confidence);
      const latest = await api.getScanJob(job.id);
      setJob(latest);
    } catch (err) {
      setRecordError(err instanceof ApiError ? err.message : "Could not record this evidence.");
    }
  }

  async function handleRecompute() {
    setRecomputing(true);
    try {
      const result = await api.recomputeVerdicts();
      setRecomputeResult(result.created);
    } catch {
      setRecomputeResult(null);
    } finally {
      setRecomputing(false);
    }
  }

  return (
    <Shell title="Run Scan" subtitle="Trigger a real, whitelisted test against a live device from here">
      {scanTests.error ? (
        <ErrorState message={scanTests.error} />
      ) : (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>1. Choose a device and test</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-end gap-4 pt-2">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-[var(--color-text-muted)]" htmlFor="device-select">
                  Device
                </label>
                <select
                  id="device-select"
                  value={deviceId}
                  onChange={(e) => {
                    setDeviceId(e.target.value);
                    setTestId("");
                  }}
                  className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)]"
                >
                  <option value="">Select a device…</option>
                  {availableDevices.map((d) => (
                    <option key={d} value={d}>
                      {d}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-[var(--color-text-muted)]" htmlFor="test-select">
                  Test
                </label>
                <select
                  id="test-select"
                  value={testId}
                  onChange={(e) => setTestId(e.target.value)}
                  disabled={!deviceId}
                  className="min-w-[260px] rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] disabled:opacity-50"
                >
                  <option value="">Select a test…</option>
                  {testsForDevice.map((t) => (
                    <option key={t.test_id} value={t.test_id}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>

              <button
                type="button"
                onClick={handleRun}
                disabled={!deviceId || !testId || (job !== null && IN_FLIGHT_STATUSES.has(job.status))}
                className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
              >
                <PlayCircle className="h-4 w-4" />
                Run test
              </button>
            </CardContent>
            {launchError && (
              <CardContent className="pt-0 text-sm text-[var(--color-critical)]">{launchError}</CardContent>
            )}
          </Card>

          {job && (
            <Card>
              <CardHeader>
                <CardTitle>2. Result</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 pt-2">
                <div className="flex items-center gap-2 text-sm">
                  {IN_FLIGHT_STATUSES.has(job.status) && (
                    <Loader2 className="h-4 w-4 animate-spin text-[var(--color-low)]" />
                  )}
                  {job.status === "recorded" && <CheckCircle2 className="h-4 w-4 text-[var(--color-pass)]" />}
                  {job.status === "failed" && <XCircle className="h-4 w-4 text-[var(--color-critical)]" />}
                  <span className={cn("font-medium", STATUS_COPY[job.status].tone)}>
                    {STATUS_COPY[job.status].label}
                  </span>
                  <span className="font-mono text-xs text-[var(--color-text-muted)]">
                    job #{job.id} · {job.device_id} · {job.test_id}
                  </span>
                </div>

                {job.status === "failed" && (
                  <p className="text-sm text-[var(--color-critical)]">{job.error}</p>
                )}

                {(job.status === "awaiting_finding" || job.status === "recorded") && (
                  <>
                    <div>
                      <p className="mb-1 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Command run
                      </p>
                      <code className="block overflow-x-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-[var(--color-text)]">
                        {job.command}
                      </code>
                    </div>
                    <div>
                      <p className="mb-1 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Raw output
                      </p>
                      <pre className="max-h-56 overflow-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-[var(--color-text-secondary)]">
                        {job.raw_output}
                      </pre>
                    </div>
                    <div>
                      <p className="mb-1 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        Auto-parsed observations
                      </p>
                      <pre className="overflow-x-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-[var(--color-text-secondary)]">
                        {JSON.stringify(job.observations, null, 2)}
                      </pre>
                    </div>
                  </>
                )}

                {job.status === "awaiting_finding" && (
                  <div className="space-y-3 border-t border-[var(--color-border)] pt-4">
                    <div>
                      <label
                        htmlFor="finding-input"
                        className="mb-1 block text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase"
                      >
                        Your finding, based on the output above
                      </label>
                      <textarea
                        id="finding-input"
                        value={finding}
                        onChange={(e) => setFinding(e.target.value)}
                        rows={2}
                        placeholder="e.g. Port 80 open; no unnecessary Telnet on this device's own container"
                        className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)]"
                      />
                    </div>
                    <div className="flex items-center gap-3">
                      <label className="text-xs text-[var(--color-text-muted)]" htmlFor="confidence-select">
                        Confidence
                      </label>
                      <select
                        id="confidence-select"
                        value={confidence}
                        onChange={(e) => setConfidence(e.target.value as "high" | "medium" | "low")}
                        className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1.5 text-sm text-[var(--color-text)]"
                      >
                        <option value="high">high</option>
                        <option value="medium">medium</option>
                        <option value="low">low</option>
                      </select>
                      <button
                        type="button"
                        onClick={handleRecord}
                        disabled={finding.trim().length === 0}
                        className="ml-auto cursor-pointer rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        Record evidence
                      </button>
                    </div>
                    {recordError && <p className="text-sm text-[var(--color-critical)]">{recordError}</p>}
                  </div>
                )}

                {job.status === "recorded" && (
                  <div className="space-y-3 border-t border-[var(--color-border)] pt-4">
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Saved as <span className="font-mono text-[var(--color-text)]">{job.evidence_id}</span>.
                      Visible on the Evidence page now. Recompute verdicts to see if this changes any
                      compliance outcome.
                    </p>
                    <button
                      type="button"
                      onClick={handleRecompute}
                      disabled={recomputing}
                      className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
                    >
                      {recomputing ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                      Recompute verdicts
                    </button>
                    {recomputeResult !== null && (
                      <p className="text-sm text-[var(--color-pass)]">
                        {recomputeResult === 0
                          ? "No new verdicts (evidence didn't map to a new control result)."
                          : `${recomputeResult} new verdict${recomputeResult === 1 ? "" : "s"} generated — check the Verdicts page.`}
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </Shell>
  );
}
