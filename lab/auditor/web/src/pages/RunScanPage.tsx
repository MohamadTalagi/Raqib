import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PlayCircle, RefreshCw, Loader2, CheckCircle2, XCircle, Ban } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState } from "@/components/ui/state";
import { api, ApiError } from "@/lib/api";
import { useFetch } from "@/lib/useFetch";
import type { AssessmentStatus, ScanJob, ScanTestCategory, ScanTestSpec, ServiceType } from "@/lib/types";
import { cn } from "@/lib/utils";
import { useToast } from "@/lib/useToast";

const POLL_INTERVAL_MS = 1200;
const IN_FLIGHT_STATUSES = new Set(["pending", "running"]);
const IN_FLIGHT_ASSESSMENT_STATUSES = new Set<AssessmentStatus>(["queued", "running"]);

const ASSESSMENT_STATUS_COPY: Record<AssessmentStatus, { label: string; tone: string }> = {
  queued: { label: "Queued", tone: "text-[var(--color-text-muted)]" },
  running: { label: "Running", tone: "text-[var(--color-low)]" },
  partially_completed: { label: "Partially completed", tone: "text-[var(--color-medium)]" },
  completed: { label: "Completed", tone: "text-[var(--color-pass)]" },
  failed: { label: "Failed", tone: "text-[var(--color-critical)]" },
  cancelled: { label: "Cancelled", tone: "text-[var(--color-text-muted)]" },
};

const SECTIONS: { category: ScanTestCategory; title: string }[] = [
  { category: "web-and-auth", title: "1. Web and Authentication Assessment" },
  { category: "network-and-protocol", title: "2. Network and Protocol Assessment" },
];

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

interface ScanJobCardProps {
  jobId: number;
  testLabel: string;
  onStatusChange: (jobId: number, status: ScanJob["status"]) => void;
}

function ScanJobCard({ jobId, testLabel, onStatusChange }: ScanJobCardProps) {
  const { showToast } = useToast();
  const [job, setJob] = useScanJob(jobId);
  const [finding, setFinding] = useState("");
  const [confidence, setConfidence] = useState<"high" | "medium" | "low">("high");
  const [recordError, setRecordError] = useState<string | null>(null);

  useEffect(() => {
    if (job) onStatusChange(jobId, job.status);
  }, [jobId, job, onStatusChange]);

  async function handleRecord() {
    if (job === null) return;
    setRecordError(null);
    try {
      await api.recordScanJob(job.id, finding, confidence);
      const latest = await api.getScanJob(job.id);
      setJob(latest);
      showToast(`Evidence recorded for ${testLabel}.`, "success");
    } catch (err) {
      setRecordError(err instanceof ApiError ? err.message : "Could not record this evidence.");
    }
  }

  if (job === null) {
    return (
      <Card>
        <CardContent className="flex items-center gap-2 pt-5 text-sm text-[var(--color-text-muted)]">
          <Loader2 className="h-4 w-4 animate-spin" />
          Starting {testLabel}…
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="space-y-4 pt-5">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {IN_FLIGHT_STATUSES.has(job.status) && (
            <Loader2 className="h-4 w-4 animate-spin text-[var(--color-low)]" />
          )}
          {job.status === "recorded" && <CheckCircle2 className="h-4 w-4 text-[var(--color-pass)]" />}
          {job.status === "failed" && <XCircle className="h-4 w-4 text-[var(--color-critical)]" />}
          <span className="font-medium text-[var(--color-text)]">{testLabel}</span>
          <span className={cn("font-medium", STATUS_COPY[job.status].tone)}>
            {STATUS_COPY[job.status].label}
          </span>
          <span className="font-mono text-xs text-[var(--color-text-muted)]">
            job #{job.id} · {job.device_id} · {job.test_id}
          </span>
        </div>

        {job.status === "failed" && <p className="text-sm text-[var(--color-critical)]">{job.error}</p>}

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
                htmlFor={`finding-input-${job.id}`}
                className="mb-1 block text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase"
              >
                Your finding, based on the output above
              </label>
              <textarea
                id={`finding-input-${job.id}`}
                value={finding}
                onChange={(e) => setFinding(e.target.value)}
                rows={2}
                placeholder="e.g. Port 80 open; no unnecessary Telnet on this device's own container"
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)]"
              />
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-[var(--color-text-muted)]" htmlFor={`confidence-select-${job.id}`}>
                Confidence
              </label>
              <select
                id={`confidence-select-${job.id}`}
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
          <p className="border-t border-[var(--color-border)] pt-4 text-sm text-[var(--color-text-secondary)]">
            Saved as <span className="font-mono text-[var(--color-text)]">{job.evidence_id}</span>. Visible
            on the Evidence page now.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

interface RunningJob {
  jobId: number;
  testId: string;
  testLabel: string;
}

function TestCheckbox({
  test,
  checked,
  onChange,
}: {
  test: ScanTestSpec;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="h-4 w-4 accent-[var(--color-brand)]"
      />
      {test.label}
    </label>
  );
}

export function RunScanPage() {
  const devices = useFetch(api.devices, []);
  const scanTests = useFetch(api.scanTests, []);
  const { showToast } = useToast();
  const [deviceId, setDeviceId] = useState<string>("");
  const [selectedTestIds, setSelectedTestIds] = useState<Set<string>>(new Set());
  const [jobs, setJobs] = useState<RunningJob[]>([]);
  const [jobStatuses, setJobStatuses] = useState<Record<number, ScanJob["status"]>>({});
  const [launchErrors, setLaunchErrors] = useState<Record<string, string>>({});
  const [launching, setLaunching] = useState(false);
  const [recomputing, setRecomputing] = useState(false);
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [assessmentStatus, setAssessmentStatus] = useState<AssessmentStatus | null>(null);
  const [cancelling, setCancelling] = useState(false);

  // A scan already in flight (pending/running) blocks launching another one -
  // there's no need to distinguish which test it is, just whether the
  // worker is currently busy with something the user started here.
  const hasRunningJob = Object.values(jobStatuses).some((status) => IN_FLIGHT_STATUSES.has(status));

  // Polls the current assessment's aggregate status while it's in flight -
  // the same lightweight setTimeout-poll pattern useScanJob already uses
  // per job, one level up for the batch as a whole.
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

  function handleJobStatusChange(jobId: number, status: ScanJob["status"]) {
    setJobStatuses((prev) => (prev[jobId] === status ? prev : { ...prev, [jobId]: status }));
  }

  // Registered devices are the only valid scan targets - a scan job resolves
  // its target from the devices table, so an unregistered device has no
  // enabled service for the worker to hit.
  const registeredDevices = (devices.data ?? []).filter((d) => d.registered);

  const selectedDevice = registeredDevices.find((d) => d.device_id === deviceId);
  const deviceServiceTypes = new Set<ServiceType>(
    (selectedDevice?.services ?? []).filter((s) => s.enabled).map((s) => s.service_type),
  );
  // A test applies to a device if any of the test's applicable service types
  // matches one of the service types that device actually exposes - an
  // intersection, not a lookup of the device by name against a fixed list.
  const testsForDevice = (scanTests.data ?? []).filter((t) =>
    t.applicable_service_types.some((st) => deviceServiceTypes.has(st)),
  );

  // Firmware tests have applicable_service_types=() - they're gated on
  // whether the device has firmware uploaded, not on service type - so they
  // can't come from testsForDevice's service-type intersection.
  const hasFirmware = Boolean(selectedDevice?.firmware_sha256);

  function testsInSection(category: ScanTestSpec["category"]): ScanTestSpec[] {
    if (category === "firmware") {
      // Gated on whether the device has firmware uploaded, not on service
      // type, so it can't come from testsForDevice's intersection.
      return (scanTests.data ?? []).filter((t) => t.category === "firmware");
    }
    return testsForDevice.filter((t) => t.category === category);
  }

  function toggleTest(testId: string, checked: boolean) {
    setSelectedTestIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(testId);
      else next.delete(testId);
      return next;
    });
  }

  function toggleSection(category: ScanTestSpec["category"], checked: boolean) {
    const ids = testsInSection(category).map((t) => t.test_id);
    setSelectedTestIds((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (checked) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  }

  async function handleRunSelected() {
    setLaunchErrors({});
    setLaunching(true);
    const testIds = Array.from(selectedTestIds);

    try {
      // One real Assessment groups this whole batch under one id with an
      // aggregate status - "Select device -> create assessment -> run
      // collectors -> ..." per the brief's own workflow description. Tests
      // that don't apply are reported in `errors` without failing the batch.
      const result = await api.createAssessment(deviceId, testIds);
      setAssessmentId(result.id);
      setAssessmentStatus(result.status);

      const newJobs: RunningJob[] = result.jobs.map((job) => ({
        jobId: job.id,
        testId: job.test_id,
        testLabel: testsForDevice.find((t) => t.test_id === job.test_id)?.label ?? job.test_id,
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

  async function handleRecompute() {
    setRecomputing(true);
    try {
      const result = await api.recomputeVerdicts();
      const message =
        result.created === 0
          ? "No new verdicts (evidence didn't map to a new control result)."
          : `${result.created} new verdict${result.created === 1 ? "" : "s"} generated — check the Verdicts page.`;
      showToast(message, "success");
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : "Could not recompute verdicts.", "error");
    } finally {
      setRecomputing(false);
    }
  }

  const pageError = devices.error ?? scanTests.error;

  return (
    <Shell title="Run Scan" subtitle="Trigger real, whitelisted tests against a live device from here">
      {pageError ? (
        <ErrorState message={pageError} />
      ) : (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Device</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs text-[var(--color-text-muted)]" htmlFor="device-select">
                  Device
                </label>
                <select
                  id="device-select"
                  value={deviceId}
                  onChange={(e) => {
                    setDeviceId(e.target.value);
                    setSelectedTestIds(new Set());
                    setLaunchErrors({});
                  }}
                  className="max-w-xs rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)]"
                >
                  <option value="">Select a device…</option>
                  {registeredDevices.map((d) => (
                    <option key={d.device_id} value={d.device_id}>
                      {d.device_id}
                    </option>
                  ))}
                </select>
              </div>
              <p className="mt-3 text-xs text-[var(--color-text-muted)]">
                Looking to find devices on the network rather than test one you've already
                registered?{" "}
                <Link to="/devices" className="text-[var(--color-brand)] underline">
                  Discover devices
                </Link>{" "}
                on the Devices page — no device selection needed there.
              </p>
            </CardContent>
          </Card>

          {deviceId &&
            SECTIONS.map(({ category, title }) => {
              const tests = testsInSection(category);
              if (tests.length === 0) return null;
              const allChecked = tests.every((t) => selectedTestIds.has(t.test_id));
              return (
                <Card key={category}>
                  <CardHeader>
                    <CardTitle>{title}</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 pt-2">
                    <label className="mb-1 flex cursor-pointer items-center gap-2 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                      <input
                        type="checkbox"
                        checked={allChecked}
                        onChange={(e) => toggleSection(category, e.target.checked)}
                        className="h-4 w-4 accent-[var(--color-brand)]"
                      />
                      Select all
                    </label>
                    {tests.map((t) => (
                      <TestCheckbox
                        key={t.test_id}
                        test={t}
                        checked={selectedTestIds.has(t.test_id)}
                        onChange={(checked) => toggleTest(t.test_id, checked)}
                      />
                    ))}
                  </CardContent>
                </Card>
              );
            })}

          {deviceId &&
            testsInSection("firmware").length > 0 &&
            (() => {
              const tests = testsInSection("firmware");
              const allChecked = hasFirmware && tests.every((t) => selectedTestIds.has(t.test_id));
              return (
                <Card>
                  <CardHeader>
                    <CardTitle>3. Simulated Firmware Analysis</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 pt-2">
                    {hasFirmware ? (
                      <label className="mb-1 flex cursor-pointer items-center gap-2 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                        <input
                          type="checkbox"
                          checked={allChecked}
                          onChange={(e) => toggleSection("firmware", e.target.checked)}
                          className="h-4 w-4 accent-[var(--color-brand)]"
                        />
                        Select all
                      </label>
                    ) : (
                      <p className="mb-2 text-xs text-[var(--color-text-muted)]">
                        No firmware uploaded for this device yet.{" "}
                        <Link to={`/devices/${deviceId}`} className="text-[var(--color-brand)] underline">
                          Upload firmware
                        </Link>{" "}
                        on the device detail page to enable these tests.
                      </p>
                    )}
                    {tests.map((t) =>
                      hasFirmware ? (
                        <TestCheckbox
                          key={t.test_id}
                          test={t}
                          checked={selectedTestIds.has(t.test_id)}
                          onChange={(checked) => toggleTest(t.test_id, checked)}
                        />
                      ) : (
                        <label
                          key={t.test_id}
                          className="flex cursor-not-allowed items-center gap-2 rounded-md px-2 py-1.5 text-sm text-[var(--color-text-muted)]"
                        >
                          <input type="checkbox" disabled className="h-4 w-4" />
                          {t.label}
                        </label>
                      ),
                    )}
                  </CardContent>
                </Card>
              );
            })()}

          {deviceId &&
            (testsInSection("web-and-auth").length > 0 ||
              testsInSection("network-and-protocol").length > 0 ||
              (hasFirmware && testsInSection("firmware").length > 0)) && (
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
                  A scan is already running — wait for it to finish before starting another.
                </p>
              )}
              {Object.entries(launchErrors).map(([testId, message]) => (
                <p key={testId} className="text-sm text-[var(--color-critical)]">
                  {testId === "_assessment" ? message : `${testId}: ${message}`}
                </p>
              ))}
            </div>
          )}

          {jobs.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-medium tracking-wide text-[var(--color-text-secondary)] uppercase">
                  Results
                </h2>
                <button
                  type="button"
                  onClick={handleRecompute}
                  disabled={recomputing}
                  className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
                >
                  {recomputing ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                  Recompute verdicts
                </button>
              </div>

              {assessmentId && assessmentStatus && (
                <div className="flex flex-wrap items-center gap-3 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
                  {IN_FLIGHT_ASSESSMENT_STATUSES.has(assessmentStatus) && (
                    <Loader2 className="h-4 w-4 animate-spin text-[var(--color-low)]" />
                  )}
                  <span className="font-mono text-xs text-[var(--color-text-muted)]">{assessmentId}</span>
                  <span className={cn("text-sm font-medium", ASSESSMENT_STATUS_COPY[assessmentStatus].tone)}>
                    {ASSESSMENT_STATUS_COPY[assessmentStatus].label}
                  </span>
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
                <ScanJobCard
                  key={j.jobId}
                  jobId={j.jobId}
                  testLabel={j.testLabel}
                  onStatusChange={handleJobStatusChange}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </Shell>
  );
}
