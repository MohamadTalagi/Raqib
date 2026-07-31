import { useEffect, useRef, useState } from "react";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { api, ApiError } from "@/lib/api";
import { useScanJob, SCAN_JOB_IN_FLIGHT_STATUSES } from "@/lib/useScanJob";
import { useToast } from "@/lib/useToast";
import { cn } from "@/lib/utils";
import type { ScanJob } from "@/lib/types";

const STATUS_COPY: Record<ScanJob["status"], { label: string; tone: string }> = {
  pending: { label: "Queued", tone: "text-[var(--color-text-muted)]" },
  running: { label: "Running on auditor-worker…", tone: "text-[var(--color-low)]" },
  awaiting_finding: { label: "Awaiting your finding", tone: "text-[var(--color-medium)]" },
  recorded: { label: "Recorded as evidence", tone: "text-[var(--color-pass)]" },
  failed: { label: "Failed", tone: "text-[var(--color-critical)]" },
};

export interface ScanJobCardProps {
  jobId: number;
  testLabel: string;
  onStatusChange: (jobId: number, status: ScanJob["status"]) => void;
}

/**
 * One running/completed scan job: polls until it leaves pending/running,
 * pre-fills a suggested finding/confidence once (never clobbering an
 * auditor's edit on a later poll tick), and records evidence on submit.
 * Shared by Run Scan and every cohort-based pipeline page that launches a
 * real scan test against a device.
 */
export function ScanJobCard({ jobId, testLabel, onStatusChange }: ScanJobCardProps) {
  const { showToast } = useToast();
  const [job, setJob] = useScanJob(jobId);
  const [finding, setFinding] = useState("");
  const [confidence, setConfidence] = useState<"high" | "medium" | "low">("high");
  const [confidenceReason, setConfidenceReason] = useState("");
  const [recordError, setRecordError] = useState<string | null>(null);
  const [suggestionApplied, setSuggestionApplied] = useState(false);
  const appliedSuggestionFor = useRef<number | null>(null);

  useEffect(() => {
    if (job) onStatusChange(jobId, job.status);
  }, [jobId, job, onStatusChange]);

  useEffect(() => {
    if (job?.status !== "awaiting_finding") return;
    if (appliedSuggestionFor.current === job.id) return;
    appliedSuggestionFor.current = job.id;
    if (job.suggested_finding) {
      setFinding(job.suggested_finding);
      setSuggestionApplied(true);
    }
    if (job.suggested_confidence) setConfidence(job.suggested_confidence);
  }, [job?.id, job?.status, job?.suggested_finding, job?.suggested_confidence]);

  async function handleRecord() {
    if (job === null) return;
    setRecordError(null);
    try {
      await api.recordScanJob(job.id, finding, confidence, confidenceReason.trim() || undefined);
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
          {SCAN_JOB_IN_FLIGHT_STATUSES.has(job.status) && (
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
            {suggestionApplied && (
              <p className="rounded-md bg-[var(--color-brand)]/10 px-3 py-2 text-xs text-[var(--color-text-secondary)]">
                Suggested from automated observations — review and edit before recording.
              </p>
            )}
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
            <div>
              <label
                htmlFor={`confidence-reason-input-${job.id}`}
                className="mb-1 block text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase"
              >
                Why this confidence level? (optional)
              </label>
              <input
                id={`confidence-reason-input-${job.id}`}
                type="text"
                value={confidenceReason}
                onChange={(e) => setConfidenceReason(e.target.value)}
                placeholder="Left blank, a default reason is recorded automatically"
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)]"
              />
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
