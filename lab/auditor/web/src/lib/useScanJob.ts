import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ScanJob } from "@/lib/types";

const POLL_INTERVAL_MS = 1200;
export const SCAN_JOB_IN_FLIGHT_STATUSES = new Set(["pending", "running"]);

/**
 * Polls a single scan job until it leaves pending/running - shared by every
 * page that runs a real scan test (Run Scan, and the new cohort-based
 * pipeline pages), so there's exactly one polling implementation.
 */
export function useScanJob(jobId: number | null): [ScanJob | null, (job: ScanJob) => void] {
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
        if (SCAN_JOB_IN_FLIGHT_STATUSES.has(latest.status)) {
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
