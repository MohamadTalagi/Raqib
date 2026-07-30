import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";

/**
 * Unlike the rest of this app's evidence (always current as of whenever it
 * was recorded), CVE/KEV data is snapshot-based - it's only as fresh as the
 * last `grype db update` the worker ran (see job_runner.py's
 * maybe_refresh_grype_db). Shown next to any CVE/KEV display so an auditor
 * knows how stale it might be, sourced from GET /vuln-intel/status - itself
 * reported "as of the most recent scan that used it," not a live query
 * (the API has no access to the worker's local Grype cache).
 */
export function VulnFreshnessNote() {
  const status = useFetch(api.vulnIntelStatus, []);

  if (status.loading || !status.data) {
    return null;
  }
  if (!status.data.known) {
    return (
      <p className="text-xs text-[var(--color-text-muted)]">
        Vulnerability-database freshness unknown - no firmware scan has recorded it yet.
      </p>
    );
  }

  return (
    <p className="text-xs text-[var(--color-text-muted)]">
      Vulnerability data as of the local database built{" "}
      <span className="font-mono">{status.data.vuln_db_built_at}</span>, observed in a scan at{" "}
      <span className="font-mono">{status.data.observed_at}</span>.
    </p>
  );
}
