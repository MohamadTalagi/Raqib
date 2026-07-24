import { Link } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { NCAReadinessBadge, NCAStatusBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";

/**
 * Organizational-scope controls - domain 1 (governance) plus the mobile,
 * supplier, and cloud guideline groups. These are manual-assessment-only by
 * design: no automated mapping ever targets them, because a network or
 * device scan cannot demonstrate policy approval, personnel training, audit
 * outcomes, or supplier/cloud contract terms (see
 * policies/nca/finding_mappings.py's own docstring for the same rule
 * enforced server-side).
 */
export function OrganizationalCompliancePage() {
  const org = useFetch(api.ncaOrganization, []);

  return (
    <Shell
      title="Organizational Compliance"
      subtitle="Governance, personnel, supplier, and cloud controls — manual assessment only"
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
            <CardContent className="flex flex-wrap items-center gap-4 pt-5">
              <NCAStatusBadge status={org.data.overall_status} />
              <span className="font-mono-tabular text-sm text-[var(--color-text-secondary)]">
                {org.data.score === null ? "not assessed" : `${org.data.score}% informational score`}
              </span>
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
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                {Object.entries(org.data.domain_summary).map(([domainName, counts]) => (
                  <div key={domainName} className="rounded-md border border-[var(--color-border)] p-4">
                    <p className="text-xs font-medium text-[var(--color-text-secondary)]">{domainName}</p>
                    <div className="mt-2 flex flex-wrap gap-3 text-xs">
                      <span className="text-[var(--color-pass)]">{counts.pass} pass</span>
                      <span className="text-[var(--color-medium)]">{counts.partial} partial</span>
                      <span className="text-[var(--color-critical)]">{counts.fail} fail</span>
                      <span className="text-[var(--color-text-muted)]">{counts.not_tested} not tested</span>
                      <span className="text-[var(--color-brand)]">{counts.review_required} review</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Controls</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              {org.data.controls.length === 0 ? (
                <EmptyState message="No organizational controls loaded." />
              ) : (
                <ul className="divide-y divide-[var(--color-border)]">
                  {org.data.controls.map(({ control, assessment }) => (
                    <li key={control.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                      <Link
                        to={`/nca-compliance/controls/${encodeURIComponent(control.id)}`}
                        className="inline-flex items-center gap-1 font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
                      >
                        {control.guideline_id}
                        <ArrowUpRight className="h-3 w-3" />
                      </Link>
                      <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                        {control.implementation_summary}
                      </span>
                      <NCAStatusBadge status={assessment?.status ?? "not_tested"} />
                      <Link
                        to={`/nca-compliance/controls/${encodeURIComponent(control.id)}`}
                        className="inline-flex shrink-0 items-center rounded-md border border-[var(--color-border)] px-2 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                      >
                        {assessment ? "Retest" : "Assess"}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </Shell>
  );
}
