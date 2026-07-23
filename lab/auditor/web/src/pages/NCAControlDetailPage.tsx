import { Link, useParams } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { SeverityBadge, NCAStatusBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";

export function NCAControlDetailPage() {
  const { controlId } = useParams<{ controlId: string }>();
  const detail = useFetch(() => api.ncaControl(controlId ?? ""), [controlId]);

  if (detail.error) {
    return (
      <Shell title="Control" subtitle={controlId}>
        <ErrorState message={detail.error} />
      </Shell>
    );
  }

  if (detail.loading || !detail.data) {
    return (
      <Shell title="Control">
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </Shell>
    );
  }

  const { control, assessments, audit_events: auditEvents } = detail.data;

  return (
    <Shell title={control.guideline_id} subtitle={control.subdomain_name}>
      <div className="space-y-6">
        <Card>
          <CardContent className="space-y-3 pt-5">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={control.severity} />
              <span className="font-mono text-xs text-[var(--color-text-secondary)]">
                {control.domain_name} &middot; {control.subdomain_name}
              </span>
              <span className="rounded-md bg-[var(--color-surface-hover)] px-2 py-0.5 font-mono text-xs text-[var(--color-text-secondary)]">
                {control.scope_type}
              </span>
              <span className="rounded-md bg-[var(--color-surface-hover)] px-2 py-0.5 font-mono text-xs text-[var(--color-text-secondary)]">
                {control.assessment_type}
              </span>
              {!control.required && (
                <span className="rounded-md bg-[var(--color-surface-hover)] px-2 py-0.5 font-mono text-xs text-[var(--color-text-muted)]">
                  optional
                </span>
              )}
            </div>
            <p className="text-sm text-[var(--color-text)]">{control.canonical_requirement}</p>
            {control.source_page && (
              <p className="text-xs text-[var(--color-text-muted)]">
                {control.framework} {control.framework_version}, page {control.source_page}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Implementation summary</CardTitle>
          </CardHeader>
          <CardContent className="pt-2 text-sm text-[var(--color-text-secondary)]">
            {control.implementation_summary}
          </CardContent>
        </Card>

        {control.remediation_guidance && (
          <Card>
            <CardHeader>
              <CardTitle>Remediation</CardTitle>
            </CardHeader>
            <CardContent className="pt-2 text-sm text-[var(--color-text-secondary)]">
              {control.remediation_guidance}
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Assessments</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {assessments.length === 0 ? (
              <EmptyState message="No assessments recorded for this control yet." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {assessments.map((assessment) => (
                  <li key={assessment.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    <NCAStatusBadge status={assessment.status} />
                    {assessment.device_id && (
                      <Link
                        to={`/devices/${assessment.device_id}`}
                        className="inline-flex items-center gap-0.5 font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
                      >
                        {assessment.device_id}
                        <ArrowUpRight className="h-3 w-3" />
                      </Link>
                    )}
                    <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                      {assessment.finding ?? <span className="text-[var(--color-text-muted)]">no finding recorded</span>}
                    </span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{assessment.assessed_by}</span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{assessment.assessed_at}</span>
                    {assessment.superseded_by && (
                      <span className="rounded-md bg-[var(--color-surface-hover)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-text-muted)]">
                        superseded
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Audit trail</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {auditEvents.length === 0 ? (
              <EmptyState message="No reassessments recorded yet." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {auditEvents.map((event) => (
                  <li key={event.id} className="py-2.5 text-sm">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="font-mono text-xs text-[var(--color-text-secondary)]">{event.event_type}</span>
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{event.actor}</span>
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{event.occurred_at}</span>
                    </div>
                    {event.reason && (
                      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{event.reason}</p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
