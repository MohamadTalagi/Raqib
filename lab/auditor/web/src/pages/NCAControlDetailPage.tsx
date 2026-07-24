import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Ban, Plus, RefreshCw, ShieldOff, Stamp } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { SeverityBadge, NCAStatusBadge } from "@/components/ui/severity-badge";
import { RecordAssessmentDialog } from "@/components/nca/RecordAssessmentDialog";
import { RequestExceptionDialog } from "@/components/nca/RequestExceptionDialog";
import { OverrideAssessmentDialog } from "@/components/nca/OverrideAssessmentDialog";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import type { NCAAssessment, NCAException } from "@/lib/types";

const EXCEPTION_STATUS_STYLE: Record<NCAException["status"], string> = {
  pending: "text-[var(--color-medium)]",
  approved: "text-[var(--color-pass)]",
  rejected: "text-[var(--color-critical)]",
  expired: "text-[var(--color-text-muted)]",
};

export function NCAControlDetailPage() {
  const { controlId } = useParams<{ controlId: string }>();
  const [searchParams] = useSearchParams();
  const deviceIdFromQuery = searchParams.get("device_id");
  const { showToast } = useToast();

  const [refreshKey, setRefreshKey] = useState(0);
  const detail = useFetch(() => api.ncaControl(controlId ?? ""), [controlId, refreshKey]);
  const devices = useFetch(api.devices, []);
  const exceptions = useFetch(
    () => api.ncaExceptions({ controlId: controlId ?? "" }),
    [controlId, refreshKey],
  );

  const [assessmentDialog, setAssessmentDialog] = useState<{
    open: boolean;
    existing: NCAAssessment | null;
  }>({ open: false, existing: null });
  const [overrideAssessment, setOverrideAssessment] = useState<NCAAssessment | null>(null);
  const [exceptionDialogOpen, setExceptionDialogOpen] = useState(false);
  const [reviewerName, setReviewerName] = useState("");
  const [exceptionActionError, setExceptionActionError] = useState<string | null>(null);
  const [exceptionActionBusy, setExceptionActionBusy] = useState<string | null>(null);

  function refresh() {
    setRefreshKey((k) => k + 1);
  }

  async function handleExceptionAction(exception: NCAException, action: "approve" | "reject") {
    if (!reviewerName.trim()) {
      setExceptionActionError("Enter your name before approving or rejecting an exception.");
      return;
    }
    setExceptionActionError(null);
    setExceptionActionBusy(exception.id);
    try {
      if (action === "approve") {
        await api.approveNcaException(exception.id, reviewerName.trim());
        showToast(`Exception ${exception.id} approved.`, "success");
      } else {
        await api.rejectNcaException(exception.id, reviewerName.trim());
        showToast(`Exception ${exception.id} rejected.`, "success");
      }
      refresh();
    } catch (err) {
      setExceptionActionError(err instanceof ApiError ? err.message : "Could not update the exception.");
    } finally {
      setExceptionActionBusy(null);
    }
  }

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
              {control.blocking && (
                <span
                  className="inline-flex items-center gap-1 rounded-md bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] px-2 py-0.5 font-mono text-xs text-[var(--color-critical)]"
                  title="A failure of this control alone forces the device's overall readiness classification to Failed, regardless of score."
                >
                  <Ban className="h-3 w-3" />
                  blocking condition
                </span>
              )}
              <div className="ml-auto flex gap-2">
                <button
                  type="button"
                  onClick={() => setExceptionDialogOpen(true)}
                  className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                >
                  <ShieldOff className="h-3.5 w-3.5" />
                  Request exception
                </button>
                <button
                  type="button"
                  onClick={() => setAssessmentDialog({ open: true, existing: null })}
                  className="inline-flex cursor-pointer items-center gap-1.5 rounded-md bg-[var(--color-brand)] px-3 py-1.5 text-xs font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Record assessment
                </button>
              </div>
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
                    {assessment.superseded_by ? (
                      <span className="rounded-md bg-[var(--color-surface-hover)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-text-muted)]">
                        superseded
                      </span>
                    ) : (
                      <span className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setAssessmentDialog({ open: true, existing: assessment })}
                          className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                        >
                          <RefreshCw className="h-3 w-3" />
                          Retest
                        </button>
                        <button
                          type="button"
                          onClick={() => setOverrideAssessment(assessment)}
                          className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
                        >
                          <Stamp className="h-3 w-3" />
                          Override
                        </button>
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
            <CardTitle>Exceptions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-2">
            {exceptions.data && exceptions.data.some((e) => e.status === "pending") && (
              <div className="flex flex-wrap items-center gap-2">
                <label htmlFor="exception-reviewer-name" className="text-xs text-[var(--color-text-muted)]">
                  Your name, to approve/reject below:
                </label>
                <input
                  id="exception-reviewer-name"
                  aria-label="Reviewer name for exception approval"
                  value={reviewerName}
                  onChange={(e) => setReviewerName(e.target.value)}
                  className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text)]"
                />
              </div>
            )}
            {exceptionActionError && <p className="text-xs text-[var(--color-critical)]">{exceptionActionError}</p>}
            {!exceptions.data || exceptions.data.length === 0 ? (
              <EmptyState message="No exceptions requested for this control." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {exceptions.data.map((exception) => (
                  <li key={exception.id} className="py-2.5 text-sm">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className={`text-xs font-semibold tracking-wide uppercase ${EXCEPTION_STATUS_STYLE[exception.status]}`}>
                        {exception.status}
                      </span>
                      {exception.device_id && (
                        <span className="font-mono text-xs text-[var(--color-text-muted)]">{exception.device_id}</span>
                      )}
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">
                        expires {exception.expires_at}
                      </span>
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">
                        requested by {exception.requested_by}
                      </span>
                      {exception.status === "pending" && (
                        <span className="ml-auto flex gap-2">
                          <button
                            type="button"
                            disabled={exceptionActionBusy === exception.id}
                            onClick={() => handleExceptionAction(exception, "approve")}
                            className="inline-flex cursor-pointer items-center rounded-md border border-[var(--color-pass)]/40 px-2 py-1 text-xs font-medium text-[var(--color-pass)] transition-colors hover:bg-[color-mix(in_oklab,var(--color-pass)_10%,transparent)] disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Approve
                          </button>
                          <button
                            type="button"
                            disabled={exceptionActionBusy === exception.id}
                            onClick={() => handleExceptionAction(exception, "reject")}
                            className="inline-flex cursor-pointer items-center rounded-md border border-[var(--color-critical)]/40 px-2 py-1 text-xs font-medium text-[var(--color-critical)] transition-colors hover:bg-[color-mix(in_oklab,var(--color-critical)_10%,transparent)] disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Reject
                          </button>
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{exception.reason}</p>
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

      <RecordAssessmentDialog
        open={assessmentDialog.open}
        control={control}
        devices={devices.data ?? []}
        initialDeviceId={deviceIdFromQuery}
        existingAssessment={assessmentDialog.existing}
        onCancel={() => setAssessmentDialog({ open: false, existing: null })}
        onSaved={(saved) => {
          setAssessmentDialog({ open: false, existing: null });
          showToast(`Assessment ${saved.id} recorded (${saved.status}).`, "success");
          refresh();
        }}
      />

      <RequestExceptionDialog
        open={exceptionDialogOpen}
        control={control}
        devices={devices.data ?? []}
        initialDeviceId={deviceIdFromQuery}
        onCancel={() => setExceptionDialogOpen(false)}
        onSaved={(saved) => {
          setExceptionDialogOpen(false);
          showToast(`Exception ${saved.id} requested — pending approval.`, "success");
          refresh();
        }}
      />

      {overrideAssessment && (
        <OverrideAssessmentDialog
          open={Boolean(overrideAssessment)}
          assessment={overrideAssessment}
          onCancel={() => setOverrideAssessment(null)}
          onSaved={(saved) => {
            setOverrideAssessment(null);
            showToast(`Assessment overridden to ${saved.status}.`, "success");
            refresh();
          }}
        />
      )}
    </Shell>
  );
}
