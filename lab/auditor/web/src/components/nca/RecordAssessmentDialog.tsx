import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import type {
  CreateNCAAssessmentPayload,
  Device,
  NCAApplicability,
  NCAAssessment,
  NCAAssessmentType,
  NCAControl,
  NCADeviceSuggestion,
  NCAStatus,
  Severity,
} from "@/lib/types";

const STATUS_OPTIONS: NCAStatus[] = ["pass", "partial", "fail", "not_tested", "review_required"];
const SEVERITY_OPTIONS: Severity[] = ["low", "medium", "high", "critical"];
const TEST_METHOD_OPTIONS: NCAAssessmentType[] = ["manual", "automated", "hybrid"];

interface RecordAssessmentDialogProps {
  open: boolean;
  control: NCAControl;
  devices: Device[];
  /** Pre-selects (and locks, if only one is possible) the device when the
   * control is device-scoped and a device context is already known, e.g.
   * navigating here from a device's own Compliance tab. */
  initialDeviceId?: string | null;
  /** When set, this is a retest of an existing assessment rather than a
   * brand-new one - fields are pre-filled from it and the submit goes
   * through POST /nca/assessments/{id}/retest instead of a plain create. */
  existingAssessment?: NCAAssessment | null;
  /** Auto-verdict hint from mapped automated evidence for this (device,
   * control). When present on a brand-new assessment, the status, evidence
   * ids, and test method are pre-filled from it - the auditor still confirms
   * or overrides before saving. Ignored on a retest (that reuses the prior
   * assessment's own values). */
  suggestion?: NCADeviceSuggestion | null;
  onSaved: (assessment: NCAAssessment) => void;
  onCancel: () => void;
}

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

/**
 * The single write path for a compliance assessment - used identically for
 * a brand-new assessment and a retest, and identically whether reached from
 * the control detail page, a device's Compliance tab, or the organizational
 * compliance page. Device-scope vs organization-scope is driven entirely by
 * control.scope_type, not left to the user to pick wrong.
 */
export function RecordAssessmentDialog({
  open,
  control,
  devices,
  initialDeviceId,
  existingAssessment,
  suggestion,
  onSaved,
  onCancel,
}: RecordAssessmentDialogProps) {
  const isDeviceScoped = control.scope_type === "device";
  const isRetest = Boolean(existingAssessment);
  // A suggestion only pre-fills a brand-new assessment; a retest reuses the
  // prior assessment's own recorded values instead.
  const activeSuggestion = isRetest ? null : suggestion ?? null;

  const [deviceId, setDeviceId] = useState("");
  const [applicability, setApplicability] = useState<NCAApplicability>("applicable");
  const [applicabilityReason, setApplicabilityReason] = useState("");
  const [status, setStatus] = useState<NCAStatus | "">("");
  const [severity, setSeverity] = useState<Severity>(control.severity);
  const [finding, setFinding] = useState("");
  const [testMethod, setTestMethod] = useState<NCAAssessmentType>("manual");
  const [testIdentifier, setTestIdentifier] = useState("");
  const [evidenceIdsText, setEvidenceIdsText] = useState("");
  const [remediation, setRemediation] = useState("");
  const [remediationDueDate, setRemediationDueDate] = useState("");
  const [assessedBy, setAssessedBy] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const source = existingAssessment;
    setDeviceId(source?.device_id ?? initialDeviceId ?? "");
    setApplicability(source?.applicability ?? "applicable");
    setApplicabilityReason(source?.applicability_reason ?? "");
    setStatus(source?.status ?? activeSuggestion?.suggested_status ?? "");
    setSeverity(source?.severity ?? control.severity);
    setFinding(source?.finding ?? "");
    setTestMethod(source?.test_method ?? (activeSuggestion ? "automated" : "manual"));
    setTestIdentifier(source?.test_identifier ?? activeSuggestion?.test_ids[0] ?? "");
    setEvidenceIdsText((source?.evidence_ids ?? activeSuggestion?.evidence_ids ?? []).join(", "));
    setRemediation(source?.remediation ?? "");
    setRemediationDueDate(source?.remediation_due_date ?? "");
    setAssessedBy("");
    setError(null);

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onCancel();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, control.id, existingAssessment?.id, activeSuggestion?.control_id]);

  if (!open) return null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (!status) {
      setError("Choose a status.");
      return;
    }
    if (isDeviceScoped && !deviceId) {
      setError("Choose a device - this control is device-scoped.");
      return;
    }
    if (applicability === "not_applicable" && !applicabilityReason.trim()) {
      setError("Explain why this control doesn't apply.");
      return;
    }

    setSubmitting(true);
    const payload: CreateNCAAssessmentPayload = {
      control_id: control.id,
      device_id: isDeviceScoped ? deviceId : null,
      organizational_scope_id: isDeviceScoped ? null : "default",
      applicability,
      applicability_reason: applicability === "not_applicable" ? applicabilityReason.trim() : null,
      status,
      severity,
      finding: finding.trim() || null,
      test_method: testMethod,
      test_identifier: testIdentifier.trim() || null,
      evidence_ids: evidenceIdsText
        .split(",")
        .map((id) => id.trim())
        .filter(Boolean),
      remediation: remediation.trim() || null,
      remediation_due_date: remediationDueDate || null,
      assessed_by: assessedBy,
    };

    try {
      const saved = existingAssessment
        ? await api.retestNcaAssessment(existingAssessment.id, payload)
        : await api.createNcaAssessment(payload);
      onSaved(saved);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save the assessment.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onCancel}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="record-assessment-title"
        className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-6 shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id="record-assessment-title" className="text-sm font-semibold text-[var(--color-text)]">
          {isRetest ? "Retest assessment" : "Record assessment"}
        </h2>
        <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">
          {control.guideline_id} &middot; {control.domain_name}
        </p>
        <p className="mt-2 text-xs text-[var(--color-text-secondary)]">{control.canonical_requirement}</p>

        {activeSuggestion && (
          <div className="mt-3 rounded-md border border-[var(--color-brand)]/40 bg-[color-mix(in_oklab,var(--color-brand)_8%,var(--color-surface))] p-3">
            <p className="text-xs font-semibold tracking-wide text-[var(--color-brand)] uppercase">
              Suggested from automated evidence: {activeSuggestion.suggested_status.replace("_", " ")}
            </p>
            <ul className="mt-1.5 list-disc space-y-0.5 pl-4 text-xs text-[var(--color-text-secondary)]">
              {activeSuggestion.reasons.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
            <p className="mt-1.5 text-[11px] text-[var(--color-text-muted)]">
              Pre-filled below — confirm or change the status, add your finding, then save. The
              verdict is always yours to record.
            </p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          {isDeviceScoped ? (
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-device">
                Device
              </label>
              <select
                id="assessment-device"
                aria-label="Device"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                className={INPUT_CLASS}
                disabled={isRetest}
              >
                <option value="">Select a device…</option>
                {devices
                  .filter((d) => d.registered)
                  .map((d) => (
                    <option key={d.device_id} value={d.device_id}>
                      {d.device_id}
                    </option>
                  ))}
              </select>
            </div>
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">
              Organization-wide control — recorded against the default organizational scope, not a
              specific device.
            </p>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-applicability">
                Applicability
              </label>
              <select
                id="assessment-applicability"
                aria-label="Applicability"
                value={applicability}
                onChange={(e) => setApplicability(e.target.value as NCAApplicability)}
                className={INPUT_CLASS}
              >
                <option value="applicable">Applicable</option>
                <option value="not_applicable">Not applicable</option>
              </select>
            </div>
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-status">
                Status
              </label>
              <select
                id="assessment-status"
                aria-label="Status"
                value={status}
                onChange={(e) => setStatus(e.target.value as NCAStatus)}
                className={INPUT_CLASS}
                required
              >
                <option value="">Select status…</option>
                {STATUS_OPTIONS.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {applicability === "not_applicable" && (
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-applicability-reason">
                Why doesn't this apply?
              </label>
              <textarea
                id="assessment-applicability-reason"
                aria-label="Applicability reason"
                value={applicabilityReason}
                onChange={(e) => setApplicabilityReason(e.target.value)}
                rows={2}
                className={INPUT_CLASS}
                required
              />
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-severity">
                Severity
              </label>
              <select
                id="assessment-severity"
                aria-label="Severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className={INPUT_CLASS}
              >
                {SEVERITY_OPTIONS.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-test-method">
                Test method
              </label>
              <select
                id="assessment-test-method"
                aria-label="Test method"
                value={testMethod}
                onChange={(e) => setTestMethod(e.target.value as NCAAssessmentType)}
                className={INPUT_CLASS}
              >
                {TEST_METHOD_OPTIONS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className={LABEL_CLASS} htmlFor="assessment-finding">
              Finding
            </label>
            <textarea
              id="assessment-finding"
              aria-label="Finding"
              value={finding}
              onChange={(e) => setFinding(e.target.value)}
              rows={3}
              className={INPUT_CLASS}
              placeholder="What did you observe, and how does it map to this requirement?"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-test-identifier">
                Test / reference id (optional)
              </label>
              <input
                id="assessment-test-identifier"
                aria-label="Test identifier"
                value={testIdentifier}
                onChange={(e) => setTestIdentifier(e.target.value)}
                className={`${INPUT_CLASS} font-mono`}
                placeholder="e.g. TEST-AUTH-DEFAULT-CREDS"
              />
            </div>
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-evidence-ids">
                Linked evidence ids (optional)
              </label>
              <input
                id="assessment-evidence-ids"
                aria-label="Linked evidence ids"
                value={evidenceIdsText}
                onChange={(e) => setEvidenceIdsText(e.target.value)}
                className={`${INPUT_CLASS} font-mono`}
                placeholder="EV-2026-07-08-0013, EV-..."
              />
            </div>
          </div>

          <div>
            <label className={LABEL_CLASS} htmlFor="assessment-remediation">
              Remediation (if not passing)
            </label>
            <textarea
              id="assessment-remediation"
              aria-label="Remediation"
              value={remediation}
              onChange={(e) => setRemediation(e.target.value)}
              rows={2}
              className={INPUT_CLASS}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-remediation-due">
                Remediation due date (optional)
              </label>
              <input
                id="assessment-remediation-due"
                aria-label="Remediation due date"
                type="date"
                value={remediationDueDate ?? ""}
                onChange={(e) => setRemediationDueDate(e.target.value)}
                className={INPUT_CLASS}
              />
            </div>
            <div>
              <label className={LABEL_CLASS} htmlFor="assessment-assessed-by">
                Your name (reviewer)
              </label>
              <input
                id="assessment-assessed-by"
                aria-label="Your name"
                value={assessedBy}
                onChange={(e) => setAssessedBy(e.target.value)}
                className={INPUT_CLASS}
                required
              />
            </div>
          </div>

          {error && <p className="text-sm text-[var(--color-critical)]">{error}</p>}

          <div className="flex justify-end gap-2 border-t border-[var(--color-border)] pt-4">
            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:cursor-not-allowed disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
            >
              {submitting ? "Saving…" : isRetest ? "Save retest" : "Save assessment"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
