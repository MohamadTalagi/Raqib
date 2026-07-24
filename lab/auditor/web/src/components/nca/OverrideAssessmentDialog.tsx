import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { NCAStatusBadge } from "@/components/ui/severity-badge";
import type { NCAAssessment, NCAStatus, OverrideNCAAssessmentPayload } from "@/lib/types";

const STATUS_OPTIONS: NCAStatus[] = ["pass", "partial", "fail", "not_tested", "review_required"];

interface OverrideAssessmentDialogProps {
  open: boolean;
  assessment: NCAAssessment;
  onSaved: (assessment: NCAAssessment) => void;
  onCancel: () => void;
}

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

/**
 * Auditor override of a recorded assessment result. Never edits the
 * original in place - POST /nca/assessments/{id}/override inserts a new,
 * superseding assessment (same supersede-and-audit-trail mechanism as a
 * retest) carrying a mandatory written justification and reviewer identity,
 * so the original automated/manual result and the override both stay
 * permanently visible in the control's audit trail.
 */
export function OverrideAssessmentDialog({ open, assessment, onSaved, onCancel }: OverrideAssessmentDialogProps) {
  const [status, setStatus] = useState<NCAStatus>(assessment.status);
  const [justification, setJustification] = useState("");
  const [overriddenBy, setOverriddenBy] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    setStatus(assessment.status);
    setJustification("");
    setOverriddenBy("");
    setError(null);

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onCancel();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, assessment.id]);

  if (!open) return null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (!justification.trim()) {
      setError("A written justification is required to override a result.");
      return;
    }
    if (!overriddenBy.trim()) {
      setError("Your name (auditor identity) is required.");
      return;
    }

    setSubmitting(true);
    const payload: OverrideNCAAssessmentPayload = {
      status,
      justification: justification.trim(),
      overridden_by: overriddenBy.trim(),
      original_status: assessment.status,
    };

    try {
      const saved = await api.overrideNcaAssessment(assessment.id, payload);
      onSaved(saved);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save the override.");
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
        aria-labelledby="override-assessment-title"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-6 shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id="override-assessment-title" className="text-sm font-semibold text-[var(--color-text)]">
          Override assessment result
        </h2>
        <p className="mt-2 text-xs text-[var(--color-text-secondary)]">
          This never edits the original result — it records a new, superseding assessment and keeps
          both the original and the override permanently visible in this control's audit trail.
        </p>

        <div className="mt-4 flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2">
          <span className="text-xs text-[var(--color-text-muted)]">Current result:</span>
          <NCAStatusBadge status={assessment.status} />
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label className={LABEL_CLASS} htmlFor="override-status">
              New status
            </label>
            <select
              id="override-status"
              aria-label="New status"
              value={status}
              onChange={(e) => setStatus(e.target.value as NCAStatus)}
              className={INPUT_CLASS}
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className={LABEL_CLASS} htmlFor="override-justification">
              Written justification (required)
            </label>
            <textarea
              id="override-justification"
              aria-label="Written justification"
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              rows={3}
              className={INPUT_CLASS}
              placeholder="Why is the recorded result being overridden?"
            />
          </div>

          <div>
            <label className={LABEL_CLASS} htmlFor="override-by">
              Your name (auditor)
            </label>
            <input
              id="override-by"
              aria-label="Your name"
              value={overriddenBy}
              onChange={(e) => setOverriddenBy(e.target.value)}
              className={INPUT_CLASS}
            />
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
              {submitting ? "Saving…" : "Save override"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
