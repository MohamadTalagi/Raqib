import { useEffect, useState } from "react";
import type { ChangeEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { Skeleton } from "@/components/ui/skeleton";
import type { NCAAssessmentSuggestion, NCAChecklist, NCAComplianceEvidence, NCAControl, NCAStatus } from "@/lib/types";

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

interface ChecklistAssessmentPanelProps {
  control: NCAControl;
  /** Called with the checklist-derived suggestion (or null if this control
   * has no guided checklist yet) once the auditor is ready to move on to
   * recording the real assessment - the caller opens RecordAssessmentDialog
   * with it, exactly like a device auto-verdict suggestion. */
  onContinue: (suggestion: NCAAssessmentSuggestion | null) => void;
}

/**
 * The guided review workflow for organizational-scope guidelines no scan can
 * ever verify: answer a small fixed checklist, optionally attach the real
 * document it's about, get a live suggested status - the auditor still
 * reviews and signs in RecordAssessmentDialog before anything is recorded.
 * Falls back to a plain "Record assessment" entry point when this control
 * has no checklist authored yet (a real, expected state for most of the 62
 * organizational guidelines until policies/nca/seed_checklists.py covers
 * them - see docs/nca-compliance.md).
 */
export function ChecklistAssessmentPanel({ control, onContinue }: ChecklistAssessmentPanelProps) {
  const [checklist, setChecklist] = useState<NCAChecklist | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<string, string | boolean>>({});
  const [suggestedStatus, setSuggestedStatus] = useState<NCAStatus | null>(null);
  const [uploaderName, setUploaderName] = useState("");
  const [uploading, setUploading] = useState(false);
  const [uploadedDoc, setUploadedDoc] = useState<NCAComplianceEvidence | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setNotFound(false);
    setLoadError(null);
    setAnswers({});
    setSuggestedStatus(null);
    setUploadedDoc(null);

    api
      .ncaControlChecklist(control.id)
      .then((result) => {
        if (!cancelled) setChecklist(result);
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
        } else {
          setLoadError(err instanceof ApiError ? err.message : "Could not load the checklist.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [control.id]);

  useEffect(() => {
    if (!checklist || Object.keys(answers).length === 0) {
      setSuggestedStatus(null);
      return;
    }
    let cancelled = false;
    api
      .evaluateNcaChecklist(control.id, answers)
      .then((result) => {
        if (!cancelled) setSuggestedStatus(result.suggested_status);
      })
      .catch(() => {
        // A live-evaluate failure just means no suggestion shows yet - the
        // auditor can still answer questions and continue manually.
      });
    return () => {
      cancelled = true;
    };
  }, [checklist, answers, control.id]);

  function setAnswer(key: string, value: string | boolean) {
    setAnswers((prev) => ({ ...prev, [key]: value }));
  }

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!uploaderName.trim()) {
      setUploadError("Enter your name before attaching a document.");
      return;
    }
    setUploading(true);
    setUploadError(null);
    try {
      const doc = await api.uploadNcaComplianceDocument(file, uploaderName.trim());
      setUploadedDoc(doc);
    } catch (err) {
      setUploadError(err instanceof ApiError ? err.message : "Could not upload the document.");
    } finally {
      setUploading(false);
    }
  }

  function buildSuggestion(): NCAAssessmentSuggestion | null {
    if (!checklist) return null;
    const reasons = checklist.questions
      .filter((q) => answers[q.key] !== undefined)
      .map((q) => `${q.label}: ${String(answers[q.key])}`);
    if (uploadedDoc) {
      reasons.push(`Document evidence attached: ${uploadedDoc.original_filename ?? uploadedDoc.id}`);
    }
    return {
      control_id: control.id,
      suggested_status: suggestedStatus ?? "review_required",
      evidence_ids: uploadedDoc ? [uploadedDoc.id] : [],
      test_ids: [],
      reasons: reasons.length ? reasons : ["No checklist answers recorded yet - review manually."],
    };
  }

  if (loading) {
    return <Skeleton className="h-24" />;
  }

  if (loadError) {
    return <p className="text-xs text-[var(--color-critical)]">{loadError}</p>;
  }

  if (notFound) {
    return (
      <div className="rounded-md border border-dashed border-[var(--color-border)] p-4 text-xs text-[var(--color-text-muted)]">
        <p>No guided checklist has been authored for this control yet - record it manually below.</p>
        <button
          type="button"
          onClick={() => onContinue(null)}
          className="mt-3 inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)]"
        >
          Record assessment
        </button>
      </div>
    );
  }

  if (!checklist) return null;

  return (
    <div className="space-y-4 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <p className="text-xs font-semibold tracking-wide text-[var(--color-text)] uppercase">Guided checklist</p>

      <div className="space-y-3">
        {checklist.questions.map((question) => (
          <div key={question.key}>
            <label className={LABEL_CLASS} htmlFor={`checklist-${question.key}`}>
              {question.label}
            </label>
            {question.type === "yes_no" ? (
              <select
                id={`checklist-${question.key}`}
                aria-label={question.label}
                value={answers[question.key] === undefined ? "" : String(answers[question.key])}
                onChange={(e) => setAnswer(question.key, e.target.value === "true")}
                className={INPUT_CLASS}
              >
                <option value="">Select…</option>
                <option value="true">Yes</option>
                <option value="false">No</option>
              </select>
            ) : (
              <input
                id={`checklist-${question.key}`}
                aria-label={question.label}
                type={question.type === "date" ? "date" : "text"}
                value={(answers[question.key] as string) ?? ""}
                onChange={(e) => setAnswer(question.key, e.target.value)}
                className={INPUT_CLASS}
              />
            )}
          </div>
        ))}
      </div>

      {suggestedStatus && (
        <div className="rounded-md border border-[var(--color-brand)]/40 bg-[color-mix(in_oklab,var(--color-brand)_8%,var(--color-surface))] p-3">
          <p className="text-xs font-semibold tracking-wide text-[var(--color-brand)] uppercase">
            Suggested from your answers: {suggestedStatus.replace("_", " ")}
          </p>
          <p className="mt-1 text-[11px] text-[var(--color-text-muted)]">
            Confirm or change this in the next step - the verdict is always yours to record.
          </p>
        </div>
      )}

      <div className="border-t border-[var(--color-border)] pt-3">
        <label className={LABEL_CLASS} htmlFor="checklist-uploader-name">
          Your name (for the document evidence record)
        </label>
        <input
          id="checklist-uploader-name"
          aria-label="Your name (for the document evidence record)"
          value={uploaderName}
          onChange={(e) => setUploaderName(e.target.value)}
          className={INPUT_CLASS}
        />
        <label className={LABEL_CLASS} htmlFor="checklist-attach-document">
          Attach document evidence (optional)
        </label>
        <input
          id="checklist-attach-document"
          aria-label="Attach document evidence"
          type="file"
          onChange={handleFileChange}
          disabled={uploading}
          className={`${INPUT_CLASS} cursor-pointer`}
        />
        {uploading && <p className="mt-1 text-xs text-[var(--color-text-muted)]">Uploading…</p>}
        {uploadedDoc && (
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Attached: {uploadedDoc.original_filename ?? uploadedDoc.id}
          </p>
        )}
        {uploadError && <p className="mt-1 text-xs text-[var(--color-critical)]">{uploadError}</p>}
      </div>

      <div className="flex justify-end border-t border-[var(--color-border)] pt-3">
        <button
          type="button"
          onClick={() => onContinue(buildSuggestion())}
          className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity"
        >
          Continue to assessment
        </button>
      </div>
    </div>
  );
}
