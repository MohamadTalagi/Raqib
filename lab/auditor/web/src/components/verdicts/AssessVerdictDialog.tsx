import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import type { ControlRecord, Device, Severity, VerdictRecord } from "@/lib/types";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

interface AssessVerdictDialogProps {
  open: boolean;
  devices: Device[];
  controls: ControlRecord[];
  onCancel: () => void;
  onAssessed: (verdict: VerdictRecord) => void;
}

/**
 * Assess a fresh verdict for one (device, control) pair from the Verdicts
 * page. The pass/fail status is computed server-side from the device's real
 * evidence (POST .../assess); the auditor picks the device, the control, and
 * optionally the severity. A backend 400 (e.g. no evidence yet, or a
 * manual-only control) is shown inline so the reason is visible.
 */
export function AssessVerdictDialog({ open, devices, controls, onCancel, onAssessed }: AssessVerdictDialogProps) {
  const [deviceId, setDeviceId] = useState("");
  const [controlId, setControlId] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setDeviceId("");
    setControlId("");
    setSeverity("");
    setError(null);
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onCancel();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    if (!deviceId) return setError("Choose a device.");
    if (!controlId) return setError("Choose a control.");

    setSubmitting(true);
    try {
      const verdict = await api.assessControlVerdict(deviceId, controlId, severity || undefined);
      onAssessed(verdict);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not assess this control.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onCancel}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="assess-verdict-title"
        className="w-full max-w-md rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="assess-verdict-title" className="text-sm font-semibold text-[var(--color-text)]">
          Assess a verdict
        </h2>
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          The pass/fail status is computed from the device's collected evidence. Severity is your call.
        </p>

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label className={LABEL_CLASS} htmlFor="assess-device">
              Device
            </label>
            <select
              id="assess-device"
              aria-label="Device"
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              className={INPUT_CLASS}
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

          <div>
            <label className={LABEL_CLASS} htmlFor="assess-control">
              Control
            </label>
            <select
              id="assess-control"
              aria-label="Control"
              value={controlId}
              onChange={(e) => setControlId(e.target.value)}
              className={INPUT_CLASS}
            >
              <option value="">Select a control…</option>
              {controls.map((c) => (
                <option key={c.control_id} value={c.control_id}>
                  {c.control_id} — {c.title}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className={LABEL_CLASS} htmlFor="assess-severity">
              Severity
            </label>
            <select
              id="assess-severity"
              aria-label="Severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity | "")}
              className={INPUT_CLASS}
            >
              <option value="">From control (default)</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          {error && <p className="text-sm text-[var(--color-critical)]">{error}</p>}

          <div className="flex justify-end gap-2 border-t border-[var(--color-border)] pt-4">
            <button
              type="button"
              onClick={onCancel}
              disabled={submitting}
              className="inline-flex cursor-pointer items-center rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:cursor-not-allowed disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex cursor-pointer items-center rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {submitting ? "Assessing…" : "Assess verdict"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
