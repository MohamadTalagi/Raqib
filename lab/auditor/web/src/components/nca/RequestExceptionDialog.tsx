import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import type { CreateNCAExceptionPayload, Device, NCAControl, NCAException } from "@/lib/types";

interface RequestExceptionDialogProps {
  open: boolean;
  control: NCAControl;
  devices: Device[];
  initialDeviceId?: string | null;
  onSaved: (exception: NCAException) => void;
  onCancel: () => void;
}

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

/** Every exception requires an expiry (compliance_exceptions.expires_at is
 * NOT NULL server-side) - there is deliberately no "permanent exception"
 * option, matching the brief's "no exceptions, pun intended" rule. */
export function RequestExceptionDialog({
  open,
  control,
  devices,
  initialDeviceId,
  onSaved,
  onCancel,
}: RequestExceptionDialogProps) {
  const isDeviceScoped = control.scope_type === "device";

  const [deviceId, setDeviceId] = useState("");
  const [reason, setReason] = useState("");
  const [compensatingControl, setCompensatingControl] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [requestedBy, setRequestedBy] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setDeviceId(initialDeviceId ?? "");
    setReason("");
    setCompensatingControl("");
    setExpiresAt("");
    setRequestedBy("");
    setError(null);

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onCancel();
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, control.id]);

  if (!open) return null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (isDeviceScoped && !deviceId) {
      setError("Choose a device - this control is device-scoped.");
      return;
    }

    setSubmitting(true);
    const payload: CreateNCAExceptionPayload = {
      control_id: control.id,
      device_id: isDeviceScoped ? deviceId : null,
      organizational_scope_id: isDeviceScoped ? null : "default",
      reason,
      compensating_control: compensatingControl.trim() || null,
      requested_by: requestedBy,
      expires_at: expiresAt,
    };
    try {
      const saved = await api.createNcaException(payload);
      onSaved(saved);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not request the exception.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onCancel}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="request-exception-title"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-6 shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id="request-exception-title" className="text-sm font-semibold text-[var(--color-text)]">
          Request exception
        </h2>
        <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">
          {control.guideline_id} &middot; {control.domain_name}
        </p>

        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          {isDeviceScoped ? (
            <div>
              <label className={LABEL_CLASS} htmlFor="exception-device">
                Device
              </label>
              <select
                id="exception-device"
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
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">
              Organization-wide control — recorded against the default organizational scope.
            </p>
          )}

          <div>
            <label className={LABEL_CLASS} htmlFor="exception-reason">
              Reason
            </label>
            <textarea
              id="exception-reason"
              aria-label="Reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              className={INPUT_CLASS}
              required
            />
          </div>

          <div>
            <label className={LABEL_CLASS} htmlFor="exception-compensating-control">
              Compensating control (optional)
            </label>
            <textarea
              id="exception-compensating-control"
              aria-label="Compensating control"
              value={compensatingControl}
              onChange={(e) => setCompensatingControl(e.target.value)}
              rows={2}
              className={INPUT_CLASS}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL_CLASS} htmlFor="exception-expires-at">
                Expires on
              </label>
              <input
                id="exception-expires-at"
                aria-label="Expires on"
                type="date"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className={INPUT_CLASS}
                required
              />
            </div>
            <div>
              <label className={LABEL_CLASS} htmlFor="exception-requested-by">
                Your name (requester)
              </label>
              <input
                id="exception-requested-by"
                aria-label="Your name"
                value={requestedBy}
                onChange={(e) => setRequestedBy(e.target.value)}
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
              {submitting ? "Saving…" : "Request exception"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
