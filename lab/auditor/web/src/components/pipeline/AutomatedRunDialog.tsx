import { useState } from "react";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { api, ApiError } from "@/lib/api";
import type { AutomatedRun } from "@/lib/types";

interface AutomatedRunDialogProps {
  open: boolean;
  onCancel: () => void;
  onStarted: (run: AutomatedRun) => void;
}

/**
 * The one required confirmation step before a Fully Automated Run touches
 * anything - this triggers real, fleet-wide side effects (a network scan,
 * 10-credential-pair login attempts, auto-registering devices, auto-writing
 * compliance records), the same class of action this project always
 * confirms before running rather than triggering silently.
 */
export function AutomatedRunDialog({ open, onCancel, onStarted }: AutomatedRunDialogProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setPending(true);
    setError(null);
    try {
      const run = await api.createAutomatedRun();
      onStarted(run);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start the run.");
    } finally {
      setPending(false);
    }
  }

  return (
    <ConfirmDialog
      open={open}
      title="Start a Fully Automated Run?"
      confirmLabel="Start fully automated run"
      pending={pending}
      onConfirm={handleConfirm}
      onCancel={onCancel}
      description={
        <div className="space-y-3">
          <p>This drives the whole fleet through the pipeline with zero further clicks:</p>
          <ol className="list-decimal space-y-1 pl-4">
            <li>Scans the network and registers any new devices it finds.</li>
            <li>Runs every applicable Fingerprinting and SA-IOT Compliance test on every device.</li>
            <li>Auto-submits each test&apos;s deterministic suggested finding - no human review.</li>
            <li>Recomputes SA-IOT verdicts.</li>
            <li>Runs Vulnerability Intelligence on any device that already has firmware uploaded.</li>
            <li>
              Auto-records NCA compliance assessments from matching evidence, marked{" "}
              <span className="font-mono text-[var(--color-medium)]">auto-recorded</span> - not a human sign-off.
            </li>
          </ol>
          <p className="text-xs text-[var(--color-text-muted)]">
            Never automated: the ~60 organizational/mobile/supplier/cloud NCA guidelines (they need a human&apos;s
            checklist answers) and Vulnerability Intelligence for a device with no firmware uploaded yet - neither
            is invented or skipped silently.
          </p>
          {error ? <p className="text-[var(--color-critical)]">{error}</p> : null}
        </div>
      }
    />
  );
}
