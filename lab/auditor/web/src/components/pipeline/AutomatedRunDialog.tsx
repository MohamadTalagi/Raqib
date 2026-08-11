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
            <li>Runs every applicable Fingerprinting and NCA compliance collector on every device.</li>
            <li>Auto-submits each test&apos;s deterministic suggested finding - no human review.</li>
            <li>Recomputes SA-IOT verdicts.</li>
            <li>
              Runs package-level Vulnerability Intelligence on any device that already has firmware uploaded, and
              device-level CVE lookup (real NVD data matched on vendor/model - no firmware needed) on any device
              whose vendor and model are known.
            </li>
            <li>
              Checks Post-Quantum Readiness (TLS key exchange, certificate signature, firmware crypto library) -
              informational only, never affects risk scoring or compliance verdicts.
            </li>
            <li>
              Auto-records failing and review-required NCA compliance assessments from matching evidence, marked{" "}
              <span className="font-mono text-[var(--color-medium)]">auto-recorded</span> - not a human sign-off. A
              suggested <span className="font-mono">pass</span> is never auto-recorded: it waits for you to sign it in
              NCA Compliance.
            </li>
          </ol>
          <p className="text-xs text-[var(--color-text-muted)]">
            Never automated: the ~60 organizational/mobile/supplier/cloud NCA guidelines (they need a human&apos;s
            checklist answers), package-level Vulnerability Intelligence for a device with no firmware uploaded yet,
            device-level CVE lookup for a device whose vendor/model are still unknown, and AI Remediation (always a
            manual, on-demand step) - none of these is invented or skipped silently.
          </p>
          {error ? <p className="text-[var(--color-critical)]">{error}</p> : null}
        </div>
      }
    />
  );
}
