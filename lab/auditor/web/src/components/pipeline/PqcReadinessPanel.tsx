import { PqcCriterionBadge } from "@/components/ui/severity-badge";
import type { DevicePqcReadiness, PqcCriterionStatus } from "@/lib/types";

interface CriterionRowProps {
  label: string;
  status: PqcCriterionStatus;
  detail?: string | null;
  tip?: string;
}

function CriterionRow({ label, status, detail, tip }: CriterionRowProps) {
  return (
    <div className="space-y-1 border-b border-[var(--color-border)] pb-3 last:border-b-0 last:pb-0">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-[var(--color-text)]">{label}</p>
        <PqcCriterionBadge status={status} />
      </div>
      {detail && <p className="font-mono text-xs text-[var(--color-text-muted)]">{detail}</p>}
      {tip && <p className="text-xs text-[var(--color-text-secondary)]">{tip}</p>}
    </div>
  );
}

interface PqcReadinessPanelProps {
  readiness: DevicePqcReadiness;
}

/**
 * The live 3-criterion Post-Quantum Readiness breakdown for one device -
 * purely informational, sourced from pqc_routes.py's already-computed
 * evidence rollup. A "fail" criterion's fixed static tip (never
 * AI-generated, matching this project's determinism rule) renders inline
 * right under that criterion rather than in a separate callout, so the
 * remediation guidance stays attached to the specific thing that failed.
 */
export function PqcReadinessPanel({ readiness }: PqcReadinessPanelProps) {
  const tls = readiness.tls_key_exchange;
  const signature = readiness.certificate_signature;
  const firmware = readiness.firmware_crypto;

  return (
    <div className="space-y-3">
      {tls && (
        <CriterionRow
          label="TLS key exchange (KEM)"
          status={tls.status}
          detail={tls.negotiated_group ? `Negotiated group: ${tls.negotiated_group}` : undefined}
          tip={tls.tip}
        />
      )}
      {signature && (
        <CriterionRow
          label="Certificate signature algorithm"
          status={signature.status}
          detail={signature.signature_algorithm ?? undefined}
          tip={signature.tip}
        />
      )}
      {firmware && (
        <CriterionRow
          label="Firmware crypto library currency"
          status={firmware.status}
          detail={
            firmware.packages.length > 0
              ? firmware.packages.map((p) => `${p.name} ${p.version}`).join(", ")
              : undefined
          }
          tip={firmware.tip}
        />
      )}
    </div>
  );
}
