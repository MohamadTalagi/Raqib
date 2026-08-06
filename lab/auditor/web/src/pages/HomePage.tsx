import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Fingerprint, HardDrive, Zap } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { AutomatedRunDialog } from "@/components/pipeline/AutomatedRunDialog";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { PHASE_GROUP_VAR } from "@/lib/phaseTheme";
import { cn } from "@/lib/utils";

interface HomeActionCardProps {
  icon: typeof Zap;
  title: string;
  description: string;
  accentVar: string;
  onClick: () => void;
}

function HomeActionCard({ icon: Icon, title, description, accentVar, onClick }: HomeActionCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "group flex flex-col items-start gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-left transition-colors",
        "hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-hover)]",
      )}
      style={{ borderTopWidth: "3px", borderTopColor: accentVar }}
    >
      <div
        className="flex h-10 w-10 items-center justify-center rounded-lg"
        style={{ backgroundColor: `color-mix(in oklab, ${accentVar} 16%, transparent)`, color: accentVar }}
      >
        <Icon className="h-5 w-5" strokeWidth={2} />
      </div>
      <div>
        <p className="text-base font-semibold text-[var(--color-text)]">{title}</p>
        <p className="mt-1 text-sm text-[var(--color-text-muted)]">{description}</p>
      </div>
    </button>
  );
}

/**
 * The landing page (route "/") - a simple, elegant entry point to get an
 * auditor going, distinct from the data-rich Overview dashboard (now at
 * /overview). Deliberately minimal: three primary actions and one thin
 * line of fleet stats, nothing more - Overview already owns the full
 * breakdown (gauges, charts, priority lists).
 */
export function HomePage() {
  const navigate = useNavigate();
  const [showAutomatedRunDialog, setShowAutomatedRunDialog] = useState(false);
  const summary = useFetch(api.summary, []);
  const devices = useFetch(api.devices, []);

  return (
    <Shell title="Raqib" subtitle="AI-assisted IoT security compliance & risk assessment">
      <AutomatedRunDialog
        open={showAutomatedRunDialog}
        onCancel={() => setShowAutomatedRunDialog(false)}
        onStarted={(run) => {
          setShowAutomatedRunDialog(false);
          navigate(`/automated-run/${run.id}`);
        }}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <HomeActionCard
          icon={Fingerprint}
          title="Start a manual run"
          description="Pick devices and choose which tests to run yourself, step by step."
          accentVar={PHASE_GROUP_VAR.discovery}
          onClick={() => navigate("/fingerprinting")}
        />
        <HomeActionCard
          icon={Zap}
          title="Start an automated run"
          description="Discovery through NCA sign-off, end to end, with one confirmation."
          accentVar={PHASE_GROUP_VAR.solution}
          onClick={() => setShowAutomatedRunDialog(true)}
        />
        <HomeActionCard
          icon={HardDrive}
          title="View devices"
          description="Browse the registered fleet, or register a device by hand."
          accentVar={PHASE_GROUP_VAR.compliance}
          onClick={() => navigate("/devices")}
        />
      </div>

      {summary.data && devices.data ? (
        <p className="mt-6 text-center text-xs text-[var(--color-text-muted)]">
          {devices.data.length} device{devices.data.length === 1 ? "" : "s"} monitored ·{" "}
          {summary.data.total_evidence} evidence collected · {summary.data.total_verdicts} verdicts issued
        </p>
      ) : null}
    </Shell>
  );
}
