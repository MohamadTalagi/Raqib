import { useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import type { PipelinePhaseGroup } from "@/lib/phaseTheme";
import { PHASE_GROUP_VAR } from "@/lib/phaseTheme";

interface ShellProps {
  title: string;
  subtitle?: string;
  /** Optional pipeline-phase accent, forwarded to TopBar — see
   * lib/phaseTheme.ts. Only pipeline pages pass this. */
  phase?: PipelinePhaseGroup;
  children: ReactNode;
}

export function Shell({ title, subtitle, phase, children }: ShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Re-declares --color-brand as this page's own phase color, scoped to
  // <main> only (never Sidebar/TopBar, which keep one constant app-wide
  // identity color). Every button, link, checkbox, and focus ring inside
  // the page's content already styles itself off var(--color-brand) - this
  // makes all of them pick up the page's KAUST color under KAUSTify with
  // zero changes to any individual component, via ordinary CSS custom-
  // property inheritance. Under Default, --color-phase-* equals
  // --color-brand's own literal value, so this is a no-op visually.
  const mainStyle = phase ? ({ "--color-brand": PHASE_GROUP_VAR[phase] } as CSSProperties) : undefined;

  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="lg:pl-60">
        <TopBar title={title} subtitle={subtitle} phase={phase} onMenuClick={() => setSidebarOpen(true)} />
        <main className="mx-auto max-w-[1400px] px-4 py-8 sm:px-8" style={mainStyle}>
          {children}
        </main>
      </div>
    </div>
  );
}
