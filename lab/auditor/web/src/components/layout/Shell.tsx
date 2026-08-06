import { useState } from "react";
import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import type { PipelinePhaseGroup } from "@/lib/phaseTheme";

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

  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="lg:pl-60">
        <TopBar title={title} subtitle={subtitle} phase={phase} onMenuClick={() => setSidebarOpen(true)} />
        <main className="mx-auto max-w-[1400px] px-4 py-8 sm:px-8">{children}</main>
      </div>
    </div>
  );
}
