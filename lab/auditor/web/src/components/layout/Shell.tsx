import { useState } from "react";
import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

interface ShellProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

export function Shell({ title, subtitle, children }: ShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="lg:pl-60">
        <TopBar title={title} subtitle={subtitle} onMenuClick={() => setSidebarOpen(true)} />
        <main className="mx-auto max-w-[1400px] px-4 py-8 sm:px-8">{children}</main>
      </div>
    </div>
  );
}
