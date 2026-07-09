import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

interface ShellProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

export function Shell({ title, subtitle, children }: ShellProps) {
  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Sidebar />
      <div className="pl-60">
        <TopBar title={title} subtitle={subtitle} />
        <main className="mx-auto max-w-[1400px] px-8 py-8">{children}</main>
      </div>
    </div>
  );
}
