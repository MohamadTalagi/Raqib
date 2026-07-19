import { NavLink } from "react-router-dom";
import { ShieldHalf, LayoutGrid, HardDrive, FileSearch, Gavel, PlayCircle, Terminal, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: LayoutGrid, end: true },
  { to: "/devices", label: "Devices", icon: HardDrive, end: false },
  { to: "/evidence", label: "Evidence", icon: FileSearch, end: false },
  { to: "/verdicts", label: "Verdicts", icon: Gavel, end: false },
  { to: "/run-scan", label: "Run Scan", icon: PlayCircle, end: false },
  { to: "/console", label: "Device Console", icon: Terminal, end: false },
  { to: "/controls", label: "Controls", icon: ShieldCheck, end: false },
];

export function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)]">
      <div className="flex h-16 items-center gap-2.5 px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-[var(--color-brand)]">
          <ShieldHalf className="h-4.5 w-4.5 text-[var(--color-brand-foreground)]" strokeWidth={2.25} />
        </div>
        <div className="leading-tight">
          <p className="text-sm font-semibold tracking-tight text-[var(--color-text)]">IoTGuard</p>
          <p className="font-mono text-[10px] tracking-wider text-[var(--color-text-muted)] uppercase">
            NCA Compliance
          </p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-[var(--color-surface-hover)] text-[var(--color-text)]"
                  : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]",
              )
            }
          >
            {({ isActive }) => (
              <>
                <span
                  className={cn(
                    "absolute left-0 h-5 w-0.5 -translate-x-3 rounded-full bg-[var(--color-brand)] transition-opacity",
                    isActive ? "opacity-100" : "opacity-0",
                  )}
                />
                <Icon className="h-4 w-4" strokeWidth={2} />
                {label}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-[var(--color-border)] px-5 py-4">
        <p className="font-mono text-[10px] leading-relaxed text-[var(--color-text-muted)]">
          CGIoT-1:2024
          <br />
          Saudi NCA IoT Guidelines
        </p>
      </div>
    </aside>
  );
}
