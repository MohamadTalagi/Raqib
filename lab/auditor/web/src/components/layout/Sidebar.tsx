import { NavLink } from "react-router-dom";
import {
  Home as HomeIcon,
  LayoutGrid,
  HardDrive,
  FileSearch,
  Gavel,
  Terminal,
  ShieldCheck,
  ClipboardCheck,
  ListChecks,
  Building2,
  Network,
  Flame,
  Radar,
  Fingerprint,
  BadgeCheck,
  Bug,
  Wrench,
  FileBarChart,
  KeyRound,
  Settings,
} from "lucide-react";
import raqibMark from "@/assets/raqib-mark.png";
import { cn } from "@/lib/utils";
import { PIPELINE_ROUTE_PHASE_GROUP, PHASE_GROUP_VAR } from "@/lib/phaseTheme";

interface NavGroup {
  label: string;
  items: Array<{ to: string; label: string; icon: typeof LayoutGrid; end: boolean }>;
}

// Order matches lib/pipeline.ts's PIPELINE_PHASES exactly for the "Pipeline"
// group - the sidebar literally reads top to bottom as the guided flow
// (Devices -> Fingerprinting -> SA-IOT Compliance -> NCA Compliance ->
// Vulnerability Intelligence -> Risk Assessment -> Remediation). Discovery
// sits above Devices since it's the pre-registration, fleet-wide activity
// that feeds into Devices, but has no per-device pipeline status of its own.
const NAV_GROUPS: NavGroup[] = [
  {
    label: "Start",
    items: [
      { to: "/", label: "Home", icon: HomeIcon, end: true },
      { to: "/overview", label: "Overview", icon: LayoutGrid, end: true },
    ],
  },
  {
    label: "Settings",
    items: [{ to: "/settings/network-scope", label: "Network Scope", icon: Settings, end: false }],
  },
  {
    label: "Pipeline",
    items: [
      { to: "/discovery", label: "Discovery", icon: Radar, end: false },
      { to: "/devices", label: "Devices", icon: HardDrive, end: false },
      { to: "/fingerprinting", label: "Fingerprinting", icon: Fingerprint, end: false },
      { to: "/sa-iot-compliance", label: "SA-IOT Compliance", icon: BadgeCheck, end: false },
      { to: "/nca-compliance", label: "NCA Compliance", icon: ClipboardCheck, end: true },
      { to: "/vulnerability-intelligence", label: "Vulnerability Intelligence", icon: Bug, end: false },
      { to: "/risk", label: "Risk Assessment", icon: Flame, end: false },
      { to: "/pqc-readiness", label: "Post-Quantum Readiness", icon: KeyRound, end: false },
      { to: "/remediation", label: "Remediation", icon: Wrench, end: false },
      { to: "/executive-summary", label: "Executive Summary", icon: FileBarChart, end: false },
    ],
  },
  {
    label: "Records",
    items: [
      { to: "/evidence", label: "Evidence", icon: FileSearch, end: false },
      { to: "/verdicts", label: "Verdicts", icon: Gavel, end: false },
      { to: "/controls", label: "Controls", icon: ShieldCheck, end: false },
      { to: "/nca-compliance/controls", label: "NCA Controls", icon: ListChecks, end: false },
      { to: "/network-map", label: "Network Map", icon: Network, end: false },
      // Device Console lives here rather than in Pipeline: it is not a
      // pipeline stage, and that group is deliberately ordered top-to-bottom
      // as the 10-stage sequence. This group already holds Network Map, which
      // is likewise a live view rather than a stored record, so "Records"
      // reads as "inspect things" in practice.
      { to: "/console", label: "Device Console", icon: Terminal, end: false },
    ],
  },
  {
    label: "Organization-wide",
    items: [
      { to: "/nca-compliance/organization", label: "Organizational Compliance", icon: Building2, end: true },
    ],
  },
];

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps) {
  return (
    <>
      {open ? (
        <div
          className="fixed inset-0 z-20 bg-black/60 lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      ) : null}

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] transition-transform duration-200 lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-16 items-center gap-2.5 px-5">
          {/* The mark sits on a light chip rather than directly on the sidebar:
              its shield is navy, which all but disappears against the dark
              theme's near-black surface. The ring keeps the chip readable in
              the light theme too, where white-on-white would otherwise vanish. */}
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-white p-1 ring-1 ring-inset ring-[var(--color-border)]">
            <img
              src={raqibMark}
              alt="Raqib"
              className="h-full w-full object-contain"
            />
          </div>
          <div className="leading-tight">
            <p className="text-sm font-semibold tracking-tight text-[var(--color-text)]">Raqib</p>
            <p className="font-mono text-[10px] tracking-wider text-[var(--color-text-muted)] uppercase">
              NCA Compliance
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              <p className="px-3 pb-1.5 text-[10px] font-semibold tracking-wider text-[var(--color-text-muted)] uppercase">
                {group.label}
              </p>
              <div className="space-y-1">
                {group.items.map(({ to, label, icon: Icon, end }) => {
                  // Pipeline items only - see lib/phaseTheme.ts. undefined
                  // for every non-pipeline nav item, which keeps the plain
                  // brand-colored active indicator they've always had.
                  const phaseGroup = PIPELINE_ROUTE_PHASE_GROUP[to];
                  const accentVar = phaseGroup ? PHASE_GROUP_VAR[phaseGroup] : "var(--color-brand)";
                  return (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      onClick={onClose}
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
                              "absolute left-0 h-5 w-0.5 -translate-x-3 rounded-full transition-opacity",
                              isActive ? "opacity-100" : "opacity-0",
                            )}
                            style={{ backgroundColor: accentVar }}
                          />
                          {phaseGroup ? (
                            <span
                              className="h-1.5 w-1.5 shrink-0 rounded-full"
                              style={{ backgroundColor: accentVar }}
                              aria-hidden="true"
                            />
                          ) : null}
                          <Icon className="h-4 w-4" strokeWidth={2} />
                          {label}
                        </>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            </div>
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
    </>
  );
}
