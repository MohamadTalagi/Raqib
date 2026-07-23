import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export interface TabItem {
  value: string;
  label: string;
  count?: number;
}

interface TabsProps {
  items: TabItem[];
  value: string;
  onChange: (value: string) => void;
  className?: string;
}

/**
 * A minimal tab-group primitive - didn't exist before this module needed it
 * twice (the device-status grouping tabs on NCACompliancePage and the
 * Compliance tab on DeviceDetailPage), which is the threshold this project
 * uses for factoring out a shared component rather than inlining it.
 */
export function Tabs({ items, value, onChange, className }: TabsProps) {
  return (
    <div role="tablist" className={cn("flex flex-wrap gap-1 border-b border-[var(--color-border)]", className)}>
      {items.map((item) => {
        const isActive = item.value === value;
        return (
          <button
            key={item.value}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(item.value)}
            className={cn(
              "relative -mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "border-[var(--color-brand)] text-[var(--color-text)]"
                : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text)]",
            )}
          >
            {item.label}
            {item.count !== undefined && (
              <span className="rounded-full bg-[var(--color-surface-hover)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-text-muted)]">
                {item.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({ children }: { children: ReactNode }) {
  return <div role="tabpanel">{children}</div>;
}
