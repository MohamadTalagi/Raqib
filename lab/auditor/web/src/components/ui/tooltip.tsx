import { useId, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface TooltipProps {
  content: ReactNode;
  children: ReactNode;
  className?: string;
}

/**
 * CSS-positioned, no-portal tooltip - matches this app's existing precedent
 * of hand-rolling small primitives (ConfirmDialog, the toast stack) rather
 * than reaching for a library. Shows on hover OR focus (React attaches
 * focus/blur in the capture phase, so these fire for a focused descendant
 * too, not just the wrapper itself) so a keyboard user gets the same
 * explanation a mouse user does.
 *
 * Uses a visible border *and* shadow, not border alone: --color-surface-raised
 * and --color-surface are the identical #ffffff in the light theme, so a
 * border-only tooltip would nearly disappear against a white page.
 */
export function Tooltip({ content, children, className }: TooltipProps) {
  const [open, setOpen] = useState(false);
  const id = useId();

  return (
    <span
      className={cn("relative inline-flex", className)}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <span aria-describedby={open ? id : undefined}>{children}</span>
      {open && (
        <span
          role="tooltip"
          id={id}
          className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 w-max max-w-xs -translate-x-1/2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2.5 py-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)] shadow-lg"
        >
          {content}
        </span>
      )}
    </span>
  );
}
