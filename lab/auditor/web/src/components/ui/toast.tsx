import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

export type ToastVariant = "success" | "error" | "info";

export interface ToastItem {
  id: number;
  message: string;
  variant: ToastVariant;
}

const VARIANT_STYLES: Record<ToastVariant, { icon: typeof CheckCircle2; color: string; border: string }> = {
  success: { icon: CheckCircle2, color: "text-[var(--color-pass)]", border: "border-[var(--color-pass)]/30" },
  error: { icon: XCircle, color: "text-[var(--color-critical)]", border: "border-[var(--color-critical)]/30" },
  info: { icon: Info, color: "text-[var(--color-brand)]", border: "border-[var(--color-brand)]/30" },
};

interface ToastStackProps {
  toasts: ToastItem[];
  onDismiss: (id: number) => void;
}

/** A fixed-position, bottom-right toast stack — the presentational half of
 * `lib/useToast.tsx`'s provider/hook. No external dependency, matching this
 * project's existing "small custom primitive" precedent
 * (`ui/confirm-dialog.tsx`). */
export function ToastStack({ toasts, onDismiss }: ToastStackProps) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex w-full max-w-sm flex-col gap-2">
      {toasts.map((toast) => {
        const style = VARIANT_STYLES[toast.variant];
        const Icon = style.icon;
        return (
          <div
            key={toast.id}
            role="status"
            className={cn(
              "flex items-start gap-2.5 rounded-md border bg-[var(--color-surface-raised)] px-4 py-3 text-sm text-[var(--color-text)] shadow-xl",
              style.border,
            )}
          >
            <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", style.color)} />
            <span className="flex-1">{toast.message}</span>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              aria-label="Dismiss notification"
              className="cursor-pointer text-[var(--color-text-muted)] transition-colors hover:text-[var(--color-text)]"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
