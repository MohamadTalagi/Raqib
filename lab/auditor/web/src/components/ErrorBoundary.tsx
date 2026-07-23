import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertOctagon } from "lucide-react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/** Class component wrapping <Routes> — the only way React lets you catch a
 * render error, so an unexpected exception shows a recoverable fallback
 * instead of leaving the whole app blank. */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled error in the dashboard UI:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-[var(--color-bg)] px-4">
          <div className="flex max-w-md flex-col items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center">
            <AlertOctagon className="h-8 w-8 text-[var(--color-critical)]" strokeWidth={1.75} />
            <div>
              <p className="text-sm font-medium text-[var(--color-text)]">Something went wrong</p>
              <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">
                {this.state.error.message}
              </p>
            </div>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="mt-2 inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)]"
            >
              Reload the page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
