import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import type { ScanJob } from "@/lib/types";

/**
 * A terminal-style front end for running scans. It is deliberately NOT a
 * shell: the only action it can take is `createScanJob(device_id, test_id)`,
 * and auditor-api re-validates both against the fixed SCAN_CATALOG whitelist
 * (and device_validation) before auditor-worker builds any command as an
 * argv list - there is no path here to run arbitrary text. The console only
 * understands `scan`, `list`, `help`, and `clear`; anything else is rejected
 * client-side too, so the security boundary is unchanged from the Run Scan
 * page - this is just a faster, keyboard-driven skin over the same jobs.
 */

const POLL_INTERVAL_MS = 1500;
const IN_FLIGHT = new Set<ScanJob["status"]>(["pending", "running"]);

type LineKind = "input" | "output" | "error" | "system";
interface Line {
  kind: LineKind;
  text: string;
}

const LINE_CLASS: Record<LineKind, string> = {
  input: "text-[var(--color-brand)]",
  output: "text-[var(--color-text-secondary)]",
  error: "text-[var(--color-critical)]",
  system: "text-[var(--color-text-muted)]",
};

const WELCOME: Line[] = [
  { kind: "system", text: "IoTGuard scan console — whitelisted catalog scans only, not a shell." },
  { kind: "system", text: "Type `help` for commands, `list tests`, or `list devices` to get started." },
];

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function ScanConsolePage() {
  const devices = useFetch(api.devices, []);
  const tests = useFetch(api.scanTests, []);

  const [lines, setLines] = useState<Line[]>(WELCOME);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState<number | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [lines]);

  function append(...newLines: Line[]) {
    setLines((prev) => [...prev, ...newLines]);
  }

  async function pollToCompletion(jobId: number): Promise<ScanJob | null> {
    // Bounded poll (~90s) so a stuck job never hangs the console forever.
    for (let i = 0; i < 60; i += 1) {
      let job: ScanJob;
      try {
        job = await api.getScanJob(jobId);
      } catch {
        await delay(POLL_INTERVAL_MS);
        continue;
      }
      if (!IN_FLIGHT.has(job.status)) return job;
      await delay(POLL_INTERVAL_MS);
    }
    return null;
  }

  async function runScan(deviceId: string, testId: string) {
    const registered = (devices.data ?? []).filter((d) => d.registered);
    if (!deviceId || !testId) {
      append({ kind: "error", text: "usage: scan <device_id> <test_id>" });
      return;
    }
    if (!registered.some((d) => d.device_id === deviceId)) {
      append({ kind: "error", text: `unknown or unregistered device: ${deviceId} (try \`list devices\`)` });
      return;
    }
    if (!(tests.data ?? []).some((t) => t.test_id === testId)) {
      append({ kind: "error", text: `unknown test: ${testId} (try \`list tests\`)` });
      return;
    }

    setBusy(true);
    append({ kind: "system", text: `queuing ${testId} against ${deviceId}…` });
    try {
      const created = await api.createScanJob(deviceId, testId);
      append({ kind: "system", text: `job #${created.id} queued; running on auditor-worker…` });
      const job = await pollToCompletion(created.id);
      if (!job) {
        append({ kind: "error", text: `job #${created.id} did not finish within the time limit.` });
        return;
      }
      if (job.command) append({ kind: "output", text: `> ${job.command}` });
      if (job.raw_output) {
        for (const l of job.raw_output.replace(/\s+$/, "").split("\n")) {
          append({ kind: "output", text: l });
        }
      }
      if (job.status === "failed") {
        append({ kind: "error", text: `job #${job.id} failed: ${job.error ?? "unknown error"}` });
      } else {
        append({
          kind: "system",
          text: `job #${job.id} ${job.status} — record a finding on the Run Scan page to store evidence.`,
        });
      }
    } catch (err) {
      append({ kind: "error", text: err instanceof ApiError ? err.message : "could not start the scan." });
    } finally {
      setBusy(false);
    }
  }

  async function handleCommand(raw: string) {
    const cmd = raw.trim();
    append({ kind: "input", text: `$ ${cmd}` });
    if (cmd) {
      setHistory((h) => [...h, cmd]);
    }
    setHistoryIdx(null);

    if (!cmd) return;
    const [verb, ...args] = cmd.split(/\s+/);

    switch (verb) {
      case "help":
        append(
          { kind: "output", text: "commands:" },
          { kind: "output", text: "  scan <device_id> <test_id>   run a whitelisted scan" },
          { kind: "output", text: "  list devices                 show registered devices" },
          { kind: "output", text: "  list tests                   show available scan tests" },
          { kind: "output", text: "  clear                        clear the screen" },
          { kind: "output", text: "  help                         show this help" },
        );
        break;
      case "clear":
        setLines([]);
        break;
      case "list":
        if (args[0] === "devices") {
          const registered = (devices.data ?? []).filter((d) => d.registered);
          if (registered.length === 0) append({ kind: "output", text: "(no registered devices)" });
          for (const d of registered) {
            append({ kind: "output", text: `  ${d.device_id}  (${d.tier})  ${d.host ?? ""}` });
          }
        } else if (args[0] === "tests") {
          for (const t of tests.data ?? []) {
            append({ kind: "output", text: `  ${t.test_id}  —  ${t.label}` });
          }
        } else {
          append({ kind: "error", text: "usage: list <devices|tests>" });
        }
        break;
      case "scan":
        await runScan(args[0], args[1]);
        break;
      default:
        append({
          kind: "error",
          text: `command not found: ${verb} — this console only runs \`scan\`, \`list\`, \`help\`, \`clear\` (whitelisted scans, not a shell).`,
        });
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    const value = input;
    setInput("");
    void handleCommand(value);
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    // Basic up/down command history, like a real terminal.
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length === 0) return;
      const next = historyIdx === null ? history.length - 1 : Math.max(0, historyIdx - 1);
      setHistoryIdx(next);
      setInput(history[next]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx === null) return;
      const next = historyIdx + 1;
      if (next >= history.length) {
        setHistoryIdx(null);
        setInput("");
      } else {
        setHistoryIdx(next);
        setInput(history[next]);
      }
    }
  }

  return (
    <Shell title="Scan Console" subtitle="Keyboard-driven runner for whitelisted catalog scans">
      <div className="space-y-4">
        <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)] bg-[color-mix(in_oklab,var(--color-pass)_6%,var(--color-surface))] px-3 py-2 text-xs text-[var(--color-text-secondary)]">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-pass)]" />
          <span>
            This console can only run pre-approved scan-catalog tests against registered lab devices. It is
            <strong className="text-[var(--color-text)]"> not a shell</strong> — every scan is re-validated
            server-side against the fixed whitelist and executed as an argv list, never interpolated text.
          </span>
        </div>

        <div
          className="flex h-[60vh] cursor-text flex-col rounded-lg border border-[var(--color-border)] bg-[#0b0e14] font-mono text-xs"
          onClick={() => inputRef.current?.focus()}
        >
          <div ref={scrollRef} className="flex-1 space-y-0.5 overflow-y-auto p-4">
            {lines.map((l, i) => (
              <div key={i} className={`whitespace-pre-wrap break-all ${LINE_CLASS[l.kind]}`}>
                {l.text}
              </div>
            ))}
            {busy && <div className="text-[var(--color-text-muted)]">…</div>}
          </div>
          <form onSubmit={onSubmit} className="flex items-center gap-2 border-t border-white/10 px-4 py-2.5">
            <span className="text-[var(--color-brand)]">$</span>
            <input
              ref={inputRef}
              aria-label="Console command"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              disabled={busy}
              spellCheck={false}
              autoComplete="off"
              placeholder={busy ? "running…" : "scan device-insecure TEST-NET-PORTSCAN"}
              className="flex-1 bg-transparent text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none disabled:opacity-50"
            />
          </form>
        </div>
      </div>
    </Shell>
  );
}
