# ERR-020 — Hardcoded `localhost:8000` API URL breaks the dashboard for any client but the PC itself

- **Date:** 2026-07-09
- **Component:** lab/auditor/web (React dashboard) / lab/auditor/api
- **Severity:** high
- **Status:** resolved
- **Author:** Claude Code session

## What happened
After deploying the new React `auditor-web` to the build PC and confirming
`curl http://localhost:8080/` returned 200 on the PC itself, the owner reported the
dashboard "isn't working by Tailscale" — i.e. opening `http://100.99.182.30:8080/`
from another device on the tailnet.

## Exact error / symptom
No server-side error at all — the HTML/JS/CSS all served fine (200 OK from any
host). The failure was entirely client-side: every screen would show its loading
skeleton or error state indefinitely, because every `fetch()` call from the
browser's JS was going to `http://localhost:8000/...`.

## Environment
- Build PC: `OSRA-PC2025-V2`, Tailscale IP `100.99.182.30`, Docker Desktop 29.x
- Relevant files: `lab/auditor/web/src/lib/api.ts`, `lab/auditor/web/Dockerfile`

## Root cause
The Dockerfile baked `VITE_API_URL=http://localhost:8000` into the production build
by default (`ARG VITE_API_URL=http://localhost:8000`). Vite inlines
`import.meta.env.VITE_API_URL` as a literal string constant at build time — it is
**not** re-evaluated per request. So every client that loads the page, regardless of
which host/IP it used to reach `auditor-web`, ships the same hardcoded string and
tries to fetch from `localhost:8000`. On the PC itself, that happens to work because
`localhost:8000` really is the PC's own `auditor-api` (published via the dev compose
overlay). On any other machine — including one reaching the dashboard over Tailscale
— the browser's `localhost:8000` resolves to *that machine's own port 8000*, where
nothing is listening. Confirmed by grepping the built bundle
(`grep -o 'http://localhost:8000' dist/assets/*.js`) and by testing directly:
`curl http://100.99.182.30:8000/summary` succeeded (the API itself is reachable over
Tailscale), while the browser was still calling `localhost:8000`.

This is the same underlying class of bug as the earlier CORS issue and the original
Flutter `--dart-define=AUDITOR_API_URL=http://localhost:8000`: a build-time-baked
"localhost" assumption that only holds when the client and server are the same
machine.

## The fix
Made the frontend derive its API base URL from the page's own host at runtime
instead of a build-time constant, in `src/lib/api.ts`:

```ts
function resolveApiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_URL as string | undefined;
  if (configured) return configured;
  return `${window.location.protocol}//${window.location.hostname}:8000`;
}
```

And stopped defaulting `VITE_API_URL` in the Dockerfile (`ARG VITE_API_URL` with no
default), so a normal build has no baked-in host at all and always falls back to
`window.location.hostname`. An explicit override is still possible via
`--build-arg VITE_API_URL=...` for deployments where the API genuinely lives on a
different host than the one serving the dashboard.

Added a regression test (`src/lib/api.test.ts`) asserting that with no
`VITE_API_URL` set, a request from `window.location.hostname = "100.99.182.30"`
calls `http://100.99.182.30:8000/summary`, not `localhost`.

## How to prevent it next time
Never bake a fixed hostname (`localhost` or otherwise) into a client-side bundle
that will be accessed from more than one network identity (localhost, LAN IP,
Tailscale, etc.) unless there's a reverse proxy unifying it. Prefer deriving the API
host from `window.location` at runtime, and write a test that simulates a
non-`localhost` `window.location.hostname` before considering "multi-host access"
verified — `curl` from the server itself will never catch this, only testing from a
genuinely different origin does.

## References
Related: the CORS bug from the Flutter build (owner caught it by opening a real
browser, not by `curl`) — same "verify from the actual client's perspective" lesson.
