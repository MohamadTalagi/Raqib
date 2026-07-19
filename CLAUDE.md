# CLAUDE.md — KAUST IoT Security Project

> **This file is the single source of truth for the project.** It MUST be updated every time
> something meaningful changes: a new component is built, a decision is made, a tool is chosen,
> a task is completed, or a milestone is reached. Treat it as a living document.
>
> **Last updated:** 2026-07-19
> **Maintained by:** Team of 4 · KAUST Academy — Cybersecurity Specialization
> **Timeline:** 3-week project · Tooling: Claude Opus 4.8

---

## 0. Current Status — RESUME HERE 👈

**Phase:** **Device registration & visibility feature COMPLETE** on branch
`worktree-device-registration` (14 tasks, subagent-driven, every task independently
reviewed) — deployed and verified on the physical PC, awaiting final whole-branch
review + merge. Before that: **Phases 0-8 functionally COMPLETE**, and the `auditor-web` dashboard has
been **rebuilt from scratch in React + Tailwind v4 + Vite**, replacing Flutter Web
entirely, after the owner rejected the Flutter redesign as "AI slop" (see §8 for the
full story — kept in `docs/NEXT-SESSION-HANDOFF.md` as a historical record of the
root-cause analysis, now resolved). Branch `worktree-phase-6-8-implementation` was
**merged into `main` on 2026-07-19** (fast-forward to `fa73983`, 48 commits, 111 files)
— `main` is now the single live branch again.

**2026-07-09 — dashboard rebuilt in React (resolved the "AI slop" complaint):**
Replaced `lab/auditor/web/` (Flutter) wholesale with a Vite + React + TypeScript +
Tailwind v4 app. Design direction: dark near-black theme, single amber brand accent,
severity-coded status colors, real bundled Inter + JetBrains Mono fonts (via
`@fontsource`, so no repeat of the "referenced but never bundled" font bug), recharts
for the compliance gauge / verdict donut / device activity bar, lucide-react icons
throughout (no emojis). Fetches live from `auditor-api` (`/summary`, `/devices`,
`/evidence`, `/verdicts`, `/controls`). Verified by seeding the real 12
evidence + 8 verdict records from `document-store/` into a locally built
`auditor-database` + `auditor-api`, then visually confirming all 4 screens
(Overview, Devices, Evidence, Verdicts) with Playwright screenshots against both the
Vite dev server and the actual built Docker/nginx image — not just `flutter
analyze`/`tsc` this time. 14 Vitest + React Testing Library tests pass (7 files),
exceeding the old Flutter suite's 11. Two small errors hit and logged
(`docs/errors/018`-`019`).

**Plans:**
- `docs/superpowers/plans/2026-07-07-preliminary-iot-lab-phases-0-5.md` — 31 tasks,
  Phases 0-5, all complete.
- `docs/superpowers/plans/2026-07-08-phases-6-8-platform-completion.md` — 20 tasks,
  Phases 6-8 (auditor-api, auditor-database, auditor-web, traffic-capture), all
  complete and PC-verified. Acceptance doc: `docs/architecture/phases-6-8-acceptance.md`.

**Acceptance verification:** `docs/architecture/phases-0-5-acceptance.md` — full Day-1/Day-2/Day-3 acceptance criteria checked off with evidence, all independently re-verified against the real committed files (not just implementer claims). Headline results:
- Day 1: full lab (6 services + auditor-worker, 2 networks) built and demonstrated working on the physical PC.
- Day 2: 12 real manual-assessment evidence entries collected (exceeds required ≥8), all schema-valid.
- Day 3: 5 NCA controls (SA-IOT-001..005) mapped to real CGIoT-1:2024 sources; verdict engine run for real against the Day-2 evidence — 4 controls (not just the required ≥2) show correct PASS+FAIL pairs across different device configs.
- 45+ tests passing across the whole codebase (schema, policy engine, controls, firmware, evidence recording, smart-camera device, auditor-api, auditor-web widget tests).
- 17 errors hit and logged (`docs/errors/001`-`017`), each with root cause + fix + prevention.

**Already done (2026-07-07/08/09):**
- Approved design spec → `docs/superpowers/specs/2026-07-07-preliminary-iot-security-lab-design.md`
- Private git repo → `https://github.com/OSAMAxALHARBI/kaust-iot-security-lab` (branch `main`)
- Working **ssh-mcp** connection to the 32 GB build PC → host `OSRA-PC2025-V2`, user `osama`, Tailscale `100.99.182.30`, key auth. Tools appear as `mcp__ssh-mcp__*`. Remote shell is **Windows PowerShell 5.1** (no `&&` — use `;`; stderr from git gets wrongly wrapped as a PowerShell error even on success — check actual result, don't trust the error alone).
- **PC has read-write repo access**: dedicated ed25519 deploy key generated on the PC (`C:\Users\osama\.ssh\kaust_iot_deploy_key`), registered on GitHub as a **read-write** deploy key ("OSRA-PC2025-V2 (build PC, read-write)" — upgraded 2026-07-07 from an initial read-only key, so the PC could commit+push Day-2 evidence files generated on it per the Phase 0-5 plan's Task 26), SSH host alias `github.com-kaust-iot` added to `C:\Users\osama\.ssh\config`. Repo cloned to `C:\Users\osama\Projects\kaust-iot-security-lab`. (gh CLI is NOT installed on the PC — GCM/HTTPS auth doesn't work non-interactively over ssh-mcp, so use this SSH deploy-key path for any future PC git auth needs.)
- **Implementation happened in git worktrees**: `.claude/worktrees/phase-0-5-implementation` (branch `worktree-phase-0-5-implementation`, merged) and `.claude/worktrees/phase-6-8-implementation` (branch `worktree-phase-6-8-implementation`, not yet merged), both via subagent-driven-development (fresh implementer + reviewer subagent per task).
- Full stack (all 11 containers, including `auditor-api`/`auditor-database`/`auditor-web`/`traffic-capture`) deployed and manually verified working on the physical PC, including a live CORS bug fix caught by the owner opening a real browser.

**Next steps, in order:**
1. Final whole-branch review of `worktree-device-registration`, then merge to `main`.
2. **Per-device PDF compliance report** — design approved and specced
   (`docs/superpowers/specs/2026-07-19-pdf-compliance-report-design.md`). Implementation
   deliberately waits until the device-registration branch is merged.
3. Fix the carried backend gap: `POST /scan-jobs` resolves a device's target with
   `ORDER BY s.id LIMIT 1` (first enabled service only), while the dashboard offers any
   test matching *any* of the device's service types. Register a device with
   service#1=mqtt and service#2=http and an HTTP-only test is offered but rejected 400.
   Dormant today (no seeded device has multiple services) but it breaks exactly the
   multi-service devices the normalized model exists to support.
4. Decide what to do with two orphaned files on the PC in `document-store/raw/`:
   `EV-2026-07-08-0001.txt` and `EV-2026-07-08-0002.txt` are 9-byte scratch files
   ("insecure" / "hardened") referenced by **no** evidence record — real Day-2 evidence
   starts at `EV-...-0013`. Deliberately NOT committed, to keep the audit trail clean.

> **Deferred, do not start:** a "production-ready" rebuild of the platform. The owner
> explicitly scoped this as a later track (2026-07-19) — finish the current feature
> work on the existing 11-container lab first.

> Also read the recalled memory notes (project-overview, ssh-pc-connection, error-log-convention).
> Full history is in §8 changelog; decisions in §9 and the spec's decisions log.

---

## 1. What We Are Building

**Project name:** IoTGuard — *AI-Assisted IoT Security Compliance & Risk Assessment Platform (NCA-Aligned)*

A plug-and-play **IoT Security Posture Management (IoT-SPM)** solution for organizations in Saudi Arabia. It:

1. Discovers IoT devices on a network
2. Fingerprints them (vendor, model, firmware, services, ports)
3. Evaluates compliance against **Saudi NCA** controls (CGIoT-1:2024)
4. Enriches findings with vulnerability intelligence (CVE/NVD/CISA KEV)
5. Computes a dynamic risk score
6. Generates AI-powered remediation blueprints and executive summaries
7. Presents everything on a security dashboard with continuous monitoring

Unlike a plain compliance auditor, it runs the **full workflow from discovery → actionable remediation**.

**We produce two deliverables:**
- **A working project** (usually a web app / platform — the auditor + dashboard)
- **A research output** (documentation, findings, policy-as-code, methodology) built up alongside the code

---

## 2. Two Governing Documents

| Doc | What it is | Where |
|---|---|---|
| **IoTGuard vision** | The 10-stage platform pipeline (the "what to build") | `docs/reference/IoTGuard.md` |
| **CGIoT-1:2024** | The Saudi NCA IoT cybersecurity guidelines — 4 domains, 27 subdomains, 81 guidelines. The compliance controls we map devices against. | `docs/reference/CGIoT-1_2024.md` |

The **preliminary tasks** (our immediate 3-day sprint) come from `First_Task/Pre-liminary Tasks.pdf` and are summarized in Section 4 below.

---

## 3. The IoTGuard 10-Stage Pipeline (target architecture)

| # | Stage | Core tech |
|---|---|---|
| 01 | Platform Deployment & Initialization | Docker, Docker Compose, FastAPI, Flutter Web, PostgreSQL, Nginx |
| 02 | Network Discovery | Nmap, python-nmap, Scapy, ARP, SSDP, mDNS |
| 03 | Device Fingerprinting | Nmap service detection, banner grabbing, SNMP, ONVIF, MAC vendor DB |
| 04 | NCA Compliance Assessment | Python rule engine, YAML/JSON rules, CGIoT-1:2024 |
| 05 | Vulnerability Intelligence | NVD, CVE, CVSS, CISA KEV, EPSS (optional) |
| 06 | Dynamic Risk Assessment | Python risk scoring, Pandas (optional) |
| 07 | AI Security Blueprint & Remediation | LLM, prompt engineering, RAG (optional) |
| 08 | AI Executive Summary | LLM, prompt templates |
| 09 | Security Dashboard | Flutter Web, REST API, FastAPI, fl_chart |
| 10 | Continuous Monitoring & Historical Analysis | PostgreSQL, APScheduler/Celery, background tasks |

Full detail per stage: `docs/reference/IoTGuard.md`.

---

## 4. Current Focus — Preliminary 3-Day Training Sprint

Source: `First_Task/Pre-liminary Tasks.pdf`. This builds the **safe simulated lab** and the **evidence → policy → verdict** core that the full platform later automates.

### Task 0 — Docker simulated laboratory (3 device profiles)

Three logical smart-camera profiles, same app configured differently via Compose profiles / env vars / mounted config:

- **Device A — Insecure:** HTTP mgmt UI, default creds, Telnet, unencrypted MQTT, hard-coded API key, outdated component, weak/missing logging, privacy doc missing retention info.
- **Device B — Partially hardened:** Telnet removed, default password changed, HTTPS with *weak* cert, MQTT still unencrypted, some logging, unsigned update process, incomplete privacy docs.
- **Device C — Hardened:** HTTPS only, strong creds, MQTT over TLS, no unnecessary services, signed firmware, security logging, updated components, complete vendor docs, retention/deletion evidence.

### Required lab architecture (Docker Compose services)

`auditor-web`, `auditor-api`, `auditor-worker`, `auditor-database`, `device-insecure`, `device-partial`, `device-hardened`, `mqtt-broker-insecure`, `mqtt-broker-secure`, `traffic-capture`, `document-store`.
Optional: vuln DB mirror, mock update server, reverse proxy, log collector, test CA.

**Networks (≥2):** `audit-network` (auditor → devices) and `internal-network` (backend, isolated from devices).
Must document: container names, IP ranges, exposed ports, trust boundaries, data flows, what is reachable, what stays isolated.

### Day 1 — Docker IoT lab + network-security basics
- Intentionally insecure Flask/FastAPI smart-camera service: login page, device-info endpoint, config endpoint, firmware-version endpoint, default user/pass, plain HTTP, ≥1 admin endpoint.
- Network services: Telnet-like, MQTT broker, HTTP, optional SSH — reachable **only inside** the lab.
- Docker infra: Dockerfiles, Compose, audit + internal networks, volumes, env config, health checks.
- Threat & evidence model: architecture diagram, trust-boundary diagram, STRIDE-style threat model, initial JSON evidence schema.
- **Day-1 output:** working Compose env, ≥1 simulated device, ≥3 exposed services, network diagram, threat model, device inventory, README (start/stop).
- **Acceptance:** reach device web UI, connect to MQTT, detect ≥3 open ports, view simulated metadata.

### Day 2 — Manual cybersecurity assessment (collect evidence before automating)
- Web/auth: default creds, anonymous access, weak sessions, missing security headers, unprotected admin endpoints.
- Network/protocol: Nmap service detection, HTTP inspection, MQTT testing, TLS testing, packet capture.
- Simulated firmware analysis: build archive (version file, config, hard-coded password, API key, cert/key, manifest, update script); analyze with `file`, `strings`, `grep`, YARA, Syft, Grype.
- Evidence normalisation record fields: Evidence ID, Device ID, Tool, Tool version, Command, Timestamp, Finding, Raw output location, Confidence, Hash of evidence file.
- **Day-2 output:** ≥8 manual findings (default creds, exposed insecure service, unencrypted protocol, hard-coded secret, outdated package, weak/missing TLS, missing logging, missing privacy/update evidence).
- **Acceptance:** each finding shows raw output → structured evidence → security interpretation → suggested remediation.

### Day 3 — Saudi policy mapping + policy-as-code
- Map first 5 controls (device identification, default credentials, unnecessary services, insecure protocols, TLS/secure comms) to Saudi sources (CGIoT-1:2024).
- Test-to-control mapping: which Docker service creates evidence, which command/tool tests it, Pass/Fail/Inconclusive results.
- YAML control schema fields: Control ID, Title, Saudi source mapping, Applicability, Required evidence, Automated test IDs, Pass/Fail/Partial/Inconclusive conditions, Severity, Remediation.
- Minimal policy engine (Python): load 1 YAML control → read 1 evidence JSON → apply verdict logic → output verdict JSON.
- **Day-3 output:** working demo — simulated device → network test → evidence JSON → YAML policy → verdict JSON.
- **Acceptance:** ≥2 controls produce correct Pass and Fail verdicts across different simulated configs.

---

## 5. Repository Layout

```
Kaust IoT Project/
├── CLAUDE.md                      # ← this file (living project charter)
├── First_Task/
│   └── Pre-liminary Tasks.pdf     # mentor-provided task brief
├── docs/
│   ├── reference/
│   │   ├── IoTGuard.md            # platform vision (10 stages)
│   │   └── CGIoT-1_2024.md        # Saudi NCA IoT guidelines
│   ├── architecture/              # diagrams, threat models, network design
│   └── errors/                    # one MD file per error we hit + how we fixed it
│       ├── README.md              # error-log convention
│       └── ERROR_TEMPLATE.md      # copy this for each new error
└── (code folders added as we build: lab/, auditor/, policies/, ...)
```

---

## 6. Error & Solution Log — MANDATORY convention

> **Every error we face while building gets its own Markdown file** in `docs/errors/`.
> This is a hard rule from the project owner — these logs feed our research report later.

- One file per distinct error: `docs/errors/NNN-short-slug.md` (e.g. `001-docker-compose-port-conflict.md`).
- Copy `docs/errors/ERROR_TEMPLATE.md` and fill it in.
- Record: what happened, exact error text, root cause, the fix, and prevention.
- Add a one-line entry to the index in `docs/errors/README.md`.
- Do this even for "small" errors — the research value is in the pattern of problems.

---

## 7. Working Agreements

- **Update this file** whenever a component is built, a decision is made, or a milestone is hit (Section 8 changelog).
- **Log every error** as its own file (Section 6).
- Keep the simulated-vulnerable lab **isolated inside Docker** — never expose insecure services to the host/internet.
- Prefer many small, cohesive files over few large ones.
- This is authorized, self-contained security training — all "insecure" devices are intentional and sandboxed.

---

## 8. Changelog

| Date | Change |
|---|---|
| 2026-07-07 | Project initialized. Copied reference docs (IoTGuard vision, CGIoT-1:2024) into `docs/reference/`. Read and summarized mentor's preliminary 3-day sprint tasks. Created CLAUDE.md charter, error-log convention, and folder scaffolding. |
| 2026-07-07 | **Stack decisions** (see §9): all-Python spine, FastAPI for device + auditor API; sprint needs **no frontend**; LLM stages use the **Claude API (Opus 4.8)**; run the lab in **WSL2**. Adopted the "AI-assisted, not AI-decided" principle — evidence and verdicts are deterministic Python, never LLM output. |
| 2026-07-07 | Ran a full **brainstorming** pass (Superpowers) on the mentor's 3-day sprint. Decisions: standalone project · full 11-container architecture (Option A) · `auditor-web` = thin Flutter/Dart built last · manual-then-automated assessment · hybrid real/simulated services · target machine = the 32 GB PC · single deliverer. Design approved section-by-section and written to `docs/superpowers/specs/2026-07-07-preliminary-iot-security-lab-design.md`. Created `setup/ssh-mcp/` scripts to remote-control the PC over Tailscale. Next: user reviews spec → set up ssh-mcp + switch Opus→Sonnet → implementation plan. |
| 2026-07-07 | **Spec approved. Git initialized** (commits `d94853e`, `71343b3`). **ssh-mcp connection to the 32 GB PC is working** (host OSRA-PC2025-V2, user `osama`, Tailscale 100.99.182.30, key auth) — verified `hostname`/`whoami` over SSH; MCP registered at user scope. Hit + fixed + logged the Windows `spawn npx ENOENT` bug (**ERR-001**; use `cmd /c npx`). **Boundary reached:** restart Claude Code + switch Opus→Sonnet to load `mcp__ssh-mcp__*`, then write the implementation plan and build on the PC. Open decision: build directly on the PC vs. author-on-laptop + git-sync + run-via-ssh-mcp. |
| 2026-07-07 | **Model switched to Sonnet 5, `mcp__ssh-mcp__*` tools confirmed loaded** (`hostname`/`whoami` succeeded over SSH). **Decided Workflow B** (author on laptop → push → PC pulls + runs via ssh-mcp). Set up **read-only repo access on the PC**: generated a dedicated ed25519 deploy key on the PC, registered it read-only on GitHub via local `gh` CLI, added SSH host alias `github.com-kaust-iot`, cloned the repo to `C:\Users\osama\Projects\kaust-iot-security-lab`. (HTTPS + Git Credential Manager doesn't work here — no TTY/browser over non-interactive ssh-mcp, and PC has no `gh` CLI — so SSH deploy key is the pattern going forward.) Confirmed the PC has **Docker Desktop 29.x + Compose v5 with the WSL2 backend already running** — `docker`/`docker compose` work directly from the ssh-mcp PowerShell session, no need to shell into WSL. **Wrote the full Phases 0-5 implementation plan** (31 tasks, TDD throughout for all pure-Python pieces) via the writing-plans skill → `docs/superpowers/plans/2026-07-07-preliminary-iot-lab-phases-0-5.md`. Next: execute Phase 0 (Task 1 onward). |
| 2026-07-08 | **Phases 0-5 fully implemented, reviewed, and PC-verified — all 31 tasks complete.** Executed via subagent-driven-development in the `phase-0-5-implementation` worktree: fresh implementer subagent + independent reviewer subagent per task, with PC-side Docker/Compose verification over ssh-mcp wherever the lab itself was touched. Phase 0 (contracts), Phase 1 (lab core: 3 device profiles, telnet-sim, 2 MQTT brokers, cert-init, auditor-worker, 2-network topology), Phase 2 (TLS profiles hardening), Phase 3 (Day-1 diagrams/threat model/inventory/README), Phase 4 (Day-2 manual assessment: 12 real evidence entries collected on the PC across nmap/curl/openssl/mosquitto/YARA/Syft/Grype, all schema-valid), and Phase 5 (Day-3 policy-as-code: deterministic policy engine with no `eval`/`exec`, 5 NCA controls mapped to real CGIoT-1:2024 sources, verdict-generation CLI run for real producing 4 controls with correct PASS+FAIL pairs — double the required ≥2). 11 errors hit and logged (`docs/errors/001`-`011`). Final acceptance doc written and independently fact-checked twice (`docs/architecture/phases-0-5-acceptance.md`) — first draft had a wrong test count and some fabricated NCA references, caught by controller cross-checking against the real committed files, then corrected and re-verified line-by-line. **Total: 45 tests passing.** Next: merge the worktree, then plan Phases 6-8. |
| 2026-07-08/09 | **Phases 6-8 implemented and PC-verified — all 20 tasks complete** in the `phase-6-8-implementation` worktree via subagent-driven-development: `auditor-api` (FastAPI, full CRUD, CORS), `auditor-database` (Postgres schema + indexes), `auditor-web` (Flutter dashboard, 4 screens), `traffic-capture` (tcpdump on audit-network), all wired into the 11-container compose stack. Hit and fixed 6 more errors (`docs/errors/012`-`017`), including two genuine infra findings: Docker Desktop's host port-forwarding proxy silently fails to bind ports for containers whose only network is `internal: true` (fixed via a dev-only compose overlay, ERR-017), and a live CORS bug the owner caught by opening a real browser (curl-based verification never exercises CORS). Full stack deployed and smoke-tested on the PC. **Then did a "full UI redesign" pass on `auditor-web` (commit `d84d21f`) that the owner rejected as "AI slop"** — root cause: custom fonts (`Inter`/`JetBrains Mono`) were referenced in `theme.dart` but never bundled in `pubspec.yaml`, no design-approval step ran before implementation, and the result was never visually verified (same blind spot as the CORS bug: checks passed, nobody looked at a real browser). Wrote `docs/NEXT-SESSION-HANDOFF.md` with the concrete root causes and fix plan for the next session. Branch pushed but not yet merged — final whole-branch review and UI redo both still outstanding. |
| 2026-07-09 | **`auditor-web` rebuilt from scratch in React, resolving the "AI slop" complaint.** Owner decided to abandon Flutter Web for the dashboard entirely and switch to React + Tailwind + shadcn-style components. Deleted `lab/auditor/web/`'s Flutter app wholesale (Dockerfile, `lib/`, `test/`, `pubspec.yaml`, `web/`) and scaffolded a Vite + React 19 + TypeScript app in its place: Tailwind v4 (`@tailwindcss/vite`), `@fontsource/inter` + `@fontsource/jetbrains-mono` actually bundled (not just referenced — the exact bug that sank the Flutter attempt), recharts for the compliance gauge/verdict donut/device bar chart, lucide-react icons, react-router for the 4 screens (Overview/Devices/Evidence/Verdicts). Design: dark near-black theme with a single amber brand accent and severity-coded status colors (critical/high/medium/low + PASS/FAIL/PARTIAL/INCONCLUSIVE), monospace accents for control/evidence IDs and raw commands — deliberately avoiding the generic "dark mode + rounded cards + one teal accent" Material look called out in the handoff doc. Verified for real this time: built `auditor-database` + `auditor-api` locally, seeded the actual 12 evidence + 8 verdict records from `document-store/` through the live API, then used Playwright to screenshot all 4 screens against both the Vite dev server and the final built Docker/nginx image (`docker run` on a scratch port, since the shared dev machine already had 8080 bound — ERR-019) — confirmed real fonts render, live data flows through, zero console errors. Added a from-scratch Vitest + React Testing Library suite (14 tests / 7 files, beating the old Flutter suite's 11) since the whole app was replaced. Hit two small errors (`docs/errors/018`-`019`). New Dockerfile is a standard Node-build → nginx multi-stage (replacing the `cirruslabs/flutter` build stage), with an `nginx.conf` adding SPA fallback routing. Deployed to the physical build PC same-day (`git pull` + `docker compose build auditor-web` + `--force-recreate`, using the existing `docker-compose.dev.yml` overlay for host port 8080) and confirmed serving the new build (`curl`'d title tag matches). Still outstanding: the owner's live sign-off in a real browser, then the final whole-branch review and merge to `main`. |
| 2026-07-12 | **Added a live "Run Scan" feature to the dashboard** — a real button that triggers an actual whitelisted test against a live device, not just the CLI/terminal workflow. Built as a job-queue architecture rather than direct execution from the web layer (`auditor-api` never runs a command itself — it only manages `scan_jobs` rows; `auditor-worker`'s new `job_runner.py` polls for pending jobs and is the sole executor, re-validating device/test against a fixed whitelist in `policies/catalog/scan_tests.py` before running anything, commands built as argv lists, never a shell string). The dashboard preserves the project's evidence principle end to end: raw output and observations are captured automatically, but a human still has to type the "finding" text before evidence gets recorded — same requirement as `record_evidence.py`, just through a form. Added an idempotent `POST /verdicts/recompute` (existing `generate_verdicts.py` would duplicate-key-crash on a second run; this one checks each verdict's `evidence_ids` first, safe to click repeatedly). Verified for real: a live nmap scan and a live rejected-login curl against real containers, driven through the actual React UI via Playwright, evidence + verdict visible afterward on the existing pages — not just mocked tests (though there are 74 of those too, all passing). Hit and logged `docs/errors/021`: adding a table to `init.sql` doesn't reach an already-initialized Postgres volume — had to apply the migration by hand on both the local dev DB and the PC's real one. |
| 2026-07-12 | **Added a "Device Console" page to the dashboard** — one card per device (`device-insecure`, `device-partial`, `device-hardened`), each with a button per service the brief requires (login page, login with default creds, device info, config, firmware version, admin reset, privacy doc, health), 24 buttons total. Every click is a real browser `fetch` straight to the device container (no backend proxy) via a new `lab/auditor/web/src/lib/consoleDevices.ts`, deriving each device's base URL from `window.location.hostname` at runtime (same pattern as ERR-020's `api.ts` fix) so the page works identically on localhost, LAN, or Tailscale. Added CORS middleware to the device app itself (`lab/devices/smart-camera/app/main.py`) since browser calls now cross the `:8080 → :8081/8082/8083` origin boundary — 1 new device test (22/22 passing). The two HTTPS devices' self-signed lab certs need a one-time manual "trust" click in a real browser; the UI surfaces this directly as an inline hint instead of failing silently. Verified for real on the physical PC over Tailscale: curl'd CORS headers on all 3 devices, then drove the page itself with Playwright at `http://100.99.182.30:8080/console` — clicked "Device info" on `device-insecure` and got back a live 200 response with real device data (`vendor: AcmeCam`, `firmware_version: 1.0.0-old`) fetched directly from the container. **Follow-up same day:** "Login page" and "Privacy doc" are HTML pages meant to be viewed, not just fetched — clicking them now also opens the real page in a new tab (`window.open`) alongside the existing fetch-result panel, via a new `viewable` flag on `ConsoleEndpoint`. Verified live on the PC with Playwright: clicking "Login page" on `device-insecure` opened a second browser tab showing the real rendered login form at `http://100.99.182.30:8081/`. |
| 2026-07-10 | **Each simulated device now has a minimal `/dashboard` UI, and all three postures are reachable from a browser.** Previously the smart-camera app only had a bare login form plus raw JSON endpoints, and only `device-insecure` was published to the host (via the dev overlay) — `device-partial`/`device-hardened` had no way to be viewed directly. Added `GET /dashboard` (`lab/devices/smart-camera/app/main.py`): shows device info, config (the hardcoded API key rendered in red when exposed — the vulnerability made visible), and a live "Trigger admin reset" button wired to the existing `/api/admin/reset` endpoint, demonstrating the exact posture difference interactively (instant reset with no auth on `device-insecure`; HTTP 401 on `device-hardened`, since the browser sends no `Authorization` header). Added a real `transport` config field mirroring `entrypoint.sh`'s `TRANSPORT` env var rather than guessing it. Left `POST /login`'s response untouched, since it's referenced byte-for-byte by committed Day-2 evidence (`EV-2026-07-08-0015`)'s raw output and hash. Published `device-partial` (`8082→443`) and `device-hardened` (`8083→443`) in `docker-compose.dev.yml` alongside the existing `device-insecure` (`8081→80`). 4 new tests (21/21 passing). Verified for real: built and ran all three device images, confirmed each dashboard renders, confirmed the admin-reset auth difference actually works, confirmed the weak/strong self-signed certs correctly trigger a browser TLS warning (expected — lab test CA, not a public one) — then deployed to the build PC and re-verified all three respond over Tailscale. |
| 2026-07-19 | **Devices became first-class database records, and the dashboard gained device registration, per-device detail, and NCA Controls screens.** Executed as a 14-task plan via subagent-driven-development (fresh implementer + independent reviewer per task) on `worktree-device-registration`. Backend: new `devices` + `device_services` tables; full device CRUD; a standalone `device_validation.py` that replaced the old hardcoded `allowed_devices` whitelist as the scan security boundary (targets restricted to container names or `172.30.0.0/24`, infrastructure hostnames denied, argv-injection blocked by requiring an alphanumeric leading character, IPs parsed with `ipaddress` so octal forms like `0172.030.0.1` cannot bypass the range check); `auditor-worker` re-validates the same values read back out of the database before building any command, treating the DB as untrusted input; scan tests re-keyed from device names to `applicable_service_types`; a per-control verdict rollup endpoint. Frontend: registration form with field-level API error rendering, per-device detail page, NCA Controls list + detail, and the deletion of `deviceMeta.ts` / `consoleDevices.ts` so device identity now comes from the API alone. **Review caught real defects the plan itself introduced**, including a port scan narrowed to a single known port (destroying the discovery purpose that evidences SA-IOT-003 — owner chose to restore full-range `-p-`), validation errors that rendered nowhere for three field names, a control-detail page that hung forever on an unknown ID because the backend returns 200-with-empty-data rather than 404, and a `Device` type that lied about three of the four endpoints returning it. **PC verification:** migration + seed applied to the live database with `GET /summary` byte-identical before and after (13 evidence / 8 verdicts / 4 PASS / 4 FAIL — note 13, not the plan's stale 12), all 11 containers healthy, and every new screen driven in a real browser over Tailscale including a live rejection of host `10.0.0.5` rendered under the Host input. Also fixed `telnet-sim`'s long-standing unhealthy status: BusyBox `nc` has no `-z` flag **and** `localhost` resolves to IPv6 while the service binds IPv4 — ERR-005 had diagnosed the same IPv6 issue in 2026-07 but its fix only landed in the Dockerfile `HEALTHCHECK`, which the Compose `healthcheck:` block overrides (`docs/errors/022`). |
| 2026-07-19 | **Merged `worktree-phase-6-8-implementation` into `main`** — fast-forward to `fa73983`, 48 commits, 111 files, +9,266/-147. `main` had zero commits the branch lacked, so no conflicts and no merge commit. This also resolved a documentation trap: `main`'s CLAUDE.md had been stale since 2026-07-08 (still claiming Phases 6-8 were merely "planned") while the branch's copy was fully current — the fix was merging, not rewriting. **Lab restored on the build PC:** Docker Desktop was found not running (all 11 containers `Exited (255)` from an engine restart, not a crash — images intact); started the engine and `docker compose up -d` brought all 11 back, 9 reporting healthy. **Known issue:** `telnet-sim` is `Up (unhealthy)` — healthcheck fails with exit 1 and empty output on a 4-run streak; the container itself is running, so this looks like a broken healthcheck command rather than a dead service. Not yet diagnosed. Also noted: 3 uncommitted evidence files on the PC in `document-store/raw/`. Owner scoped the "production-ready rebuild" as a **deferred** later track — current work continues on the existing 11-container lab. |

---

## 9. Stack Decisions

- **Model:** Opus 4.8 used across the board — as the build assistant, and as the platform LLM for Stages 7–8. Resolves the LLM-provider question → **Claude API**.
- **Determinism rule (important for research):** evidence collection (Day 2) and verdict logic (Day 3) are **deterministic Python** — reproducible from `(tool, version, command, timestamp, hash)`. LLMs assist/explain but never decide a Pass/Fail. Framed as "AI-assisted, not AI-decided."
- **Backend:** FastAPI for both the simulated device and `auditor-api` (Flask dropped — no second framework).
- **Sprint frontend:** none required — the 3-day acceptance tests are endpoint/MQTT/port/JSON based. Dashboard (Flutter Web per vision, or React/HTMX) is deferred to the full platform.
- **Environment:** WSL2 on Windows (best compatibility for nmap/Scapy/tcpdump/Docker networking).
- **Sprint core (5 things only):** FastAPI · PostgreSQL · nmap/python-nmap · PyYAML · firmware CLI tools (file/strings/grep/YARA/Syft/Grype).

### Still open
- [ ] Team fluent in Flutter/Dart or React? (No — as of 2026-07-07.) Flips the *platform* dashboard choice later; irrelevant to the sprint.
- [ ] Frontend stack for the final platform deliverable (revisit after the sprint).
