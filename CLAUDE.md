# CLAUDE.md — KAUST IoT Security Project

> **This file is the single source of truth for the project.** It MUST be updated every time
> something meaningful changes: a new component is built, a decision is made, a tool is chosen,
> a task is completed, or a milestone is reached. Treat it as a living document.
>
> **Last updated:** 2026-07-07
> **Maintained by:** Team of 4 · KAUST Academy — Cybersecurity Specialization
> **Timeline:** 3-week project · Tooling: Claude Opus 4.8

---

## 0. Current Status — RESUME HERE 👈

**Phase:** implementation plan written → **ready to execute Phase 0**.

**Plan:** `docs/superpowers/plans/2026-07-07-preliminary-iot-lab-phases-0-5.md` — 31 tasks covering Phases 0-5 (contracts → lab core → profiles/TLS → Day-1 artifacts → manual assessment → policy-as-code). Phases 6-8 (auditor-api/database, Flutter auditor-web, full 11-container polish) are a separate follow-up plan, written after Phases 0-5 are graded.

**Already done (2026-07-07):**
- Approved design spec → `docs/superpowers/specs/2026-07-07-preliminary-iot-security-lab-design.md`
- Private git repo → `https://github.com/OSAMAxALHARBI/kaust-iot-security-lab` (branch `main`)
- Working **ssh-mcp** connection to the 32 GB build PC → host `OSRA-PC2025-V2`, user `osama`, Tailscale `100.99.182.30`, key auth. Tools appear as `mcp__ssh-mcp__*`. Remote shell is **Windows PowerShell 5.1** (no `&&` — use `;`; stderr from git gets wrongly wrapped as a PowerShell error even on success — check actual result, don't trust the error alone).
- **PC has read-write repo access**: dedicated ed25519 deploy key generated on the PC (`C:\Users\osama\.ssh\kaust_iot_deploy_key`), registered on GitHub as a **read-write** deploy key ("OSRA-PC2025-V2 (build PC, read-write)" — upgraded 2026-07-07 from an initial read-only key, so the PC could commit+push Day-2 evidence files generated on it per the Phase 0-5 plan's Task 26), SSH host alias `github.com-kaust-iot` added to `C:\Users\osama\.ssh\config`. Repo cloned to `C:\Users\osama\Projects\kaust-iot-security-lab`. (gh CLI is NOT installed on the PC — GCM/HTTPS auth doesn't work non-interactively over ssh-mcp, so use this SSH deploy-key path for any future PC git auth needs.)
- **Implementation is happening in a git worktree**: `.claude/worktrees/phase-0-5-implementation` on branch `worktree-phase-0-5-implementation`, via subagent-driven-development. Progress ledger at `.superpowers/sdd/progress.md` (gitignored, local only) — check it first if resuming this work after a compaction/restart.

**Next steps, in order:**
1. Invoke the **writing-plans** skill to turn the approved spec into a step-by-step implementation plan.
2. Build in **phase order** (Workflow B: author on laptop → `git push` → PC `git pull` + `docker compose` via ssh-mcp). **Start at Phase 0** (contracts + repo skeleton + compose networks) per spec §10.

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
