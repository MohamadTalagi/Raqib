# Design Spec — Preliminary IoT Security Lab (Standalone Training Sprint)

- **Date:** 2026-07-07
- **Status:** Approved design → ready for implementation planning
- **Owner:** single deliverer (all work delivered by one person to the mentor)
- **Target machine:** the 32 GB home PC (Windows 11) — the laptop has too little free RAM
- **Reference inputs:** `docs/reference/IoTGuard.md`, `docs/reference/CGIoT-1_2024.md`, `First_Task/Pre-liminary Tasks.pdf`

---

## 1. Purpose & framing

This is a **standalone knowledge-test** set by the mentor — a self-contained sandbox that proves we can
(1) build a Dockerized IoT lab, (2) assess it and produce forensic-quality evidence, and (3) codify Saudi
NCA controls as machine-readable policy that yields deterministic verdicts.

It is *informed by* the IoTGuard platform vision and the CGIoT-1:2024 guidelines, but it does **not** need to
plug into the real platform. Optimize for **clear, correct, demonstrable**, not production extensibility.

The whole sprint is one motion done twice: **run the assessment by hand first (to learn it), then automate
it in code (to prove we understood it).** Same tools, same data shapes, both times.

### Guiding principle — AI-assisted, not AI-decided
Evidence collection and verdicts are **deterministic Python**, reproducible from `(tool, version, command,
timestamp, sha256)`. LLMs (Opus 4.8) assist with building and explaining; they never decide a Pass/Fail at
runtime. This keeps the evidence chain rigorous and is a deliberate research talking-point.

---

## 2. Scope

**In scope (the full 11-container architecture, Option A — every container has a real, explainable job):**
`auditor-web`, `auditor-api`, `auditor-worker`, `auditor-database`, `device-insecure`, `device-partial`,
`device-hardened`, `mqtt-broker-insecure`, `mqtt-broker-secure`, `traffic-capture`, `document-store`, across
two Docker networks.

**Out of scope (deferred to the real platform, not this sprint):**
Vulnerability-intel enrichment from live NVD/CISA, dynamic risk scoring, LLM remediation blueprints/exec
summaries (Stages 5–8 of IoTGuard), Celery, RAG, SSDP/mDNS/SNMP/ONVIF fingerprinting, EPSS.

---

## 3. Architecture & networks

Model a real audit: an auditor on an untrusted IoT segment scans the devices and pushes findings to a
separate, protected backend the devices can never reach.

```
HOST (the 32 GB PC): only auditor-web is published -> http://localhost:8080

internal-network 172.31.0.0/24  (TRUSTED backend — no device may enter)
  auditor-web -> auditor-api -> auditor-database (PostgreSQL)
                     \-> document-store (raw evidence + firmware)
  auditor-worker  (dual-homed — the ONLY bridge)

audit-network 172.30.0.0/24  (UNTRUSTED simulated IoT LAN)
  device-insecure  device-partial  device-hardened
  mqtt-broker-insecure  mqtt-broker-secure
  traffic-capture (tcpdump on this segment)
```

### Trust boundaries
- **Host ↔ Lab:** per the brief ("services reachable only inside the lab"), devices/Telnet/MQTT are **not**
  published to the host. Only `auditor-web` is exposed. Day-1 "reach the device / connect to MQTT" is
  demonstrated **from inside the auditor container** (a `docker-compose.dev.yml` may optionally expose device
  ports to localhost for developer convenience; default honors the brief).
- **Untrusted IoT ↔ Trusted backend:** `auditor-worker` is the only dual-homed container. It **pulls** from
  devices and **pushes** to the backend; devices have no route to `auditor-database`/`document-store` and
  cannot initiate inbound. This one-way bridge is the platform's own core defense.

### Default ports
| Container | Port | Host-exposed? |
|---|---|---|
| auditor-web | 8080 | yes |
| auditor-api | 8000 | optional (API docs) |
| device-insecure | 80 (HTTP) | no (lab-only) |
| device-partial | 443 (weak TLS) | no |
| device-hardened | 443 (strong TLS) | no |
| mqtt-broker-insecure | 1883 (plain) | no |
| mqtt-broker-secure | 8883 (TLS) | no |
| device Telnet-like | 23 | no |

---

## 4. Device profiles & hybrid services

**One FastAPI "smart-camera" image, three configurations** driven by env vars + mounted config + compose
profiles (the difference between secure and insecure is *data, not code*).

Config toggles: `TRANSPORT=http|https`, `TLS_PROFILE=none|weak|strong`, `ENABLE_TELNET`, `CREDENTIALS=default|strong`,
`EXPOSE_API_KEY`, `LOGGING=off|basic|security`, `MQTT_TARGET=insecure|secure`, `FIRMWARE_SIGNED`, `PRIVACY_DOC=<path>`.

| Feature | A (insecure) | B (partial) | C (hardened) |
|---|---|---|---|
| Transport | plain HTTP | HTTPS, weak cert | HTTPS only, strong cert |
| Telnet | on (23) | removed | removed |
| Credentials | admin/admin | changed, weak-ish | strong + unique |
| MQTT | plaintext → insecure broker | plaintext → insecure broker | TLS → secure broker |
| API key | hard-coded, leaks via /config | not exposed | secret, not exposed |
| Software component | outdated (Grype flags) | mixed | updated |
| Logging | off/minimal | some | full security logging |
| Firmware pkg | unsigned + outdated | present but unsigned | signed + verified |
| Privacy/retention doc | missing retention | incomplete | complete + deletion evidence |

### Shared FastAPI endpoints (satisfy Day-1 list; behavior gated by config)
- `GET /` login page · `POST /login` (accepts admin/admin only on A)
- `GET /api/device/info` device metadata · `GET|POST /api/config` (leaks API key on A)
- `GET /api/firmware/version` · `GET /api/admin/reset` (unauthenticated on A) · `GET /privacy`

### Hybrid real-vs-simulated (approach C)
Real: FastAPI HTTP, TLS via generated certs (weak=1024-bit/SHA-1/old TLS; strong=2048+/SHA-256/TLS1.2–1.3),
`eclipse-mosquitto` (plaintext 1883 and TLS 8883), an outdated real dependency for Grype.
Simulated: only the low-value "Telnet-like" banner listener (Device A).

---

## 5. Data contracts (the spine)

Chain: **test → evidence → control → verdict.** The connective tissue is a structured **`observations`**
object on every evidence record; controls test *those keys*. Conditions are **structured (field/op/value),
never executable code** — no `eval`, fully deterministic.

### Evidence record (Day-2 output) — 10 required fields + `test_id` + `observations`
```json
{
  "evidence_id": "EV-2026-07-08-0007",
  "device_id": "device-insecure",
  "test_id": "TEST-NET-PORTSCAN",
  "tool": "nmap",
  "tool_version": "7.94",
  "command": "nmap -sV -p- device-insecure",
  "timestamp": "2026-07-08T10:15:32Z",
  "finding": "Telnet (23/tcp) open; plaintext management exposed",
  "observations": { "open_ports": [23, 80, 1883], "telnet_open": true },
  "raw_output_path": "document-store/raw/EV-2026-07-08-0007.txt",
  "confidence": "high",
  "sha256": "3f2a…e91"
}
```

### YAML control (Day-3 policy) — all brief fields; structured conditions
```yaml
control_id: SA-IOT-002
title: No default or hard-coded credentials
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-2-2"
    clause: "Prevent the users from using default and hard-coded passwords."
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-AUTH-DEFAULT-CREDS
automated_test_ids: [TEST-AUTH-DEFAULT-CREDS]
severity: high
conditions:
  pass:         { field: "observations.default_creds", op: "equals", value: false }
  fail:         { field: "observations.default_creds", op: "equals", value: true }
  partial:      null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Force a unique strong password on first boot; remove all vendor defaults."
```

### Verdict (engine output)
```json
{
  "verdict_id": "VD-2026-07-08-0003",
  "control_id": "SA-IOT-002",
  "device_id": "device-insecure",
  "status": "FAIL",
  "severity": "high",
  "evidence_ids": ["EV-2026-07-08-0007"],
  "matched": "fail",
  "reason": "observations.default_creds == true",
  "saudi_source": "CGIoT-1:2024 §2-2-2",
  "remediation": "Force a unique strong password on first boot; remove all vendor defaults.",
  "timestamp": "2026-07-08T10:16:04Z"
}
```
Engine matches conditions in order **fail → partial → pass → inconclusive**. A verdict cites its evidence,
which cites raw output + hash + exact command → full reproducible audit trail.

### The 5 Day-3 controls mapped to Saudi sources
| Control | Covers | CGIoT-1:2024 anchor |
|---|---|---|
| SA-IOT-001 | Device identification | 2-1-1 (asset inventory) |
| SA-IOT-002 | Default credentials | 2-2-2 |
| SA-IOT-003 | Unnecessary services | 2-15-2 + Appendix A #3 |
| SA-IOT-004 | Insecure protocols | 2-4-3 |
| SA-IOT-005 | TLS / secure comms | 2-7-2 |

Acceptance falls out for free: SA-IOT-002 → **FAIL** on `device-insecure`, **PASS** on `device-hardened`.

---

## 6. The test catalog (connective tissue)

Each `test_id` = one probe (tool + the `observations` it produces). Run manually on Day 2, automated on Day 3.

| test_id | Tool (real) | Produces observations | Feeds |
|---|---|---|---|
| TEST-DEVICE-ID | nmap + /api/device/info | vendor, model, mac, device_type | SA-IOT-001 |
| TEST-NET-PORTSCAN | nmap -sV -p- | open_ports[], telnet_open | SA-IOT-003 |
| TEST-AUTH-DEFAULT-CREDS | curl login admin/admin | default_creds | SA-IOT-002 |
| TEST-ADMIN-UNAUTH | curl admin endpoint, no auth | admin_unauthenticated | SA-IOT-003 |
| TEST-HTTP-HEADERS | curl -I | missing_security_headers[] | supporting |
| TEST-TLS-CONFIG | openssl / sslscan | tls_version, weak_cipher, cert_bits | SA-IOT-005 |
| TEST-MQTT-OPEN | mosquitto_sub | mqtt_anonymous, mqtt_tls | SA-IOT-004 |
| TEST-FW-SECRETS | strings/grep/YARA | hardcoded_secret, api_key_found, private_key_present | firmware |
| TEST-FW-SBOM | syft + grype | outdated_packages[], cve_list[] | firmware |
| TEST-PRIVACY-DOC | doc parser | retention_present, deletion_evidence | privacy |

---

## 7. Simulated firmware & analysis

A short **generator** stamps out three archives matching the three device postures (consistent, reproducible,
same hashes on regen).

`camera-fw-<ver>.tar.gz` contents: `VERSION`, `etc/config.ini` (hard-coded password + embedded api_key),
`certs/device.key` (shipped private key), `certs/device.crt`, `manifest.json` (outdated packages → SBOM
source), `update.sh` (insecure: HTTP download, no sig check), `firmware.sig` (valid only on hardened).

| Variant | Version | Secrets | Packages | Signature |
|---|---|---|---|---|
| A insecure | old | password+api_key+private key | outdated (CVEs) | none |
| B partial | mid | some removed | mixed | present but invalid/unsigned |
| C hardened | current | none | updated | valid (verified by update.sh) |

Analysis: `file` (identify) → `strings`/`grep` (candidate secrets) → **YARA** `rules/iot_secrets.yar`
(HardcodedPassword, EmbeddedAPIKey, PrivateKeyFile) → **Syft** (SBOM) → **Grype** (CVEs) → plus an
`openssl` signature check (`firmware_signed`, `signature_valid`). Yields 4+ firmware findings.

---

## 8. Threat model & diagrams (Day-1 artifacts)

Diagrams in **Mermaid** (text-based, git-friendly) under `docs/architecture/`: an architecture diagram
(11 containers, 2 networks, ports) and a trust-boundary diagram (worker as sole bridge; web as sole host
surface).

### STRIDE — each threat maps to a real built feature; mitigation = what makes Device C hardened
| STRIDE | Threat (against the device) | Shown by | Mitigation → Device C |
|---|---|---|---|
| Spoofing | anonymous MQTT publish; admin/admin login | insecure MQTT, Device A creds | MQTT-TLS+auth; strong creds |
| Tampering | plaintext MITM; unsigned firmware accepted | Device A/B transport, unsigned update.sh | TLS; signed firmware verified |
| Repudiation | missing/weak logging | Device A LOGGING=off | security logging + retention |
| Info disclosure | hard-coded key/private key; /config leak; telnet plaintext | TEST-FW-SECRETS, /api/config, telnet | no secrets in images; disable telnet; TLS |
| DoS | unnecessary exposed services; no login rate-limit | open telnet/ports | remove services; rate-limit |
| Elevation of privilege | unauthenticated admin endpoint | TEST-ADMIN-UNAUTH | authz on admin routes |

Platform's own defense = the trust boundaries in §3 (network segregation, one-way worker bridge, single host surface).

---

## 9. Repository layout

```
lab/
  docker-compose.yml            # all 11 services, 2 networks, health checks
  docker-compose.dev.yml        # optional host-port exposure for dev
  .env.example                  # profile toggles
  README.md                     # start/stop the lab
  devices/smart-camera/         # one FastAPI image, 3 configs
    Dockerfile · app/ · profiles/{insecure,partial,hardened}.env · docs/privacy_*.md
  telnet-sim/                   # simulated telnet banner listener (A only)
  mqtt/{insecure,secure}/       # real mosquitto configs (+ TLS certs)
  auditor/
    api/                        # FastAPI: devices/evidence/verdicts
    worker/                     # test-catalog runner + engine invocation
      Dockerfile                # nmap, openssl, mosquitto-clients, yara, syft, grype
      tests/                    # one module per test_id
      firmware/                 # generator + rules/iot_secrets.yar
    web/                        # Flutter Web (Dart) — built LAST
    db/                         # init.sql / migrations
  policies/
    controls/                   # SA-IOT-001..005.yaml
    engine/policy_engine.py     # load control + evidence -> verdict
    schema/                     # evidence + control + verdict schemas
  document-store/               # raw tool output + firmware (hashed)
  certs/                        # generated CA + weak/strong device certs
```

---

## 10. Build order

Contracts first → graded core next → full architecture → Flutter last (so time pressure cuts the dashboard,
never the graded work). **Phases 0–5 alone form a complete gradeable submission covering all three days.**

| Phase | Builds | Maps to |
|---|---|---|
| 0 Contracts | repo skeleton, compose networks, .env, evidence/control/verdict schemas | foundation |
| 1 Lab core | smart-camera (insecure), Dockerfile, compose w/ 2 nets + health checks, telnet-sim, insecure MQTT | Day-1 acceptance |
| 2 Profiles + TLS | device-partial, device-hardened, secure MQTT, cert generation | 3 profiles |
| 3 Day-1 artifacts | Mermaid diagrams, STRIDE, device inventory, README | Day-1 output |
| 4 Manual assessment | worker toolbox image, run catalog by hand, firmware generator + YARA, ≥8 evidence records | Day-2 output |
| 5 Policy-as-code | 5 YAML controls + verdict engine; Pass on hardened / Fail on insecure | Day-3 output |
| 6 Automation backend | auditor-api + auditor-database + document-store; worker writes via API | full architecture |
| 7 Dashboard | auditor-web (Flutter/Dart), thin: inventory/evidence/verdicts | full architecture |
| 8 Polish & demo | all 11 up, end-to-end run, final README, acceptance tests green | delivery |

---

## 11. Acceptance criteria (from the brief)

- **Day 1:** working compose env; ≥1 device; ≥3 exposed services (inside lab); network diagram; threat model;
  device inventory; README. Demonstrate: reach device web UI, connect to MQTT, detect ≥3 open ports, view
  simulated metadata (from the auditor container).
- **Day 2:** ≥8 manual findings (default creds, exposed insecure service, unencrypted protocol, hard-coded
  secret, outdated package, weak/missing TLS, missing logging, missing privacy/update evidence). Each shows
  raw output → structured evidence → interpretation → remediation.
- **Day 3:** ≥2 controls produce correct Pass and Fail verdicts across different device configs; working
  demo device → test → evidence JSON → YAML policy → verdict JSON.

---

## 12. Decisions log

1. Standalone project, one combined spec, three internal parts (Day 1/2/3).
2. Option A — full 11-container architecture; every container earns a real job.
3. `auditor-web` = Flutter Web (Dart), scoped thin, built last (lowest priority; cuttable).
4. Assessment done manually first, then automated by `auditor-worker`/`auditor-api` → Flutter UI.
5. Service realism = hybrid (approach C): real MQTT/TLS/outdated-package; simulate only Telnet-like.
6. Deterministic Python for evidence + verdicts; LLM assists but never decides ("AI-assisted, not AI-decided").
7. Target machine = the 32 GB PC; compose profiles allow running subsets; document-store kept lightweight.
8. All work delivered by a single person; no team-split needed.

---

## 13. Operational prerequisite (separate track)

Building happens on the 32 GB PC. Before implementation, set up remote control per
`setup/ssh-mcp/` (enable OpenSSH on the PC, key auth, Tailscale-only). At that boundary, first check whether
the existing `ssh-pi` MCP can host the Windows PC as a second server (reuse, no new MCP) before falling back
to the dedicated `ssh-mcp`. This is bundled with the Opus→Sonnet switch (adding an MCP needs a Claude restart).
```
