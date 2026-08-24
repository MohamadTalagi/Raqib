# Running Raqib

How to get the platform running on your machine. For what Raqib is and what it
does, see [README.md](README.md).

Everything runs in Docker. You do **not** need Python, Node, PostgreSQL, nmap, or any
scanning tool installed on your machine.

---

## Quick start

**Prerequisites:** Docker Desktop with Compose v2+ (running), ~10 GB free disk space.

```bash
git clone https://github.com/MohamadTalagi/Raqib.git
cd Raqib
```

Then run **one** command for your shell:

| Shell | Start | Stop |
|---|---|---|
| PowerShell (Windows) | `.\scripts\start.ps1` | `.\scripts\stop.ps1` |
| Git Bash / macOS / Linux | `bash scripts/start.sh` | `bash scripts/stop.sh` |

The first run builds ~16 container images and takes several minutes. Later runs start in
under a minute.

When it finishes, open **http://localhost:8080**.

---

## What the start script does

It is idempotent — safe to run on a fresh clone, on an already-running stack, or after a
Docker volume purge. Each step is skipped when it has already been done:

1. Verifies the Docker daemon is reachable.
2. Creates `lab/.env` from `lab/.env.example` if missing.
3. Generates the lab's TLS certificates (`lab/certs/`) via the `cert-init` profile.
4. Creates the secure MQTT broker's password file in its Docker volume.
5. Brings up the stack with **both** compose files
   (`docker-compose.yml` + `docker-compose.dev.yml` — see [Why two compose files](#why-two-compose-files)).
6. Waits for `auditor-api` to report healthy.
7. Seeds the database: device fleet, the 81-guideline NCA catalog, finding mappings, and
   checklists. All four seed steps are idempotent.
8. Prints container status and every reachable URL.

### Options

```bash
bash scripts/start.sh --build      # force a rebuild of the custom images (after a git pull)
bash scripts/start.sh --no-seed    # skip database seeding

bash scripts/stop.sh               # stop containers, KEEP all data
bash scripts/stop.sh --wipe        # also delete volumes — destroys the database
```

PowerShell equivalents: `.\scripts\start.ps1 -Build`, `-NoSeed`, `.\scripts\stop.ps1 -Wipe`.

---

## What you get

| Service | URL | Notes |
|---|---|---|
| **Dashboard** | http://localhost:8080 | The Raqib web UI |
| **API** | http://localhost:8000 | FastAPI; try `/summary`, `/devices`, `/health` |

### Simulated devices

Eight IoT device fixtures, each modelled on a real product with real documented CVEs.
The HTTPS ones use the lab's own test CA, so your browser will warn — that is expected.

| Device | URL | Simulates |
|---|---|---|
| `device-insecure` | http://localhost:8081/ | Hikvision DS-2CD2143G2-I camera |
| `device-partial` | https://localhost:8082/ | Hikvision DS-2CD2143G2-IU camera |
| `device-hardened` | https://localhost:8083/ | Axis M3216-LVE camera |
| `device-smartlock` | http://localhost:8084/ | Yale Conexis L1 smart lock |
| `device-plc-gateway` | http://localhost:8085/health | Schneider Modicon M221 PLC (Modbus TCP on 5020) |
| `device-router-gw` | http://localhost:8086/ | Netgear R7000 router (UPnP/SSDP on 19000/udp) |
| `device-nvr` | http://localhost:8087/ | Dahua NVR4108-8P (RTSP on 5540) |
| `device-speaker` | http://localhost:8088/health | Sonos One Gen 2 (mDNS on 15353/udp) |

`device-plc-gateway` and `device-speaker` serve no page at `/` — use `/health`.

The insecure MQTT broker is published on `localhost:18830`.

---

## Using the dashboard

The sidebar is ordered top-to-bottom as the assessment pipeline. Two ways to drive it:

**Automated** — from Home, click **Start an automated run**. One action runs discovery,
registers newly found devices, fingerprints them, collects compliance evidence, looks up
CVEs, checks post-quantum readiness, and records NCA assessments end to end.

**Manual** — walk the pipeline stage by stage:

1. **Discovery** — sweep the lab subnet, see every live host classified, register the ones you want.
2. **Devices** — the registered fleet; each card shows how far down the pipeline it has reached.
3. **Fingerprinting** — port scans, banner grabs, device identity, MAC vendor lookup.
4. **NCA Compliance** — collect evidence, then assess against CGIoT-1:2024. Automated
   evidence pre-fills a *suggested* status; a human still confirms and signs it.
5. **Vulnerability Intelligence** — device-level CVE lookup by fingerprint (no firmware
   upload needed), or upload a firmware archive for package-level Grype scanning.
6. **Risk Assessment** — a 6-factor weighted score per device, worst-first.
7. **PQC Readiness** — checks TLS key exchange, certificate signatures, and firmware crypto
   against NIST FIPS 203/204/205.
8. **Remediation** — AI-generated fix blueprints (needs a Gemini key, see below).
9. **Executive Summary** — the fleet-wide rollup, exportable as PDF or HTML.

---

## Optional: AI remediation

Stage 8 (AI-Assisted Remediation) needs a Google Gemini API key. It is genuinely optional
— everything else works fully without it.

Get a free key at https://aistudio.google.com ("Get API key" — no billing required), then
edit `lab/.env`:

```
GEMINI_API_KEY=your-key-here
```

Restart the API to pick it up:

```bash
cd lab && docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate auditor-api
```

---

## Everyday operations

All commands run from the `lab/` directory.

```bash
cd lab
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dev.yml"

$COMPOSE ps                       # container status
$COMPOSE logs -f auditor-api      # follow one service's logs
$COMPOSE logs auditor-worker      # the worker runs every scan
$COMPOSE restart auditor-worker   # worker code is bind-mounted; a restart is enough
```

**After pulling new code**, rebuild the images with baked-in code before starting:

```bash
bash scripts/start.sh --build
```

`lab/auditor/api/*.py` and `lab/auditor/web/` are **baked into their images at build time** —
a restart alone will not pick up changes to them. `policies/` and the worker's scan scripts
are bind-mounted, so a restart is enough for those.

### Health check

```bash
curl http://localhost:8000/health     # {"status":"ok"}
curl http://localhost:8000/summary    # evidence/verdict counts, per-device compliance
```

A fuller check exists at `scripts/smoke_test.sh` (add `--fresh` to tear down volumes first —
this destroys your data).

---

## Why two compose files

`docker-compose.yml` alone keeps every service private to the lab's internal Docker
networks, which is correct for a non-development deployment. `docker-compose.dev.yml` is an
overlay that publishes the dashboard, API, and device ports to `localhost` so you can open
them in a browser.

`internal-network` is `internal: true` in the base file, which also blocks Docker Desktop's
host-port-forwarding proxy — so `auditor-api` and `auditor-web` would silently never bind
their published ports without the overlay relaxing it. **Always pass both files.** The
start/stop scripts do this for you.

---

## Troubleshooting

**"Cannot connect to the Docker daemon"** — Docker Desktop isn't running or hasn't finished
starting. Wait for "Engine running".

**Dashboard or API won't load** — you probably ran `docker compose up` without the dev
overlay. Use `scripts/start.sh`, or pass both `-f` flags.

**Devices page or Overview is empty** — the database wasn't seeded. Re-run
`scripts/start.sh` (seeding is idempotent), or seed manually:

```bash
cd lab
docker compose exec -e PYTHONPATH=/work auditor-api python -m policies.engine.seed_devices
docker compose exec auditor-api python -m policies.nca.seed_catalog
docker compose exec auditor-api python -m policies.nca.seed_finding_mappings
docker compose exec auditor-api python -m policies.nca.seed_checklists
```

**Git Bash mangles container paths** — Git Bash rewrites POSIX-looking arguments, so
`-e PYTHONPATH=/work` becomes `C:/Program Files/Git/work` and the seed fails with
`ModuleNotFoundError: No module named 'policies'`. Prefix the command with
`MSYS_NO_PATHCONV=1`, or use the start script, which sets it for you. The same applies to
any `docker run -v volume:/container/path`.

**Port already in use** — something else holds 8080, 8000, 8081-8088, 5020, 5540, 15353,
18830, or 19000. Stop it, or edit the port numbers in `lab/docker-compose.dev.yml`.

**A container keeps restarting or shows "unhealthy"** — check `docker compose logs <service>`.
After a Docker Desktop "Clean / Purge data", the certificate and MQTT-password setup needs
to run again against the fresh volumes; `scripts/start.sh` detects this and redoes it.

**Compose warns the `mqtt-secure-passwd` volume "was not created by Docker Compose"** —
harmless. The password file has to exist before `mqtt-broker-secure` starts, so the script
creates the volume with `docker run` first.

More: `lab/README.md`, and `docs/errors/` — every issue hit during development is logged
there with its root cause and fix.

---

## Repository layout

```
Raqib/
├── scripts/           start.sh / start.ps1 / stop.sh / stop.ps1, smoke_test.sh
├── lab/
│   ├── docker-compose.yml         the 16-service stack, two networks
│   ├── docker-compose.dev.yml     publishes ports to localhost
│   ├── auditor/                   api (FastAPI) · web (React+Vite) · worker (scanners) · db
│   ├── devices/                   8 simulated IoT device fixtures
│   └── certs/                     generated by cert-init (not in git)
├── policies/
│   ├── controls/                  SA-IOT-*.yaml policy-as-code controls
│   ├── nca/                       CGIoT-1:2024 catalog, evaluator, checklists, seeds
│   ├── catalog/                   the scan-test catalog (what each collector runs)
│   ├── engine/                    deterministic policy/verdict engine
│   └── risk/                      the risk-scoring engine
├── document-store/                evidence, raw tool output, firmware, verdicts
├── docs/                          architecture, NCA compliance, risk, PQC, errors
├── INSTALLATION.txt               the long-form manual install guide
└── CLAUDE.md                      full project history and decision log
```

### Networks

Two Docker networks enforce a real trust boundary:

- **`audit-network`** (`172.30.0.0/24`) — every simulated device plus `auditor-worker` and
  `traffic-capture`.
- **`internal-network`** (`172.31.0.0/24`, `internal: true`) — `auditor-api` and
  `auditor-database`, with no route out.

`auditor-worker` is the only service with a leg in both, and the only component that ever
executes a scan. `auditor-api` never runs a command itself — it queues jobs, and the worker
re-validates every device and test against a fixed whitelist before running anything.

---

## Design principles

**AI-assisted, not AI-decided.** Evidence collection and verdict logic are deterministic
Python, reproducible from `(tool, version, command, timestamp, hash)`. LLMs explain and
suggest remediation; they never decide a pass or fail.

**Absence of proof is not proof of compliance.** A control that was never tested is reported
as missing coverage — never assumed to pass.

**Append-only audit trail.** Evidence and assessments are never overwritten. A re-assessment
supersedes the prior record; both stay visible.

---

This is an isolated security training lab. Every "insecure" device is intentionally
vulnerable and confined to the lab's Docker networks — never expose it to a real network.
