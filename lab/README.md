# KAUST IoT Security Lab

A Dockerized 3-posture smart-camera lab (insecure / partially hardened / hardened) plus a
manual-assessment toolbox, used to produce evidence for Saudi NCA (CGIoT-1:2024) policy verdicts.

## Prerequisites
- Docker Desktop with Compose v2 (verified: Docker 29.x, Compose v5 on the build PC).
- Run everything from this `lab/` directory.

## First-time setup (once per clone)

```
docker compose --profile init run --rm cert-init
docker run --rm -v kaust-iot-lab_mqtt-secure-passwd:/mosquitto/config eclipse-mosquitto:2 mosquitto_passwd -c -b /mosquitto/config/passwd labworker "LabWork3r-Secr3t!"
docker run --rm -v kaust-iot-lab_mqtt-secure-passwd:/mosquitto/config alpine chmod 644 /mosquitto/config/passwd
```

## Start the lab

```
docker compose up -d --build
docker compose ps    # wait until all services report healthy
```

## Stop the lab

```
docker compose down
```

## Notes
- No device or broker port is published to the host by default — everything is reachable only
  from inside `audit-network`/`internal-network`, matching the training brief. Use
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` if you want all three device
  profiles and `mqtt-broker-insecure` exposed to `localhost` for manual poking around:
  - `device-insecure` → http://localhost:8081/
  - `device-partial` → https://localhost:8082/ (weak self-signed cert — expect a browser warning)
  - `device-hardened` → https://localhost:8083/ (strong self-signed cert — still a browser warning,
    since it's a lab test CA rather than a publicly trusted one, but the cert itself is 2048-bit/SHA-256)
  - Each device serves a minimal `/dashboard` page (device info, config, an admin-reset button) in
    addition to the JSON API endpoints — see it live to compare postures side by side.
- To probe the lab from the audit network without a published port, run a throwaway container
  attached to it, e.g.:
  `docker run --rm --network kaust-iot-lab_audit-network nicolaka/netshoot nmap -sV device-insecure`
- All "insecure" behavior (default creds, hardcoded API key, plaintext MQTT, unsigned firmware) is
  an intentional training fixture inside this sandboxed, non-internet-facing lab.

## Full Stack (Phases 6-8)

Beyond the Day-1/2/3 core, the lab now includes:

- **auditor-database** (PostgreSQL) — stores devices, assessments, scan jobs, evidence, verdicts,
  and the NCA CGIoT-1:2024 compliance module's own tables. Schema auto-created on first boot from
  `lab/auditor/db/init.sql`; existing volumes are brought up to date via the numbered files in
  `lab/auditor/db/migrations/` (see "Migrations" below).
- **auditor-api** (FastAPI, `:8000` internal / `:8000` host-published via `docker-compose.dev.yml`) — REST
  API for devices, assessments, scan jobs, evidence, verdicts, controls, NCA compliance, and per-device
  reports (PDF/HTML/JSON). No authentication (network-isolated).
- **auditor-worker** — polls `auditor-api` for pending scan jobs and is the only thing that ever runs a
  real collector command (nmap/curl/openssl/mosquitto_sub/tcpdump/...) against a live device or parses a
  firmware archive.
- **auditor-web** (React + Vite + TypeScript, `:8080` host-published) — the dashboard. Open
  http://localhost:8080 after bringing the stack up.
- **traffic-capture** — `tcpdump` on `audit-network`, writes `.pcap` files to `document-store/pcap/`.

### Application features (dashboard)

- **Devices** — register/deregister a device and its exposed services, upload/remove a firmware
  archive.
- **Run Scan** — pick a device and one or more whitelisted tests; launching creates a real
  **Assessment** (`POST /assessments`) grouping the batch under one id with an aggregate status
  (`queued` → `running` → `completed`/`partially_completed`/`failed`, or `cancelled`), visible as a
  status bar with a Cancel button. Each individual test still goes through its own job card to read
  the collector's raw output/observations and record a human-typed finding as evidence.
- **Evidence** / **Verdicts** / **Controls** — browse recorded evidence, computed verdicts (including
  `NOT_APPLICABLE` for controls that genuinely can't apply to a device's registered services, and
  conflict-flagged verdicts when two evidence records disagree), and the 5 `SA-IOT-*` control
  definitions. "Recompute verdicts" is idempotent — safe to click repeatedly.
- **NCA Compliance** — a separate, additive module (`policies/nca/`) covering all 81 real
  CGIoT-1:2024 guidelines with its own device/organizational assessments, evidence, and exceptions.
  See `docs/nca-compliance.md`.
- **Device reports** — `GET /devices/{id}/report.pdf` (WeasyPrint), `.html`, and `.json` — same
  underlying `build_report_model()`, covering device profile, scope, methodology, control results
  (with policy version and conflict flags), controls not yet assessed, evidence provenance, and a
  not-an-official-certification disclaimer.

### Bring up the full stack

```
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

### One-time seeding, on a fresh clone

Run **both** of these once, in this order. Skipping the first leaves the dashboard with an empty
device list, which looks broken rather than empty.

**1. Seed the six lab devices** into the `devices` / `device_services` tables:

```
docker compose exec -e PYTHONPATH=/work \
  -e DATABASE_URL=postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor \
  auditor-api python -m policies.engine.seed_devices
```

Expected: `Seeded 6 devices`. Running it again prints `Seeded 0 devices` — it is idempotent, so it is
safe to re-run, and it will also restore service rows if they are ever lost.

Note this runs in **auditor-api**, not `auditor-worker`. The worker talks to the API over HTTP and has
no PostgreSQL driver installed; the seeder writes to the database directly.

**2. Load the recorded evidence and verdicts** from `document-store/evidence/*.json` and
`document-store/verdicts/*.json`:

```
docker compose exec auditor-worker sh -c "cd /work && python -m policies.engine.migrate_existing_records"
```

This one *does* run in the worker — it POSTs to `auditor-api` rather than touching the database.

### Migrations (existing volumes only — fresh clones get all of this from `init.sql`)

Postgres only runs `init.sql` on a **fresh** volume (see `docs/errors/021`); an already-initialized
one needs each numbered migration applied by hand once:

```
docker exec -i kaust-iot-lab-auditor-database-1 psql -U auditor -d auditor < lab/auditor/db/migrations/002-devices-firmware-columns.sql
docker exec -i kaust-iot-lab-auditor-database-1 psql -U auditor -d auditor < lab/auditor/db/migrations/003-nca-compliance.sql
docker exec -i kaust-iot-lab-auditor-database-1 psql -U auditor -d auditor < lab/auditor/db/migrations/004-assessments-and-evidence-fields.sql
```

All three are idempotent — safe to re-run.

### Verify

- Dashboard: http://localhost:8080 — Devices should list six devices, and Overview should show
  non-zero evidence/verdict counts.
- API directly: http://localhost:8000/summary should return non-zero `total_evidence`/`total_verdicts`
  and a `verdicts_by_status` breakdown across `PASS`/`FAIL`/`PARTIAL`/`INCONCLUSIVE`/`NOT_APPLICABLE`
  (exact numbers aren't pinned here since they grow as more scans are recorded).
- Clean-deployment smoke test: `bash scripts/smoke_test.sh` from the repo root brings the stack up
  and asserts every health-checked service reports healthy plus a few HTTP endpoints respond.

### A note on where data lives

Evidence recorded through the dashboard's **Run Scan** flow is written to the database only — it does
not create a `document-store/evidence/*.json` file. So a database can drift ahead of what a fresh clone
would reproduce. If you record new evidence you want other clones to have, export it from
`GET /evidence/{id}` into `document-store/evidence/` and commit it alongside its raw output file.
