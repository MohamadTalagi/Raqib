# Phases 6-8 — Platform Completion Design (auditor-api, auditor-database, auditor-web, traffic-capture)

**Date:** 2026-07-08
**Status:** Approved (brainstorming session), ready for implementation planning
**Builds on:** `docs/superpowers/specs/2026-07-07-preliminary-iot-security-lab-design.md` (Phases 0-5, complete and merged to `main`)

---

## 1. Context

Phases 0-5 delivered a complete, gradeable submission: the 3-device lab, 2 MQTT brokers, manual Day-2 evidence
collection (12 real entries), and Day-3 policy-as-code (5 controls, deterministic verdict engine, 8 real
verdicts). Evidence and verdicts currently live as flat JSON files under `document-store/`, written directly
by `lab/auditor/worker/tests/record_evidence.py` and `policies/engine/generate_verdicts.py`.

The original design spec's Build Order (§10) reserved three phases for the parts of the full 11-container
architecture that weren't required for grading:

| Phase | Builds | Maps to |
|---|---|---|
| 6 | `auditor-api` + `auditor-database` + `document-store` integration; worker writes via API | full architecture |
| 7 | `auditor-web` (Flutter Web), thin: inventory/evidence/verdicts | full architecture |
| 8 | Polish & demo — all containers up, end-to-end run, final README | delivery |

This spec fills in the concrete design for those three phases, which the original spec only sketched at a
one-line-per-phase level.

---

## 2. Scope

**In scope:**
- `auditor-api` — FastAPI service exposing evidence, verdicts, controls, devices, and a summary endpoint.
- `auditor-database` — PostgreSQL, two tables (`evidence`, `verdicts`), schema created via plain `init.sql`.
- Adapting `record_evidence.py` and `generate_verdicts.py` to `POST` to the API instead of writing files
  directly (raw tool output stays on disk under `document-store/raw/`, unchanged).
- A one-time migration script that loads the 12 existing evidence + 8 existing verdict JSON files into the
  new database, so Phase 0-5's history is preserved.
- `auditor-web` — Flutter Web, 4 screens (Overview, Devices, Evidence, Verdicts), dark security-console style.
- `traffic-capture` — a `tcpdump`-based container on `audit-network`, the one architectural piece from the
  original 11-container list that was never built in Phases 0-5.
- Wiring all of the above into `lab/docker-compose.yml`, plus an updated `lab/README.md` and an end-to-end
  PC-verified acceptance demo.

**Out of scope (unchanged from the original spec, still deferred to the real platform):**
Vulnerability-intel enrichment (NVD/CISA/EPSS), dynamic risk scoring, LLM remediation blueprints/executive
summaries, Celery, RAG, SSDP/mDNS/SNMP/ONVIF fingerprinting, user authentication (see §4), a controls table
in the database (controls stay YAML — see §4), any state-management library for Flutter (see §5).

---

## 3. Architecture & Data Flow

```
internal-network (trusted, unchanged from Phase 0-5)
  auditor-web (Flutter Web, :8080, host-exposed — the only published port, as before)
       │ HTTP GET (read-only)
       ▼
  auditor-api (FastAPI, :8000)
       │ reads/writes evidence + verdicts
       ▼
  auditor-database (PostgreSQL) ── evidence, verdicts tables

  auditor-api also reads policies/controls/*.yaml directly at request time
  (no DB copy of controls, no drift between git and the database)

  auditor-worker (dual-homed: audit-network + internal-network, unchanged)
       │ runs the same test catalog against devices (docs/../run_catalog.md, unchanged), THEN
       │ POST /evidence, POST /verdicts  — replaces direct json.dump() to document-store/
       ▼
  auditor-api ──validates against the same evidence/verdict JSON schemas──▶ auditor-database
       │
       └─ raw tool output (nmap/curl/openssl transcripts, firmware archives) still written
          straight to document-store/raw/ on disk by the worker — this part is unchanged

audit-network (untrusted, unchanged)
  device-insecure  device-partial  device-hardened
  mqtt-broker-insecure  mqtt-broker-secure  telnet-sim
  traffic-capture (NEW — tcpdump on this segment, writes .pcap to document-store/)
```

Nothing about the existing trust boundary changes: `auditor-worker` remains the only dual-homed container,
`internal-network` remains `internal: true`, and `auditor-web` remains the only service published to the
host.

---

## 4. `auditor-api`

**No authentication.** `internal-network` is already the trust boundary, and `auditor-web` is the only
client — adding login/tokens/roles would be scope for a multi-tenant product, not this lab.

**Endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/evidence` | Validate against `evidence.schema.json`, insert into `evidence` table |
| `GET` | `/evidence` | List, optional `?device_id=` / `?test_id=` filters |
| `GET` | `/evidence/{evidence_id}` | Single record, 404 if missing |
| `POST` | `/verdicts` | Validate against `verdict.schema.json`, insert into `verdicts` table |
| `GET` | `/verdicts` | List, optional `?control_id=` / `?device_id=` filters |
| `GET` | `/verdicts/{verdict_id}` | Single record, 404 if missing |
| `GET` | `/controls` | Read all 5 YAML files from `policies/controls/`, return as JSON |
| `GET` | `/controls/{control_id}` | Single control, 404 if the file doesn't exist |
| `GET` | `/devices` | `SELECT DISTINCT device_id FROM evidence`, with per-device evidence/verdict counts |
| `GET` | `/summary` | Aggregate counts for the Overview screen (total evidence, verdicts by status) — computed on read, never stored |

**Controls stay as YAML files** — no `controls` table. This keeps the policy-as-code principle from Phase 5
intact (controls are version-controlled, auditable text, not database rows that can drift from git).

---

## 5. `auditor-database`

PostgreSQL. Schema created via a single `auditor/db/init.sql`, auto-executed by Postgres's standard
`docker-entrypoint-initdb.d` mechanism on first container start. No migration framework — this is lab-scale,
matching the project's existing "5 things only" tooling philosophy.

```sql
CREATE TABLE evidence (
    evidence_id      TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    test_id          TEXT NOT NULL,
    tool             TEXT NOT NULL,
    tool_version     TEXT NOT NULL,
    command          TEXT NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL,
    finding          TEXT NOT NULL,
    observations     JSONB NOT NULL,
    raw_output_path  TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    sha256           TEXT NOT NULL
);

CREATE TABLE verdicts (
    verdict_id       TEXT PRIMARY KEY,
    control_id       TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    status           TEXT NOT NULL,
    severity         TEXT NOT NULL,
    evidence_ids     JSONB NOT NULL,
    matched          JSONB,
    reason           TEXT NOT NULL,
    saudi_source     JSONB NOT NULL,
    remediation      TEXT NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL
);
```

No `devices` table (derived via `DISTINCT device_id` on `evidence` — avoids a second source of truth that
could drift). No `controls` table (§4).

**Migration of Phase 0-5 history:** a one-time script (`policies/engine/migrate_existing_evidence.py` or
similar, exact name decided at planning time) reads every file under `document-store/evidence/*.json` and
`document-store/verdicts/*.json` and `POST`s it to the running API, so the 12 real evidence entries and 8
real verdicts collected during Phase 0-5 land in the database rather than being silently orphaned.

---

## 6. `auditor-web` (Flutter Web)

**State management: deliberately minimal.** The team has zero prior Flutter/Dart experience (noted as an
open question in `CLAUDE.md` §9). Given this dashboard is thin and mostly read-only, the design uses the
`http` package for API calls, `FutureBuilder` per screen, and plain `StatefulWidget` local state — no
Provider/Riverpod/Bloc. Keeping the state-management surface small matters more here than idiomatic-Flutter
polish, since whoever maintains this after the sprint needs to be able to read it.

**Navigation:** a `NavigationRail` (left-side rail, standard for desktop/web dashboards) with 4 destinations.

**Screens:**

1. **Overview** — stat cards from `GET /summary`: total evidence count, verdict counts by status
   (Pass/Fail/Partial/Inconclusive), quick links into the other 3 screens.
2. **Devices** — list from `GET /devices`, each row showing evidence/verdict counts; tapping a device filters
   the Evidence and Verdicts screens to it.
3. **Evidence** — table from `GET /evidence` (filterable by device/test), row tap opens a detail panel:
   finding, tool, command, confidence, raw output path, observations.
4. **Verdicts** — table of control × device showing status, tap opens detail: reason, `saudi_source`,
   remediation text.

**Visual design — dark security-console style** (chosen over a light enterprise theme to signal
"practitioner tool," and over a light-first-then-dark-toggle approach to keep scope thin):

| Token | Value | Use |
|---|---|---|
| Background | `#0F172A` (slate-900) | App background |
| Surface/card | `#1E293B` (slate-800) | Cards, table rows |
| Primary text | `#F1F5F9` | Body text (contrast-checked against background) |
| Muted text | `#94A3B8` | Secondary/meta text |
| Accent | `#22D3EE` (cyan) | Nav rail, links, interactive elements — single accent, not scattered |
| Status: Pass | `#4ADE80` (green) | Verdict/status chips only |
| Status: Fail | `#F87171` (red) | Verdict/status chips only |
| Status: Partial | `#FBBF24` (amber) | Verdict/status chips only |
| Status: Inconclusive | `#94A3B8` (gray) | Verdict/status chips only |
| Font (technical) | JetBrains Mono or similar | Evidence/verdict IDs, hashes, timestamps |
| Font (body) | Inter or similar | Everything else |

No emoji icons anywhere — Material Icons (already bundled with Flutter) throughout, consistent sizing.

---

## 7. `traffic-capture`

A minimal container running `tcpdump` on `audit-network`, capturing traffic to `.pcap` files under
`document-store/raw/` (or a dedicated `document-store/pcap/` subdirectory — exact path decided at planning
time). This is the one piece of the original 11-container architecture (spec §2, §9) that Phases 0-5 never
built. It requires no application code, just a Dockerfile (a small image with `tcpdump` installed) and a
compose service definition with appropriate capabilities (`NET_ADMIN` or similar) to capture on the bridge
network.

---

## 8. Testing

TDD throughout, matching the practice established in Phases 0-5:

- **`auditor-api`:** pytest + FastAPI `TestClient`, one test module per endpoint group — schema validation
  (bad payloads rejected), filtering, 404 handling.
- **`auditor-database`:** integration tests against a real, throwaway Postgres instance (via a `docker
  compose` test override), not mocks — this project's established pattern is to hit the real dependency
  (see `[[error-log-convention]]`-adjacent practice from Phases 0-5's evidence recording tests).
- **Worker adapter:** verify `record_evidence.py`/`generate_verdicts.py` `POST` correct, schema-valid
  payloads against a real test instance of the API — not a mock of the HTTP layer.
- **`auditor-web`:** Flutter widget tests per screen, with a fake/injected HTTP client (Flutter's standard
  `http.Client` is trivially fakeable without a mocking framework).
- **End-to-end:** PC-verified via ssh-mcp, same pattern as every prior phase — bring the full stack up,
  confirm the dashboard shows real data end-to-end.

---

## 9. Decisions Log

1. Full original Build Order followed (Phase 6 backend → Phase 7 dashboard → Phase 8 polish), not a reduced
   scope — Phases 0-5 already satisfy grading requirements on their own, so this round is explicitly the
   "complete the architecture" round.
2. Worker moves from direct file writes to API calls for structured data; raw tool output stays on disk
   under `document-store/raw/`, unchanged.
3. `auditor-api` has no authentication — network position (internal-network) is the real control, matching
   the security model already established in Phases 0-5.
4. Controls remain YAML files, read live by the API — no database copy, avoiding schema/git drift.
5. No `devices` table — derived via `DISTINCT device_id` on `evidence`, avoiding a second source of truth.
6. Flutter dashboard uses plain `http` + `FutureBuilder`, no state-management library — deliberately simple
   given the team's zero prior Flutter experience.
7. Dark security-console visual style chosen over light-enterprise, to read as a practitioner tool.
8. Plain `init.sql` for the database schema, no migration framework — matches the project's lab-scale
   tooling philosophy.
9. Existing Phase 0-5 evidence/verdict JSON files are migrated into the database via a one-time script, not
   discarded.
