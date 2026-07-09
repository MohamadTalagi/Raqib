# Phases 6-8 Acceptance Verification

Builds on `docs/architecture/phases-0-5-acceptance.md` (Phases 0-5, already merged to `main`). This document
covers Phase 6 (backend: `auditor-api` + `auditor-database`), Phase 7 (Flutter dashboard `auditor-web`), and
Phase 8 (`traffic-capture` + full-stack integration).

## Phase 6: Backend

- [x] `auditor-database` (PostgreSQL 16) — schema auto-created from `lab/auditor/db/init.sql`
  (`evidence`, `verdicts` tables, 4 indexes), verified via `docker compose exec auditor-database psql -U
  auditor -d auditor -c "\dt"` showing both tables.
- [x] `auditor-api` (FastAPI, no auth) — every endpoint implemented and PC-verified against the real,
  running container (not just unit tests):
  - `GET /health` → `{"status":"ok"}`
  - `POST /evidence`, `GET /evidence`, `GET /evidence/{id}` — schema-validated against
    `policies/schema/evidence.schema.json`; PC-verified `POST` returns 201 with correct echoed JSON,
    `GET` by id and by `?device_id=` filter both correct.
  - `POST /verdicts`, `GET /verdicts`, `GET /verdicts/{id}` — schema-validated against
    `policies/schema/verdict.schema.json`; PC-verified round-tripping including a UTF-8 `§` character in
    `saudi_source`.
  - `GET /controls`, `GET /controls/{id}` — reads live from `policies/controls/*.yaml` (no DB copy);
    PC-verified all 5 real controls served correctly through the real container mount. `GET
    /controls/{id}` rejects invalid `control_id` characters (regex `^[A-Za-z0-9\-]+$`) with 400 before any
    filesystem access, closing a path-traversal gap caught in review (Task 5).
  - `GET /devices`, `GET /summary` — derived via SQL (`DISTINCT`/`UNION`, no `devices` table); PC-verified
    correct aggregate counts.
- [x] Worker adapters — `record_evidence.py` and `generate_verdicts.py` now `POST` to `auditor-api` instead
  of writing files directly (raw tool output still goes to `document-store/raw/`, unchanged). PC-verified
  end-to-end: two back-to-back `record_evidence.py` invocations inside the real `auditor-worker` container
  produced distinct sequential `evidence_id`s (no collision — see ERR-014), and a real
  evidence→`generate_verdicts.py`→database round trip produced correct `SA-IOT-002` FAIL/PASS verdicts.
- [x] Migration — `policies.engine.migrate_existing_records` run for real on the PC against the actual 12
  evidence + 8 verdict JSON files from Phase 0-5: `Migrated 12 evidence records and 8 verdicts`. Confirmed
  via `GET /summary`: `{"total_evidence": 12, "total_verdicts": 8, "verdicts_by_status": {"PASS": 4,
  "FAIL": 4, "PARTIAL": 0, "INCONCLUSIVE": 0}}` — every number matches Phase 0-5's original acceptance
  result exactly, confirming the migration preserved history without loss or alteration.

Deterministic policy engine (`policies/engine/policy_engine.py`, unchanged since Phase 0-5) still has no
`eval`/`exec` — `grep -n "eval(\|exec(" policies/engine/policy_engine.py` → clean.

## Phase 7: Frontend (`auditor-web`, Flutter Web)

- [x] Dark security-console theme (`lib/theme.dart`) — all 9 design tokens verified exact against the
  approved spec (`#0F172A` background, `#1E293B` surface, `#F1F5F9`/`#94A3B8` text, `#22D3EE` accent,
  `#4ADE80`/`#F87171`/`#FBBF24`/`#94A3B8` status colors).
- [x] `NavigationRail` shell with 4 destinations (Overview, Devices, Evidence, Verdicts), each backed by a
  real API call via an injectable `ApiClient` (added specifically so widget tests don't make real network
  calls — see the Task 13 fix below).
- [x] **Overview** — stat cards from `GET /summary` (total evidence, total verdicts, per-status counts).
- [x] **Devices** — list from `GET /devices` (device_id, evidence/verdict counts).
- [x] **Evidence** — list + detail dialog from `GET /evidence` (finding, tool, confidence, raw output path).
- [x] **Verdicts** — list with status-colored avatars + detail dialog from `GET /verdicts` (reason,
  `saudi_source` formatted as "framework §reference", remediation).
- [x] `Dockerfile` (multi-stage: `ghcr.io/cirruslabs/flutter:stable` build → `nginx:alpine` serve),
  published at `:8080` in `lab/docker-compose.yml`. `docker-compose.dev.yml` publishes `auditor-api`
  at `:8000` so the browser-hosted compiled app can reach it directly (it runs outside any Docker network).

PC-verified end-to-end: `curl http://localhost:8080` returns 200 with `<title>IoTGuard Auditor</title>`, and
the dashboard is backed by the real migrated data (12 evidence, 8 verdicts) once the stack is up.

Two real gaps caught and fixed during Phase 7:
- **DI gap (Task 13):** `navigation_test.dart` pumped the full `AuditorApp()`, which built a real,
  non-mockable `ApiClient`. Every screen wired into `HomeShell` (starting with `OverviewScreen`) would have
  fired an un-mocked HTTP call during every widget test run. Fixed by making `AuditorApp`/`HomeShell` accept
  an optional injectable `ApiClient`, defaulting to the real one in production; `navigation_test.dart` now
  injects a `MockClient`.
- **Missing `web/` platform scaffold (ERR-015):** Tasks 10-16 hand-wrote all Dart source (no Flutter SDK
  available anywhere in this environment), which covered everything `flutter test` needs but never generated
  the `web/` directory `flutter build web` requires. Fixed by generating `web/` via an isolated
  `flutter create --platforms web` run, copying over only the platform files (not `lib/main.dart` or
  `test/`), and branding them to match the app ("IoTGuard Auditor", dark theme color).

## Phase 8: Polish & Full-Stack Demo

- [x] `traffic-capture` — `tcpdump` on `audit-network`, PC-verified: after generating one HTTP request to
  `device-insecure`, a real, non-empty `.pcap` file appeared in `/pcap`. Re-verified during the final
  full-stack run: 3 real capture files present (2736, 2998, 3160 bytes).
- [x] `lab/README.md` and `lab/.env.example` updated for the full stack (all 4 new services documented,
  correct ports, migration command, verification steps).
- [x] **Full 11-container stack verified together on the PC** (not just individually, as in Phases 6-7):

```
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

All 10 containers (`auditor-database`, `auditor-api`, `auditor-web`, `auditor-worker`,
`device-insecure`/`partial`/`hardened`, `mqtt-broker-insecure`/`secure`, `telnet-sim`, `traffic-capture`)
started and reached their expected state. `telnet-sim` shows Docker's own health status as "unhealthy" — this
is the already-documented ERR-005 healthcheck flakiness from Phase 0-5 (BusyBox `nc -z localhost` IPv4/IPv6
binding mismatch), not a functional regression: `nmap -sV -p 23 telnet-sim` from inside `auditor-worker`
confirmed the service genuinely responds correctly (`AcmeCam Telnet Management Console` banner).

Full verification, in order, against the live stack:

| Check | Command | Result |
|---|---|---|
| API summary | `curl http://localhost:8000/summary` | `{"total_evidence":12,"total_verdicts":8,"verdicts_by_status":{"PASS":4,"FAIL":4,"PARTIAL":0,"INCONCLUSIVE":0}}` |
| Dashboard | `curl http://localhost:8080` | 200, `<title>IoTGuard Auditor</title>` |
| Verdicts by control | (script against `GET /verdicts`, grouped by `control_id`) | `SA-IOT-002 ['FAIL','PASS']`, `SA-IOT-003 ['FAIL','PASS']`, `SA-IOT-004 ['FAIL','PASS']`, `SA-IOT-005 ['FAIL','PASS']` — all 4 controls confirmed with both statuses, matching Phase 0-5's original result exactly |
| Traffic capture | `docker compose exec traffic-capture ls -la /pcap` | 3 non-empty `.pcap` files |

Stack torn down afterward (`docker compose down`) with the migrated database volume left intact.

### Two infrastructure incidents during this final verification (not code defects)

Getting to the successful run above required diagnosing and fixing two real problems on the physical build
PC, both logged per the project's error convention:

- **[ERR-016](../errors/016-disk-space-exhaustion-corrupts-docker-containerd.md):** the PC's `C:` drive ran
  down to ~2.5GB free while loading the Flutter Docker image (transferred directly via `scp` over Tailscale
  to bypass an extremely slow public `docker pull`), corrupting Docker Desktop's containerd storage. Required
  the user to free ~50GB, then `wsl --shutdown` (fixes containerd) and a full Docker Desktop process restart
  (fixes the separate host port-forwarding proxy, which stayed broken after `wsl --shutdown` alone).
- **[ERR-017](../errors/017-internal-network-blocks-docker-desktop-port-forwarding.md):** a genuine,
  disk-space-unrelated bug found once Docker Desktop was healthy again — `auditor-api`/`auditor-web` sit only
  on `internal-network` (`internal: true` in the base compose file, intentional for production isolation),
  and that isolation silently blocked Docker Desktop's host port-forwarding proxy from ever reaching them,
  even with a correct `ports:` declaration. Fixed by overriding `internal: false` for `internal-network` in
  `docker-compose.dev.yml` only (the dev-only overlay whose whole documented purpose is exposing things to
  `localhost` for convenience) — the base file's production isolation is untouched.

Neither incident affected any code, evidence, or verdict data — the migrated database volume persisted
through both restarts and the final verification confirmed identical counts to before the incidents began.

## Test Suite

All tests pass across the Phases 6-8 codebase. Every count below was independently re-run and confirmed in
this session (not taken from implementer claims):

| Component | File(s) | Tests |
|---|---|---|
| lab/auditor/api | `test_health.py` (1) + `test_evidence.py` (6) + `test_verdicts.py` (5) + `test_controls.py` (6, includes 3 path-traversal regression tests) + `test_devices_summary.py` (2) | 20 |
| lab/auditor/worker/tests | `test_record_evidence.py` | 4 |
| policies/engine | `test_generate_verdicts.py` (1) + `test_migrate_existing_records.py` (1) | 2 |
| lab/auditor/web (Flutter, own toolchain via Docker) | `api_client_test.dart` (2) + `theme_test.dart` (2) + `navigation_test.dart` (1) + `overview_screen_test.dart` (1) + `devices_screen_test.dart` (1) + `evidence_screen_test.dart` (1) + `verdicts_screen_test.dart` (1) | 9 |

**Total: 35 tests passed** (26 Python, run via the dedicated `lab/auditor/api/.venv` for Postgres-backed
tests against a real throwaway Postgres container spun up by the test fixtures themselves; 9 Dart, run via
`ghcr.io/cirruslabs/flutter:stable` in Docker since no Flutter SDK is installed anywhere in this environment).

Combined with Phase 0-5's 45 tests, the full project now has **80 tests passing** across the whole codebase.

## Determinism Check (unchanged, re-confirmed)

- [x] No `eval`/`exec` anywhere in `policies/engine/policy_engine.py` or the new `auditor-api`/worker-adapter
  code — verified by inspection during each task's review; no dynamic code execution was introduced anywhere
  in Phases 6-8.

## Controller-Caught Issues Summary

Six issues were found and fixed by the controller (not the task implementers) during Phases 6-8's review
loop, each logged as its own error file per the project convention:

| ID | What | Where |
|---|---|---|
| ERR-012 | `psycopg[binary]==3.2.3` pinned in the plan has no PyPI wheel; would have silently required `libpq` at container runtime | `lab/auditor/api/requirements.txt` |
| ERR-013 | Plan's verdict test fixtures used dict-shaped `matched`/`saudi_source`, contradicting the real committed schema and `evaluate()`'s actual contract | Plan text (Tasks 4, 6, 8) |
| (unlogged, fixed inline) | Path traversal in `GET /controls/{control_id}` — unvalidated `control_id` used directly in file path construction | `lab/auditor/api/main.py` (Task 5) |
| ERR-014 | `record_evidence.py`'s sequence numbering would collide on every repeated invocation after moving off local-file-count-based IDs | `lab/auditor/worker/tests/record_evidence.py` |
| ERR-015 | Flutter project missing the `web/` platform scaffold, breaking `flutter build web` | `lab/auditor/web/` |
| ERR-016 + ERR-017 | PC disk-space exhaustion + Docker Desktop corruption, plus a genuine `internal: true` network bug blocking port forwarding | Build PC / `lab/docker-compose.dev.yml` |

This is the same pattern established in Phase 0-5 (11 errors caught and logged) — the review loop
(implementer → controller PC-verification → reviewer subagent → fix cycle) continues to catch real defects
before they ship, not just rubber-stamp task completion.
