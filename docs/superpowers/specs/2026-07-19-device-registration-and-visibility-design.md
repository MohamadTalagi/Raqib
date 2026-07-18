# Device Registration & Visibility — Design Spec

**Date:** 2026-07-19
**Status:** Approved
**Builds on:** merged `main` (Phases 0-8 complete, `fa73983`)

Adds manual device registration to the IoTGuard auditor, makes registered devices scannable, and
adds the two missing visibility screens (device detail, NCA controls).

---

## 1. Motivation

Today there is **no `devices` table**. `GET /devices` derives its list from
`SELECT device_id FROM evidence UNION SELECT device_id FROM verdicts` — a device exists only
*because* it already has evidence. Device identity is hardcoded in three places that duplicate the
same facts:

| Location | Hardcodes |
|---|---|
| `lab/auditor/web/src/lib/deviceMeta.ts` | label, description, tier, icon |
| `lab/auditor/web/src/lib/consoleDevices.ts` | scheme + published port |
| `policies/catalog/scan_tests.py` | `DEVICE_SCHEME`, per-test `allowed_devices` |

Manual registration inverts this: devices become first-class records that exist before any
evidence, and the three hardcoded lists collapse into one source of truth.

## 2. Scope decisions

Settled during brainstorming:

1. **Registered devices are scannable**, not inventory-only. This trades a fixed whitelist for
   validated user input — see §5.
2. **Targets are lab container names or IPs inside `172.30.0.0/24`** (`audit-network`). Not
   arbitrary hosts.
3. **The existing devices migrate in.** Single source of truth; the hardcoded modules are deleted.
4. **Both new screens ship**: device detail and NCA controls.
5. **Normalized model**: `devices` + `device_services`, not a flat record.

Out of scope: the production-ready platform rebuild (explicitly deferred by the owner).

## 3. Data model

Two new tables in `lab/auditor/db/init.sql`.

### `devices`

| Column | Type | Notes |
|---|---|---|
| `device_id` | TEXT PRIMARY KEY | Stable join key, already used by `evidence.device_id` / `verdicts.device_id` |
| `display_name` | TEXT NOT NULL | |
| `description` | TEXT NOT NULL DEFAULT `''` | |
| `tier` | TEXT NOT NULL | CHECK IN (`insecure`, `partial`, `hardened`, `unknown`) |
| `host` | TEXT NOT NULL | Container name or `172.30.0.0/24` IP. Validated per §5. |
| `vendor`, `model`, `location`, `owner`, `notes` | TEXT | Optional inventory fields |
| `source` | TEXT NOT NULL | CHECK IN (`seeded`, `manual`) |
| `created_at`, `updated_at` | TIMESTAMPTZ NOT NULL DEFAULT `now()` | |

### `device_services`

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PRIMARY KEY | |
| `device_id` | TEXT | REFERENCES `devices(device_id)` ON DELETE CASCADE |
| `service_type` | TEXT | CHECK IN (`http`, `https`, `mqtt`, `mqtts`, `telnet`, `ssh`) |
| `port` | INTEGER NOT NULL | CHECK BETWEEN 1 AND 65535. Port *inside* `audit-network` — what the worker targets. |
| `published_port` | INTEGER NULL | Host port from `docker-compose.dev.yml` — what the *browser* reaches. NULL = not browser-reachable. |
| `enabled` | BOOLEAN NOT NULL DEFAULT true | |
| | | UNIQUE (`device_id`, `service_type`, `port`) |

**`port` vs `published_port` is not redundancy.** The worker runs inside `audit-network` and reaches
`device-partial:443`. The browser runs on the operator's machine and reaches
`<host>:8082`. That gap is exactly why `consoleDevices.ts` and `scan_tests.py` are separate
hardcoded lists today. Storing both columns lets both be deleted.

**Capabilities derive from services, not a device type.** An `http`/`https` service gets the HTTP
console endpoint catalog; an `mqtt` service gets none of it. MQTT brokers stop being a special case
handled by omission.

## 4. API surface

In `lab/auditor/api/main.py`.

| Endpoint | Behavior |
|---|---|
| `POST /devices` | Register. Device fields + services array. 201 created; 409 duplicate `device_id`; 400 validation failure. |
| `GET /devices` | List from the table, LEFT JOINed to evidence/verdict counts. |
| `GET /devices/{device_id}` | Detail: device, services, evidence, verdicts, scan jobs — one call. |
| `PATCH /devices/{device_id}` | Edit metadata. `device_id` immutable. |
| `DELETE /devices/{device_id}` | Deregister. Cascades to `device_services` only. |
| `POST /devices/{device_id}/services` | Add a service. |
| `DELETE /devices/{device_id}/services/{id}` | Remove a service. |
| `GET /controls/{id}/verdicts` | Per-control verdict rollup for the Controls page. |

### Two invariants

**Evidence must never become invisible.** Reading devices from a table breaks the old implicit
guarantee that every device with evidence appears. So `GET /devices` returns registered devices
**plus** orphan `device_id`s still present in `evidence`/`verdicts`, flagged `registered: false`.

**Deleting a device must not delete its audit trail.** There is no foreign key from `evidence` to
`devices` — `evidence.device_id` is free text, and its rows are immutable audit records referenced
by committed hashes. Deregistering drops the `devices` row and its services, leaves every evidence
and verdict row untouched, and the device reappears in the list as unregistered. Deleting a device
is an inventory action, never a records action.

`GET /controls` and `GET /controls/{id}` are unchanged; the rollup is additive so existing consumers
keep working. The existing path-traversal guard on `control_id` (`^[A-Za-z0-9\-]+$`, checked before
any filesystem access) applies to the new route.

## 5. Security and validation

Scope decision 1 traded a fixed whitelist for user-supplied targets. This section is what replaces
that guarantee.

**Network isolation is not a backstop.** `auditor-worker` is attached to *both* `audit-network` and
`internal-network`, and `audit-network` is a plain bridge (only `internal-network` sets
`internal: true`). The worker can therefore reach the lab devices, the backend including
`auditor-database`, and the internet. Validation is the entire control.

### Write-time validation (API, before any DB write)

- `device_id` — `^[a-z0-9][a-z0-9-]{0,62}$`. No dots, slashes, spaces, or path characters.
- `host` — **either** a container-name matching `^[a-z0-9][a-z0-9-]{0,62}$` **or** an IP literal
  parsed with Python's `ipaddress` module and confirmed inside `172.30.0.0/24`. String comparison is
  insufficient: `172.30.0.1` and `0172.030.0.1` are the same address to a resolver and different
  strings to a regex.
- Rejected even though nominally private: `127.0.0.1`/`localhost`, `0.0.0.0`,
  `169.254.0.0/16` (link-local and cloud metadata), `10.0.0.0/8`, `192.168.0.0/16`. Everything
  outside `172.30.0.0/24` is refused.
- Infrastructure hostnames refused by name: `auditor-api`, `auditor-database`, `auditor-web`,
  `auditor-worker`. Devices are audit targets; the auditor is not one.
- `port` — integer 1–65535. `service_type` — enum-checked.

### Two specific attacks this closes

- **Argv injection.** A host of `--script=http-shellshock` is a valid string that becomes an *nmap
  flag* rather than a target once it lands in the argv list. The leading-character rule
  (`[a-z0-9]` first) rejects anything starting with `-`.
- **Scanning our own backend.** `auditor-database` is reachable from the worker over
  `internal-network` and would pass the container-name pattern. The infrastructure-name denylist
  closes it.

### Execute-time re-validation

`job_runner.py` re-runs the identical validation on the host and port it reads from the database,
immediately before building the command. **The database is treated as untrusted input** — a row
written by a buggy or older API version is still refused. Commands remain argv lists, never shell
strings (unchanged from today).

### `scan_tests.py` changes

`allowed_devices` is replaced by `applicable_service_types` per test: the nmap test applies to any
service; login and headers tests apply to `http`/`https` only. The worker resolves the concrete
target from `device_services`, so an MQTT-only device is never offered an HTTP login test.

### Documented trade-off

This is **weaker** than a hardcoded list of three names — that list could not be wrong; this can.
What it buys is a feature that works for arbitrary lab devices. Mitigations: validation runs twice
on independent sides of the boundary, the allowlist is a `/24` rather than "private IPs" broadly,
and infrastructure hostnames are denied by name. Recorded here deliberately, because "why did the
security boundary change?" is a question the mentor should ask.

## 6. Frontend

Existing design language holds: dark near-black, single amber accent, severity-coded status colors,
bundled Inter / JetBrains Mono, lucide icons, recharts, no emojis.

- **Devices page becomes the registry** — gains a "Register device" action, a
  `registered`/`unregistered` indicator, and rows linking to the detail page. Unregistered devices
  render muted with a "Register" affordance, turning the orphan case into a feature.
- **Registration form** — device fields as a plain form; services as an add/remove repeater
  (`service_type` + `port` + optional `published_port`). Quick-picks prefill sensible service sets
  (smart camera → `http:80` / `https:443`; MQTT broker → `mqtt:1883` / `mqtts:8883`), editable
  afterward. API validation errors render against the causing field, not as a single toast.
- **Device detail — `/devices/:id`** — identity and inventory metadata, services, evidence,
  verdicts, scan history, and inline console buttons. One page per device.
- **Controls — `/controls` and `/controls/:id`** — title, Saudi source reference, severity,
  applicability, required evidence, pass/fail conditions, remediation, plus the verdict rollup
  showing which devices pass and fail. Sidebar gains a seventh item.
- **Device Console becomes data-driven** — `consoleDevices.ts` and `deviceMeta.ts` are deleted.
  Cards come from the API; each `http`/`https` service with a `published_port` renders the endpoint
  catalog. Icon mapping stays in the frontend, keyed by `service_type`.
- **Run Scan becomes data-driven** — targets from registered devices, tests filtered by service type.

**Visual verification is mandatory.** Given the Flutter redesign that shipped on green checks and
was rejected on sight, no screen is called done off a passing `tsc` and green tests. Every new
screen is driven in a real browser with Playwright against the real PC stack, and screenshots go to
the owner for sign-off before completion.

**Separable scope:** the Controls page shares no code with registration and can be split into a
follow-up if scope needs cutting. Kept here because it most directly demonstrates NCA alignment.

## 7. Migration

`docs/errors/021` already records the trap: adding a table to `init.sql` does **not** reach an
already-initialized Postgres volume. Both paths are handled:

- **Fresh volumes** — new tables in `init.sql`.
- **Existing volumes** — a standalone idempotent migration (`CREATE TABLE IF NOT EXISTS`,
  `INSERT ... ON CONFLICT DO NOTHING`), safe to run twice, because it will be run twice: once on the
  dev DB, once on the PC's.

### Seed data — six devices, all `source = 'seeded'`

| device_id | tier | services |
|---|---|---|
| `device-insecure` | insecure | `http:80` (published 8081) |
| `device-partial` | partial | `https:443` (published 8082) |
| `device-hardened` | hardened | `https:443` (published 8083) |
| `mqtt-broker-insecure` | insecure | `mqtt:1883` |
| `mqtt-broker-secure` | hardened | `mqtts:8883` |
| `telnet-sim` | insecure | `telnet:23` |

Labels, descriptions and tiers for the **first five** are lifted verbatim from `deviceMeta.ts`;
ports and published ports from `docker-compose.yml` and `docker-compose.dev.yml`.

**`telnet-sim` is the exception and needs new metadata.** It has no `deviceMeta.ts` entry today —
it was never rendered as a device card — but it *is* listed in `scan_tests.py`'s nmap
`allowed_devices`, so omitting it from the seed would silently drop a currently-working scan target.
Its `display_name`, `description` and `tier` are therefore newly authored for this migration rather
than copied, and should be reviewed on sight rather than assumed correct. Its `telnet:23` port comes
from the real compose service and its nmap special-case in `scan_tests.py`.

### Non-negotiable constraint

**`device_id` values stay byte-for-byte identical.** Committed Day-2 evidence references these
strings, and `EV-2026-07-08-0015` is documented as referenced byte-for-byte by its raw output and
hash. The migration only *inserts into new tables*. It never touches, rewrites, or re-keys a row in
`evidence` or `verdicts`.

### Verification

`GET /summary` must return exactly `{"total_evidence": 12, "total_verdicts": 8,
"verdicts_by_status": {"PASS": 4, "FAIL": 4, "PARTIAL": 0, "INCONCLUSIVE": 0}}` both before and
after — the same numbers pinned by the Phase 6-8 acceptance doc. Identical counts prove the device
registry changed nothing about the audit record.

**Ordering:** the hardcoded frontend modules are deleted *after* the migration is confirmed applied
in a given environment, never in the same step. Otherwise the dashboard reads an empty table and
every device silently disappears.

## 8. Testing

Conventions unchanged: pytest (API/worker/policies), Vitest + React Testing Library (frontend),
Playwright (real stack). Baseline is 74 tests passing.

### Security tests — named cases, one assertion each

| Input | Expected |
|---|---|
| `host = "--script=http-shellshock"` | 400 (argv injection) |
| `host = "auditor-database"` | 400 (infrastructure hostname) |
| `host = "10.0.0.5"` / `"192.168.1.1"` / `"127.0.0.1"` / `"169.254.169.254"` | 400 (outside the `/24`) |
| `host = "0172.030.0.1"` | 400 (octal-encoded in-range address) |
| `host = "172.30.0.9"` | 201 (in-range case must still work) |
| `device_id` with `../`, spaces, or uppercase | 400 |

### Execute-time re-validation — adversarial test

Write a malicious row **directly into the database**, bypassing the API, then assert `job_runner.py`
refuses to build a command from it. This proves defense-in-depth is real rather than decorative — if
the worker trusted the DB, this test fails.

### Migration tests

Run twice, assert the second run is a no-op; assert all six seeded devices land with correct
services; assert `GET /summary` is byte-identical before and after.

### API tests

Registration happy path; 409 duplicate; PATCH; DELETE cascading to services while leaving evidence
intact; the orphan-device case; the controls verdict rollup.

### Frontend tests

New pages render from fixtures; the registration form surfaces field-level API errors; console and
scan pages render from API data with their hardcoded modules gone.

### Playwright acceptance — the test that decides

Against the real PC stack: register a device through the actual UI, confirm it appears on the
Devices list and its detail page, run a real scan against it, confirm real evidence appears
afterward. The project's pattern is that curl-passing and test-passing both missed bugs a real
browser caught immediately (the CORS bug, the unbundled fonts).

---

## Decisions log

| Decision | Chosen | Rejected alternatives |
|---|---|---|
| Purpose of registration | Inventory **+ scannable** | Inventory only; discovery groundwork |
| Target scope | Lab containers **+ `172.30.0.0/24` IPs** | Containers only; any host (footgun in a lab of vulnerable services) |
| Visibility screens | **Both** device detail and Controls | Either alone |
| Existing devices | **Migrate in**, single source of truth | Keep hardcoded (guarantees drift); hybrid |
| Capability model | **`devices` + `device_services`** (normalized) | Flat record; typed profile field |
