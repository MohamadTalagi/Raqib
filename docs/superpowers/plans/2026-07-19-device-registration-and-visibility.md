# Device Registration & Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make devices first-class database records that can be registered by hand, scanned safely, and inspected on dedicated device-detail and NCA-controls screens.

**Architecture:** Two new tables (`devices`, `device_services`) become the single source of truth for device identity, replacing three hardcoded lists (`deviceMeta.ts`, `consoleDevices.ts`, `scan_tests.py`'s `DEVICE_SCHEME`/`allowed_devices`). A standalone validation module guards every registration and is re-run by the worker before any command executes. The React dashboard gains registration, device detail, and controls screens, and its console/scan pages become data-driven.

**Tech Stack:** FastAPI · PostgreSQL 16 · psycopg 3 · pytest · React 19 + TypeScript + Vite · Tailwind v4 · Vitest + React Testing Library · Playwright · Docker Compose

**Spec:** `docs/superpowers/specs/2026-07-19-device-registration-and-visibility-design.md`

## Global Constraints

- **`device_id` values never change.** Committed Day-2 evidence references these strings byte-for-byte (`EV-2026-07-08-0015` is documented as referenced by raw output and hash). Migrations only INSERT into new tables; they never touch, rewrite, or re-key `evidence` or `verdicts`.
- **Audit record must be provably unchanged.** `GET /summary` returns exactly `{"total_evidence": 12, "total_verdicts": 8, "verdicts_by_status": {"PASS": 4, "FAIL": 4, "PARTIAL": 0, "INCONCLUSIVE": 0}}` before and after every migration.
- **Commands are argv lists, never shell strings.** `subprocess.run` without `shell=True`. Unchanged from today.
- **Validation runs twice** — once in the API at write time, once in the worker at execute time. The database is untrusted input.
- **Target allowlist is `172.30.0.0/24`** (`audit-network`) only. Everything else is refused, including other private ranges.
- **Infrastructure hostnames are never registrable:** `auditor-api`, `auditor-database`, `auditor-web`, `auditor-worker`.
- **No emojis in UI.** Dark near-black theme, single amber accent, severity-coded status colors, bundled Inter / JetBrains Mono, lucide icons, recharts. Matches existing pages.
- **Deleting a device never deletes evidence.** Cascade reaches `device_services` only.
- **Python:** 4-space indent, type hints on new functions. **TypeScript:** no `any`, explicit prop types.
- Run backend tests from `lab/auditor/api/`; frontend tests from `lab/auditor/web/`.

---

## File Structure

**Created:**
- `lab/auditor/db/migrations/001-devices.sql` — idempotent migration for existing volumes
- `lab/auditor/api/device_validation.py` — pure validation, no DB or HTTP imports (so both API and worker can use it)
- `lab/auditor/api/test_device_validation.py` — security test cases
- `lab/auditor/api/test_devices_crud.py` — registration CRUD tests
- `lab/auditor/api/test_controls_verdicts.py` — controls rollup tests
- `policies/engine/seed_devices.py` — idempotent seeding of the 6 existing devices
- `policies/engine/test_seed_devices.py`
- `lab/auditor/web/src/lib/serviceIcons.ts` — icon mapping by `service_type` (presentation only)
- `lab/auditor/web/src/pages/DeviceDetailPage.tsx` (+ `.test.tsx`)
- `lab/auditor/web/src/pages/ControlsPage.tsx` (+ `.test.tsx`)
- `lab/auditor/web/src/pages/ControlDetailPage.tsx`
- `lab/auditor/web/src/components/devices/RegisterDeviceForm.tsx` (+ `.test.tsx`)

**Modified:**
- `lab/auditor/db/init.sql` — new tables for fresh volumes
- `lab/auditor/api/conftest.py:47-51` — truncate the new tables
- `lab/auditor/api/main.py` — device CRUD, rewritten `GET /devices`, controls rollup
- `policies/catalog/scan_tests.py` — `applicable_service_types`, `build_command(target)`
- `lab/auditor/worker/job_runner.py:38-50` — resolve target, re-validate
- `lab/auditor/web/src/lib/types.ts`, `api.ts`
- `lab/auditor/web/src/pages/DevicesPage.tsx`, `DeviceConsolePage.tsx`, `RunScanPage.tsx`
- `lab/auditor/web/src/components/layout/Sidebar.tsx`, `src/App.tsx`
- `lab/docker-compose.yml` — telnet-sim healthcheck fix

**Deleted (Task 12, only after migration is confirmed applied):**
- `lab/auditor/web/src/lib/deviceMeta.ts`
- `lab/auditor/web/src/lib/consoleDevices.ts`

---

### Task 1: Database schema and migration

**Files:**
- Modify: `lab/auditor/db/init.sql`
- Create: `lab/auditor/db/migrations/001-devices.sql`
- Modify: `lab/auditor/api/conftest.py:47-51`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: tables `devices(device_id, display_name, description, tier, host, vendor, model, location, owner, notes, source, created_at, updated_at)` and `device_services(id, device_id, service_type, port, published_port, enabled)`

- [ ] **Step 1: Append the new tables to `init.sql`**

Append to `lab/auditor/db/init.sql` (leave every existing table untouched):

```sql
CREATE TABLE devices (
    device_id        TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    tier             TEXT NOT NULL CHECK (tier IN ('insecure', 'partial', 'hardened', 'unknown')),
    host             TEXT NOT NULL,
    vendor           TEXT,
    model            TEXT,
    location         TEXT,
    owner            TEXT,
    notes            TEXT,
    source           TEXT NOT NULL CHECK (source IN ('seeded', 'manual')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_services (
    id               SERIAL PRIMARY KEY,
    device_id        TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    service_type     TEXT NOT NULL CHECK (service_type IN ('http', 'https', 'mqtt', 'mqtts', 'telnet', 'ssh')),
    port             INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    published_port   INTEGER CHECK (published_port BETWEEN 1 AND 65535),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (device_id, service_type, port)
);

CREATE INDEX idx_device_services_device_id ON device_services(device_id);
```

- [ ] **Step 2: Create the idempotent migration for existing volumes**

Create `lab/auditor/db/migrations/001-devices.sql`. This exists because `init.sql` does **not** re-run on an already-initialized Postgres volume (see `docs/errors/021`). It must be safe to run repeatedly:

```sql
-- Idempotent. Safe to run repeatedly on a live database.
-- init.sql only runs on a fresh volume; this is the path for existing ones.
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    tier             TEXT NOT NULL CHECK (tier IN ('insecure', 'partial', 'hardened', 'unknown')),
    host             TEXT NOT NULL,
    vendor           TEXT,
    model            TEXT,
    location         TEXT,
    owner            TEXT,
    notes            TEXT,
    source           TEXT NOT NULL CHECK (source IN ('seeded', 'manual')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_services (
    id               SERIAL PRIMARY KEY,
    device_id        TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    service_type     TEXT NOT NULL CHECK (service_type IN ('http', 'https', 'mqtt', 'mqtts', 'telnet', 'ssh')),
    port             INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    published_port   INTEGER CHECK (published_port BETWEEN 1 AND 65535),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (device_id, service_type, port)
);

CREATE INDEX IF NOT EXISTS idx_device_services_device_id ON device_services(device_id);
```

- [ ] **Step 3: Add the new tables to the test truncation fixture**

In `lab/auditor/api/conftest.py`, change the `clean_tables` fixture's TRUNCATE. Order matters — `device_services` has an FK to `devices`, and `CASCADE` on the truncate handles it:

```python
@pytest.fixture(autouse=True)
def clean_tables(postgres_url):
    conn = psycopg.connect(postgres_url)
    conn.execute("TRUNCATE evidence, verdicts, scan_jobs, device_services, devices RESTART IDENTITY CASCADE")
    conn.commit()
    conn.close()
```

- [ ] **Step 4: Verify the schema loads**

Run from `lab/auditor/api/`: `pytest test_health.py -v`

Expected: PASS. The session fixture executes `init.sql` against a scratch Postgres container; if the new DDL had a syntax error this fails at setup.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/db/init.sql lab/auditor/db/migrations/001-devices.sql lab/auditor/api/conftest.py
git commit -m "feat(db): add devices and device_services tables

init.sql covers fresh volumes; migrations/001-devices.sql is the idempotent
path for already-initialized ones (see docs/errors/021)."
```

---

### Task 2: Validation module

This is the security boundary. It is a standalone module with no DB or HTTP imports so that **both** the API and the worker import the identical logic.

**Files:**
- Create: `lab/auditor/api/device_validation.py`
- Create: `lab/auditor/api/test_device_validation.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `ValidationError(Exception)` with a `.field: str` and `.message: str`
  - `validate_device_id(value: str) -> str`
  - `validate_host(value: str) -> str`
  - `validate_port(value: int, field: str = "port") -> int`
  - `validate_service_type(value: str) -> str`
  - `SERVICE_TYPES: tuple[str, ...]`
  - `TIERS: tuple[str, ...]`

- [ ] **Step 1: Write the failing security tests**

Create `lab/auditor/api/test_device_validation.py`:

```python
import pytest

from device_validation import (
    ValidationError,
    validate_device_id,
    validate_host,
    validate_port,
    validate_service_type,
)


def test_valid_container_name_accepted():
    assert validate_host("device-insecure") == "device-insecure"


def test_valid_in_range_ip_accepted():
    assert validate_host("172.30.0.9") == "172.30.0.9"


def test_argv_injection_rejected():
    # A leading dash makes this an nmap FLAG, not a target.
    with pytest.raises(ValidationError):
        validate_host("--script=http-shellshock")


def test_infrastructure_hostname_rejected():
    for name in ("auditor-api", "auditor-database", "auditor-web", "auditor-worker"):
        with pytest.raises(ValidationError):
            validate_host(name)


def test_out_of_range_private_ips_rejected():
    for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254", "0.0.0.0"):
        with pytest.raises(ValidationError):
            validate_host(ip)


def test_octal_encoded_in_range_ip_rejected():
    # Same address as 172.30.0.1 to a resolver, different string to a regex.
    with pytest.raises(ValidationError):
        validate_host("0172.030.0.1")


def test_localhost_rejected():
    with pytest.raises(ValidationError):
        validate_host("localhost")


def test_device_id_rejects_path_traversal_and_spaces_and_uppercase():
    for bad in ("../etc/passwd", "device insecure", "Device-Insecure", "", "-leading"):
        with pytest.raises(ValidationError):
            validate_device_id(bad)


def test_device_id_accepts_normal_name():
    assert validate_device_id("device-insecure") == "device-insecure"


def test_port_bounds():
    assert validate_port(443) == 443
    for bad in (0, -1, 65536, 99999):
        with pytest.raises(ValidationError):
            validate_port(bad)


def test_service_type_enum():
    assert validate_service_type("https") == "https"
    with pytest.raises(ValidationError):
        validate_service_type("gopher")
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `lab/auditor/api/`: `pytest test_device_validation.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'device_validation'`

- [ ] **Step 3: Write the implementation**

Create `lab/auditor/api/device_validation.py`:

```python
"""Validation for device registration and scan targeting.

This module is the security boundary that replaced the fixed
`allowed_devices` whitelist when devices became user-registerable. It has no
DB or HTTP imports on purpose: auditor-api imports it at write time and
auditor-worker imports it again at execute time, so a row written by a buggy
or older API version is still refused before any command is built.
"""
import ipaddress
import re

# audit-network, per lab/docker-compose.yml. Nothing outside this is a legal
# target - including other private ranges.
ALLOWED_NETWORK = ipaddress.ip_network("172.30.0.0/24")

# The auditor is not an audit target.
INFRASTRUCTURE_HOSTS = frozenset(
    {"auditor-api", "auditor-database", "auditor-web", "auditor-worker"}
)

# Leading char must be alphanumeric: that is what stops a value like
# "--script=http-shellshock" from becoming a command-line FLAG in the argv list.
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

SERVICE_TYPES = ("http", "https", "mqtt", "mqtts", "telnet", "ssh")
TIERS = ("insecure", "partial", "hardened", "unknown")


class ValidationError(Exception):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


def validate_device_id(value: str) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.match(value):
        raise ValidationError(
            "device_id",
            "device_id must be lowercase alphanumeric with dashes, "
            "start with a letter or digit, and be at most 63 characters",
        )
    return value


def validate_host(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError("host", "host is required")

    # Try IP first. ipaddress parses octal/alternate forms that a regex would
    # treat as an unrelated string, which is the point of parsing rather than
    # pattern-matching.
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    if address is not None:
        if address not in ALLOWED_NETWORK:
            raise ValidationError(
                "host", f"IP must be inside {ALLOWED_NETWORK} (audit-network)"
            )
        return value

    # Reject any dotted form that is not a valid IP but looks like one, so
    # "0172.030.0.1" cannot slip through as a hostname.
    if re.fullmatch(r"[0-9a-fA-FxX.:]+", value):
        raise ValidationError("host", "host looks like an IP but is not a valid address")

    if value in INFRASTRUCTURE_HOSTS:
        raise ValidationError("host", f"{value} is infrastructure and cannot be a target")

    if not NAME_PATTERN.match(value):
        raise ValidationError(
            "host",
            "host must be a container name (lowercase alphanumeric with dashes) "
            f"or an IP inside {ALLOWED_NETWORK}",
        )
    return value


def validate_port(value: int, field: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(field, f"{field} must be an integer")
    if not 1 <= value <= 65535:
        raise ValidationError(field, f"{field} must be between 1 and 65535")
    return value


def validate_service_type(value: str) -> str:
    if value not in SERVICE_TYPES:
        raise ValidationError(
            "service_type", f"service_type must be one of {', '.join(SERVICE_TYPES)}"
        )
    return value
```

- [ ] **Step 4: Run tests to verify they pass**

Run from `lab/auditor/api/`: `pytest test_device_validation.py -v`

Expected: PASS, 10 tests.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/api/device_validation.py lab/auditor/api/test_device_validation.py
git commit -m "feat(api): add device validation module

Replaces the fixed allowed_devices whitelist as the scan security boundary.
Parses IPs with the ipaddress module rather than regex-matching them, so
octal-encoded forms cannot bypass the 172.30.0.0/24 allowlist, and requires
an alphanumeric leading character so a host cannot become an argv flag."
```

---

### Task 3: Register and list devices

**Files:**
- Modify: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/test_devices_crud.py`

**Interfaces:**
- Consumes: `device_validation.validate_device_id`, `validate_host`, `validate_port`, `validate_service_type`, `TIERS`, `ValidationError`
- Produces: `POST /devices` (201), `GET /devices` returning `[{device_id, display_name, description, tier, host, vendor, model, location, owner, notes, source, registered: bool, evidence_count: int, verdict_count: int, services: [{id, service_type, port, published_port, enabled}]}]`

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_devices_crud.py`:

```python
import psycopg
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


def _payload(**overrides) -> dict:
    payload = {
        "device_id": "test-camera",
        "display_name": "Test Camera",
        "description": "A registered test device.",
        "tier": "insecure",
        "host": "test-camera",
        "vendor": "AcmeCam",
        "model": "AC-100",
        "location": "Lab bench",
        "owner": "Security team",
        "notes": "Registered by hand.",
        "services": [{"service_type": "http", "port": 80, "published_port": 8091}],
    }
    payload.update(overrides)
    return payload


def test_register_device_returns_201_with_services():
    response = client.post("/devices", json=_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["device_id"] == "test-camera"
    assert body["source"] == "manual"
    assert len(body["services"]) == 1
    assert body["services"][0]["port"] == 80
    assert body["services"][0]["published_port"] == 8091


def test_duplicate_device_id_returns_409():
    client.post("/devices", json=_payload())
    response = client.post("/devices", json=_payload())
    assert response.status_code == 409


def test_invalid_host_returns_400_naming_the_field():
    response = client.post("/devices", json=_payload(host="10.0.0.5"))
    assert response.status_code == 400
    assert response.json()["field"] == "host"


def test_argv_injection_host_returns_400():
    response = client.post("/devices", json=_payload(host="--script=http-shellshock"))
    assert response.status_code == 400


def test_registered_device_appears_in_list():
    client.post("/devices", json=_payload())
    devices = client.get("/devices").json()
    entry = next(d for d in devices if d["device_id"] == "test-camera")
    assert entry["registered"] is True
    assert entry["evidence_count"] == 0
    assert entry["display_name"] == "Test Camera"


def test_orphan_device_with_evidence_still_appears_unregistered(postgres_url):
    # Evidence exists for a device that was never registered. It must not
    # vanish from the dashboard just because devices now come from a table.
    conn = psycopg.connect(postgres_url)
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-ORPHAN-1', 'ghost-device', 'TEST-NET-PORTSCAN', 'nmap', '7.94',
                'nmap -sV ghost-device', now(), 'ghost finding', '{}'::jsonb,
                'document-store/raw/ghost.txt', 'high', 'abc123')
        """
    )
    conn.commit()
    conn.close()

    devices = client.get("/devices").json()
    entry = next(d for d in devices if d["device_id"] == "ghost-device")
    assert entry["registered"] is False
    assert entry["evidence_count"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `lab/auditor/api/`: `pytest test_devices_crud.py -v`

Expected: FAIL — `POST /devices` returns 405 (route does not exist yet).

- [ ] **Step 3: Implement registration and the rewritten list endpoint**

In `lab/auditor/api/main.py`, add the import near the existing ones:

```python
from device_validation import (
    TIERS,
    ValidationError,
    validate_device_id,
    validate_host,
    validate_port,
    validate_service_type,
)
```

Replace the existing `get_devices` function (currently at `main.py:469`) and add the POST route:

```python
def _validate_device_payload(payload: dict) -> dict:
    device_id = validate_device_id(payload.get("device_id", ""))
    host = validate_host(payload.get("host", ""))

    tier = payload.get("tier", "unknown")
    if tier not in TIERS:
        raise ValidationError("tier", f"tier must be one of {', '.join(TIERS)}")

    display_name = payload.get("display_name", "")
    if not isinstance(display_name, str) or not display_name.strip():
        raise ValidationError("display_name", "display_name is required")

    raw_services = payload.get("services", [])
    if not isinstance(raw_services, list) or not raw_services:
        raise ValidationError("services", "at least one service is required")

    services = []
    for service in raw_services:
        published = service.get("published_port")
        services.append(
            {
                "service_type": validate_service_type(service.get("service_type", "")),
                "port": validate_port(service.get("port")),
                "published_port": (
                    validate_port(published, "published_port")
                    if published is not None
                    else None
                ),
                "enabled": bool(service.get("enabled", True)),
            }
        )

    return {
        "device_id": device_id,
        "display_name": display_name.strip(),
        "description": payload.get("description", "") or "",
        "tier": tier,
        "host": host,
        "vendor": payload.get("vendor"),
        "model": payload.get("model"),
        "location": payload.get("location"),
        "owner": payload.get("owner"),
        "notes": payload.get("notes"),
        "services": services,
    }


def _services_for(conn, device_id: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, service_type, port, published_port, enabled
        FROM device_services WHERE device_id = %s ORDER BY id
        """,
        (device_id,),
    ).fetchall()
    return [
        {
            "id": r[0],
            "service_type": r[1],
            "port": r[2],
            "published_port": r[3],
            "enabled": r[4],
        }
        for r in rows
    ]


@app.post("/devices", status_code=201)
def create_device(payload: dict) -> dict:
    try:
        device = _validate_device_payload(payload)
    except ValidationError as exc:
        return JSONResponse(
            status_code=400, content={"field": exc.field, "detail": exc.message}
        )

    conn = get_connection()
    try:
        exists = conn.execute(
            "SELECT 1 FROM devices WHERE device_id = %s", (device["device_id"],)
        ).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="device_id already registered")

        conn.execute(
            """
            INSERT INTO devices (device_id, display_name, description, tier, host,
                                 vendor, model, location, owner, notes, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'manual')
            """,
            (
                device["device_id"], device["display_name"], device["description"],
                device["tier"], device["host"], device["vendor"], device["model"],
                device["location"], device["owner"], device["notes"],
            ),
        )
        for service in device["services"]:
            conn.execute(
                """
                INSERT INTO device_services (device_id, service_type, port, published_port, enabled)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    device["device_id"], service["service_type"], service["port"],
                    service["published_port"], service["enabled"],
                ),
            )
        conn.commit()
        services = _services_for(conn, device["device_id"])
    finally:
        conn.close()

    return {**device, "source": "manual", "services": services, "registered": True}


@app.get("/devices")
def get_devices() -> list[dict]:
    conn = get_connection()
    try:
        # Registered devices LEFT JOINed to counts, UNIONed with orphan
        # device_ids that only exist in evidence/verdicts. The orphan half
        # preserves the old guarantee that no evidence is ever invisible.
        rows = conn.execute(
            """
            SELECT
                ids.device_id,
                d.display_name, d.description, d.tier, d.host,
                d.vendor, d.model, d.location, d.owner, d.notes, d.source,
                (d.device_id IS NOT NULL) AS registered,
                COALESCE(e.evidence_count, 0),
                COALESCE(v.verdict_count, 0)
            FROM (
                SELECT device_id FROM devices
                UNION SELECT device_id FROM evidence
                UNION SELECT device_id FROM verdicts
            ) ids
            LEFT JOIN devices d ON d.device_id = ids.device_id
            LEFT JOIN (
                SELECT device_id, COUNT(*) AS evidence_count FROM evidence GROUP BY device_id
            ) e ON e.device_id = ids.device_id
            LEFT JOIN (
                SELECT device_id, COUNT(*) AS verdict_count FROM verdicts GROUP BY device_id
            ) v ON v.device_id = ids.device_id
            ORDER BY ids.device_id
            """
        ).fetchall()

        devices = []
        for r in rows:
            device_id = r[0]
            devices.append(
                {
                    "device_id": device_id,
                    "display_name": r[1] or device_id,
                    "description": r[2] or "",
                    "tier": r[3] or "unknown",
                    "host": r[4],
                    "vendor": r[5], "model": r[6], "location": r[7],
                    "owner": r[8], "notes": r[9], "source": r[10],
                    "registered": r[11],
                    "evidence_count": r[12],
                    "verdict_count": r[13],
                    "services": _services_for(conn, device_id) if r[11] else [],
                }
            )
    finally:
        conn.close()
    return devices
```

- [ ] **Step 4: Run tests to verify they pass**

Run from `lab/auditor/api/`: `pytest test_devices_crud.py -v`

Expected: PASS, 6 tests.

- [ ] **Step 5: Confirm nothing else regressed**

Run from `lab/auditor/api/`: `pytest -v`

Expected: all pre-existing API tests still PASS. `test_devices_summary.py` exercises the old `GET /devices` shape — if it fails because it asserts the old response, update its assertions to the new shape (`registered`, `services` added; `device_id`, `evidence_count`, `verdict_count` unchanged).

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/api/main.py lab/auditor/api/test_devices_crud.py lab/auditor/api/test_devices_summary.py
git commit -m "feat(api): add POST /devices and read the device list from the table

GET /devices now UNIONs registered devices with orphan device_ids still
present in evidence/verdicts, so moving to a table cannot make existing
evidence invisible."
```

---

### Task 4: Device detail, update, delete, and service management

**Files:**
- Modify: `lab/auditor/api/main.py`
- Modify: `lab/auditor/api/test_devices_crud.py`

**Interfaces:**
- Consumes: Task 3's `_validate_device_payload`, `_services_for`
- Produces: `GET /devices/{device_id}` → `{device, services, evidence, verdicts, scan_jobs}`; `PATCH /devices/{device_id}`; `DELETE /devices/{device_id}`; `POST /devices/{device_id}/services`; `DELETE /devices/{device_id}/services/{service_id}`

- [ ] **Step 1: Write the failing tests**

Append to `lab/auditor/api/test_devices_crud.py`:

```python
def test_device_detail_returns_related_records(postgres_url):
    client.post("/devices", json=_payload())
    conn = psycopg.connect(postgres_url)
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-DETAIL-1', 'test-camera', 'TEST-NET-PORTSCAN', 'nmap', '7.94',
                'nmap -sV test-camera', now(), 'open ports', '{}'::jsonb,
                'document-store/raw/d.txt', 'high', 'aaa')
        """
    )
    conn.commit()
    conn.close()

    body = client.get("/devices/test-camera").json()
    assert body["device"]["display_name"] == "Test Camera"
    assert len(body["services"]) == 1
    assert len(body["evidence"]) == 1
    assert body["evidence"][0]["evidence_id"] == "EV-DETAIL-1"
    assert body["verdicts"] == []


def test_device_detail_404_for_unknown_device():
    assert client.get("/devices/nope").status_code == 404


def test_patch_updates_metadata_but_not_device_id():
    client.post("/devices", json=_payload())
    response = client.patch(
        "/devices/test-camera", json={"location": "Rack 3", "device_id": "hacked"}
    )
    assert response.status_code == 200
    assert response.json()["location"] == "Rack 3"
    assert response.json()["device_id"] == "test-camera"
    assert client.get("/devices/hacked").status_code == 404


def test_delete_removes_device_and_services_but_keeps_evidence(postgres_url):
    client.post("/devices", json=_payload())
    conn = psycopg.connect(postgres_url)
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-KEEP-1', 'test-camera', 'TEST-NET-PORTSCAN', 'nmap', '7.94',
                'nmap -sV test-camera', now(), 'keep me', '{}'::jsonb,
                'document-store/raw/k.txt', 'high', 'bbb')
        """
    )
    conn.commit()
    conn.close()

    assert client.delete("/devices/test-camera").status_code == 204

    # Evidence survives; the device reappears as unregistered.
    entry = next(d for d in client.get("/devices").json() if d["device_id"] == "test-camera")
    assert entry["registered"] is False
    assert entry["evidence_count"] == 1

    conn = psycopg.connect(postgres_url)
    remaining = conn.execute(
        "SELECT COUNT(*) FROM device_services WHERE device_id = 'test-camera'"
    ).fetchone()[0]
    conn.close()
    assert remaining == 0


def test_add_and_remove_a_service():
    client.post("/devices", json=_payload())
    added = client.post(
        "/devices/test-camera/services",
        json={"service_type": "mqtt", "port": 1883},
    )
    assert added.status_code == 201
    service_id = added.json()["id"]
    assert len(client.get("/devices/test-camera").json()["services"]) == 2

    assert client.delete(f"/devices/test-camera/services/{service_id}").status_code == 204
    assert len(client.get("/devices/test-camera").json()["services"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `lab/auditor/api/`: `pytest test_devices_crud.py -v -k "detail or patch or delete or service"`

Expected: FAIL — routes return 404/405.

- [ ] **Step 3: Implement the routes**

Add to `lab/auditor/api/main.py`:

```python
PATCHABLE_DEVICE_FIELDS = (
    "display_name", "description", "tier", "host",
    "vendor", "model", "location", "owner", "notes",
)


def _device_row(conn, device_id: str) -> dict | None:
    row = conn.execute(
        """
        SELECT device_id, display_name, description, tier, host, vendor, model,
               location, owner, notes, source, created_at, updated_at
        FROM devices WHERE device_id = %s
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    keys = (
        "device_id", "display_name", "description", "tier", "host", "vendor",
        "model", "location", "owner", "notes", "source", "created_at", "updated_at",
    )
    device = dict(zip(keys, row))
    device["created_at"] = device["created_at"].isoformat()
    device["updated_at"] = device["updated_at"].isoformat()
    return device


@app.get("/devices/{device_id}")
def get_device_detail(device_id: str) -> dict:
    validate_device_id(device_id)
    conn = get_connection()
    try:
        device = _device_row(conn, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")

        evidence = conn.execute(
            """
            SELECT evidence_id, test_id, tool, finding, confidence, timestamp
            FROM evidence WHERE device_id = %s ORDER BY timestamp DESC
            """,
            (device_id,),
        ).fetchall()
        verdicts = conn.execute(
            """
            SELECT verdict_id, control_id, status, severity, reason, timestamp
            FROM verdicts WHERE device_id = %s ORDER BY control_id
            """,
            (device_id,),
        ).fetchall()
        jobs = conn.execute(
            """
            SELECT id, test_id, status, created_at
            FROM scan_jobs WHERE device_id = %s ORDER BY created_at DESC LIMIT 25
            """,
            (device_id,),
        ).fetchall()
        services = _services_for(conn, device_id)
    finally:
        conn.close()

    return {
        "device": device,
        "services": services,
        "evidence": [
            {
                "evidence_id": r[0], "test_id": r[1], "tool": r[2],
                "finding": r[3], "confidence": r[4], "timestamp": r[5].isoformat(),
            }
            for r in evidence
        ],
        "verdicts": [
            {
                "verdict_id": r[0], "control_id": r[1], "status": r[2],
                "severity": r[3], "reason": r[4], "timestamp": r[5].isoformat(),
            }
            for r in verdicts
        ],
        "scan_jobs": [
            {"id": r[0], "test_id": r[1], "status": r[2], "created_at": r[3].isoformat()}
            for r in jobs
        ],
    }


@app.patch("/devices/{device_id}")
def update_device(device_id: str, payload: dict) -> dict:
    validate_device_id(device_id)
    updates = {k: v for k, v in payload.items() if k in PATCHABLE_DEVICE_FIELDS}
    if not updates:
        raise HTTPException(status_code=400, detail="no updatable fields supplied")

    try:
        if "host" in updates:
            validate_host(updates["host"])
        if "tier" in updates and updates["tier"] not in TIERS:
            raise ValidationError("tier", f"tier must be one of {', '.join(TIERS)}")
    except ValidationError as exc:
        return JSONResponse(
            status_code=400, content={"field": exc.field, "detail": exc.message}
        )

    assignments = ", ".join(f"{field} = %s" for field in updates)
    conn = get_connection()
    try:
        result = conn.execute(
            f"UPDATE devices SET {assignments}, updated_at = now() WHERE device_id = %s",
            (*updates.values(), device_id),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="device not found")
        conn.commit()
        device = _device_row(conn, device_id)
        device["services"] = _services_for(conn, device_id)
    finally:
        conn.close()
    return device


@app.delete("/devices/{device_id}", status_code=204)
def delete_device(device_id: str) -> None:
    validate_device_id(device_id)
    conn = get_connection()
    try:
        # Cascades to device_services only. evidence/verdicts have no FK to
        # devices and are immutable audit records - they are never touched.
        result = conn.execute("DELETE FROM devices WHERE device_id = %s", (device_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="device not found")
        conn.commit()
    finally:
        conn.close()


@app.post("/devices/{device_id}/services", status_code=201)
def add_device_service(device_id: str, payload: dict) -> dict:
    validate_device_id(device_id)
    try:
        service_type = validate_service_type(payload.get("service_type", ""))
        port = validate_port(payload.get("port"))
        published = payload.get("published_port")
        published_port = (
            validate_port(published, "published_port") if published is not None else None
        )
    except ValidationError as exc:
        return JSONResponse(
            status_code=400, content={"field": exc.field, "detail": exc.message}
        )

    conn = get_connection()
    try:
        if _device_row(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="device not found")
        row = conn.execute(
            """
            INSERT INTO device_services (device_id, service_type, port, published_port)
            VALUES (%s, %s, %s, %s) RETURNING id, service_type, port, published_port, enabled
            """,
            (device_id, service_type, port, published_port),
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    return {
        "id": row[0], "service_type": row[1], "port": row[2],
        "published_port": row[3], "enabled": row[4],
    }


@app.delete("/devices/{device_id}/services/{service_id}", status_code=204)
def delete_device_service(device_id: str, service_id: int) -> None:
    validate_device_id(device_id)
    conn = get_connection()
    try:
        result = conn.execute(
            "DELETE FROM device_services WHERE device_id = %s AND id = %s",
            (device_id, service_id),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="service not found")
        conn.commit()
    finally:
        conn.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run from `lab/auditor/api/`: `pytest test_devices_crud.py -v`

Expected: PASS, 11 tests.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/api/main.py lab/auditor/api/test_devices_crud.py
git commit -m "feat(api): add device detail, update, delete and service routes

Deleting a device cascades to device_services only; evidence and verdicts
are immutable audit records and survive deregistration."
```

---

### Task 5: Seed the six existing devices

**Files:**
- Create: `policies/engine/seed_devices.py`
- Create: `policies/engine/test_seed_devices.py`

**Interfaces:**
- Consumes: the `devices`/`device_services` tables from Task 1
- Produces: `SEED_DEVICES: list[dict]`, `seed(conn) -> int` (returns count of devices inserted; 0 on a second run)

> **`telnet-sim` metadata is newly authored**, not copied — it has no `deviceMeta.ts` entry today but *is* in `scan_tests.py`'s nmap `allowed_devices`, so omitting it would silently drop a working scan target. Review its wording on sight.

- [ ] **Step 1: Write the failing tests**

Create `policies/engine/test_seed_devices.py`:

```python
import psycopg
import pytest

from policies.engine.seed_devices import SEED_DEVICES, seed

TEST_DB_URL = "postgresql://auditor:auditor-lab-pw@localhost:55432/auditor"


@pytest.fixture
def conn():
    connection = psycopg.connect(TEST_DB_URL)
    connection.execute("TRUNCATE device_services, devices RESTART IDENTITY CASCADE")
    connection.commit()
    yield connection
    connection.close()


def test_seeds_all_six_devices(conn):
    assert seed(conn) == 6
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    assert count == 6


def test_second_run_is_a_noop(conn):
    seed(conn)
    assert seed(conn) == 0
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    assert count == 6


def test_all_seeded_devices_marked_seeded(conn):
    seed(conn)
    rows = conn.execute("SELECT source FROM devices").fetchall()
    assert all(r[0] == "seeded" for r in rows)


def test_published_ports_match_dev_overlay(conn):
    seed(conn)
    row = conn.execute(
        """
        SELECT port, published_port FROM device_services
        WHERE device_id = 'device-partial'
        """
    ).fetchone()
    assert row == (443, 8082)


def test_telnet_sim_seeded_with_port_23(conn):
    seed(conn)
    row = conn.execute(
        "SELECT service_type, port FROM device_services WHERE device_id = 'telnet-sim'"
    ).fetchone()
    assert row == ("telnet", 23)


def test_device_ids_are_exactly_the_committed_strings():
    # These strings are referenced byte-for-byte by committed Day-2 evidence.
    assert {d["device_id"] for d in SEED_DEVICES} == {
        "device-insecure", "device-partial", "device-hardened",
        "mqtt-broker-insecure", "mqtt-broker-secure", "telnet-sim",
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run from the repo root: `pytest policies/engine/test_seed_devices.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'policies.engine.seed_devices'`

(If Postgres is not running, start the scratch container first:
`docker run -d --rm --name auditor-api-test-db -e POSTGRES_DB=auditor -e POSTGRES_USER=auditor -e POSTGRES_PASSWORD=auditor-lab-pw -p 55432:5432 postgres:16-alpine`
then apply `lab/auditor/db/migrations/001-devices.sql` to it.)

- [ ] **Step 3: Write the implementation**

Create `policies/engine/seed_devices.py`:

```python
"""Seeds the six pre-existing lab devices into the devices tables.

Idempotent: safe to run repeatedly, because it will be - once against the
local dev database and once against the PC's real one (init.sql does not
re-run on an initialized volume; see docs/errors/021).

device_id values here are load-bearing: committed Day-2 evidence references
them byte-for-byte. This module only ever INSERTs into devices and
device_services - it never touches evidence or verdicts.

Labels, descriptions and tiers for the first five are lifted verbatim from
the frontend's former deviceMeta.ts. telnet-sim's metadata is newly authored:
it never had a device card, but it is a real nmap scan target.
"""

SEED_DEVICES = [
    {
        "device_id": "device-insecure",
        "display_name": "Smart Camera — Insecure",
        "description": "Default creds, plain HTTP, Telnet, unencrypted MQTT, hard-coded API key.",
        "tier": "insecure",
        "host": "device-insecure",
        "services": [{"service_type": "http", "port": 80, "published_port": 8081}],
    },
    {
        "device_id": "device-partial",
        "display_name": "Smart Camera — Partially Hardened",
        "description": "Telnet removed, HTTPS with a weak cert, MQTT still unencrypted.",
        "tier": "partial",
        "host": "device-partial",
        "services": [{"service_type": "https", "port": 443, "published_port": 8082}],
    },
    {
        "device_id": "device-hardened",
        "display_name": "Smart Camera — Hardened",
        "description": "HTTPS only, strong creds, MQTT over TLS, signed firmware.",
        "tier": "hardened",
        "host": "device-hardened",
        "services": [{"service_type": "https", "port": 443, "published_port": 8083}],
    },
    {
        "device_id": "mqtt-broker-insecure",
        "display_name": "MQTT Broker — Insecure",
        "description": "Unauthenticated, plaintext MQTT on port 1883.",
        "tier": "insecure",
        "host": "mqtt-broker-insecure",
        "services": [{"service_type": "mqtt", "port": 1883, "published_port": 18830}],
    },
    {
        "device_id": "mqtt-broker-secure",
        "display_name": "MQTT Broker — Secure",
        "description": "TLS-only MQTT on port 8883 with certificate auth.",
        "tier": "hardened",
        "host": "mqtt-broker-secure",
        "services": [{"service_type": "mqtts", "port": 8883, "published_port": None}],
    },
    {
        "device_id": "telnet-sim",
        "display_name": "Telnet Service Simulator",
        "description": "Standalone legacy Telnet service on port 23, used as an insecure-protocol scan target.",
        "tier": "insecure",
        "host": "telnet-sim",
        "services": [{"service_type": "telnet", "port": 23, "published_port": None}],
    },
]


def seed(conn) -> int:
    """Insert any missing seed devices. Returns how many devices were inserted."""
    inserted = 0
    for device in SEED_DEVICES:
        result = conn.execute(
            """
            INSERT INTO devices (device_id, display_name, description, tier, host, source)
            VALUES (%s, %s, %s, %s, %s, 'seeded')
            ON CONFLICT (device_id) DO NOTHING
            """,
            (
                device["device_id"], device["display_name"], device["description"],
                device["tier"], device["host"],
            ),
        )
        if result.rowcount == 0:
            continue
        inserted += 1
        for service in device["services"]:
            conn.execute(
                """
                INSERT INTO device_services (device_id, service_type, port, published_port)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (device_id, service_type, port) DO NOTHING
                """,
                (
                    device["device_id"], service["service_type"],
                    service["port"], service["published_port"],
                ),
            )
    conn.commit()
    return inserted


if __name__ == "__main__":
    import os

    import psycopg

    url = os.environ["DATABASE_URL"]
    connection = psycopg.connect(url)
    try:
        print(f"Seeded {seed(connection)} devices")
    finally:
        connection.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run from the repo root: `pytest policies/engine/test_seed_devices.py -v`

Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add policies/engine/seed_devices.py policies/engine/test_seed_devices.py
git commit -m "feat(policies): seed the six existing lab devices

Idempotent, INSERT-only. device_id strings are byte-identical to those
referenced by committed Day-2 evidence."
```

---

### Task 6: Make the scan catalog service-aware

**Files:**
- Modify: `policies/catalog/scan_tests.py`
- Modify: `policies/catalog/test_scan_tests.py`

**Interfaces:**
- Consumes: nothing new
- Produces: each `SCAN_CATALOG` entry gains `applicable_service_types: tuple[str, ...]` and loses `allowed_devices`; `build_command(target: dict) -> list[str]` where `target = {"device_id": str, "host": str, "service_type": str, "port": int}`; `is_applicable(target: dict, test_id: str) -> bool` replaces `is_allowed`

- [ ] **Step 1: Write the failing tests**

Replace the contents of `policies/catalog/test_scan_tests.py` with:

```python
from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable

HTTP_TARGET = {
    "device_id": "device-insecure", "host": "device-insecure",
    "service_type": "http", "port": 80,
}
MQTT_TARGET = {
    "device_id": "mqtt-broker-insecure", "host": "mqtt-broker-insecure",
    "service_type": "mqtt", "port": 1883,
}


def test_portscan_applies_to_any_service_type():
    assert is_applicable(HTTP_TARGET, "TEST-NET-PORTSCAN")
    assert is_applicable(MQTT_TARGET, "TEST-NET-PORTSCAN")


def test_http_tests_do_not_apply_to_mqtt():
    assert not is_applicable(MQTT_TARGET, "TEST-AUTH-DEFAULT-CREDS")
    assert not is_applicable(MQTT_TARGET, "TEST-HTTP-HEADERS")


def test_http_tests_apply_to_http_services():
    assert is_applicable(HTTP_TARGET, "TEST-AUTH-DEFAULT-CREDS")
    assert is_applicable(HTTP_TARGET, "TEST-HTTP-HEADERS")


def test_unknown_test_id_is_never_applicable():
    assert not is_applicable(HTTP_TARGET, "TEST-DOES-NOT-EXIST")


def test_login_command_uses_target_scheme_and_host():
    command = SCAN_CATALOG["TEST-AUTH-DEFAULT-CREDS"]["build_command"](HTTP_TARGET)
    assert command[0] == "curl"
    assert "http://device-insecure/login" in command
    # argv list, never a shell string
    assert all(isinstance(part, str) for part in command)


def test_https_target_builds_https_url_with_insecure_flag():
    target = {
        "device_id": "device-hardened", "host": "device-hardened",
        "service_type": "https", "port": 443,
    }
    command = SCAN_CATALOG["TEST-HTTP-HEADERS"]["build_command"](target)
    assert "https://device-hardened/" in command
    assert "-k" in command  # self-signed lab certs


def test_portscan_targets_the_service_port():
    command = SCAN_CATALOG["TEST-NET-PORTSCAN"]["build_command"](MQTT_TARGET)
    assert command[0] == "nmap"
    assert "mqtt-broker-insecure" in command
```

- [ ] **Step 2: Run tests to verify they fail**

Run from the repo root: `pytest policies/catalog/test_scan_tests.py -v`

Expected: FAIL — `ImportError: cannot import name 'is_applicable'`

- [ ] **Step 3: Rewrite the catalog**

In `policies/catalog/scan_tests.py`, delete the `DEVICE_SCHEME` dict and replace the command builders and catalog. Update the module docstring's first paragraph to reflect the new boundary:

```python
"""Whitelisted scan tests for the dashboard's live "Run Scan" feature.

Security boundary: test_id is validated against this fixed catalog, and the
target host/port is validated by device_validation (172.30.0.0/24 or a
container name, never infrastructure) on both the API and worker sides.
Commands are built as argv lists (never a shell string), so even a bypassed
validation has no shell-injection surface. auditor-api never executes a
command itself - it only ever creates/reads scan_jobs rows; auditor-worker is
the sole executor, and it re-validates before running anything.

Finding text is deliberately NOT produced here. Observations are simple,
mechanical parses of real tool output (port numbers, string matches) - the
same category of fact a human would read off the screen, just automated.
The security *interpretation* (the "finding") is still typed by a human in
the dashboard before evidence is recorded, matching the CLI-driven flow
this mirrors (record_evidence.py).
"""

HTTP_SERVICE_TYPES = ("http", "https")
ALL_SERVICE_TYPES = ("http", "https", "mqtt", "mqtts", "telnet", "ssh")


def _scheme_for(target: dict) -> str:
    return "https" if target["service_type"] == "https" else "http"


def _nmap_command(target: dict) -> list[str]:
    port = target["port"]
    return ["nmap", "-sV", "-p", str(port), target["host"]]


def _login_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = ["-s", "-k"] if scheme == "https" else ["-s"]
    return [
        "curl", *flags, "-X", "POST", f"{scheme}://{target['host']}/login",
        "-d", "username=admin&password=admin",
    ]


def _headers_command(target: dict) -> list[str]:
    scheme = _scheme_for(target)
    flags = ["-s", "-k", "-I"] if scheme == "https" else ["-s", "-I"]
    return ["curl", *flags, f"{scheme}://{target['host']}/"]
```

Keep `_parse_nmap_observations`, `_parse_login_observations` and `_parse_headers_observations` exactly as they are, but change each signature's first parameter from `device_id: str` to `target: dict` and use `target["device_id"]` wherever `device_id` was referenced.

Then replace the catalog and `is_allowed`:

```python
SCAN_CATALOG = {
    "TEST-NET-PORTSCAN": {
        "label": "Nmap service/port scan",
        "tool": "nmap",
        "tool_version_command": ["nmap", "--version"],
        "applicable_service_types": ALL_SERVICE_TYPES,
        "build_command": _nmap_command,
        "parse_observations": _parse_nmap_observations,
    },
    "TEST-AUTH-DEFAULT-CREDS": {
        "label": "Default credentials (admin/admin)",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _login_command,
        "parse_observations": _parse_login_observations,
    },
    "TEST-HTTP-HEADERS": {
        "label": "HTTP security headers",
        "tool": "curl",
        "tool_version_command": ["curl", "--version"],
        "applicable_service_types": HTTP_SERVICE_TYPES,
        "build_command": _headers_command,
        "parse_observations": _parse_headers_observations,
    },
}


def is_applicable(target: dict, test_id: str) -> bool:
    spec = SCAN_CATALOG.get(test_id)
    if spec is None:
        return False
    return target.get("service_type") in spec["applicable_service_types"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run from the repo root: `pytest policies/catalog/test_scan_tests.py -v`

Expected: PASS, 7 tests.

- [ ] **Step 5: Update the API's import of `is_allowed`**

`main.py` imports `is_allowed` (line 15). Change that import to `is_applicable` and update its call site in the scan-job creation route: it must now load the device's service from `device_services` and build the target dict before checking applicability. Find the scan-job POST route and replace its `is_allowed(device_id, test_id)` check with:

```python
    conn = get_connection()
    try:
        service = conn.execute(
            """
            SELECT d.host, s.service_type, s.port
            FROM devices d
            JOIN device_services s ON s.device_id = d.device_id
            WHERE d.device_id = %s AND s.enabled = true
            ORDER BY s.id LIMIT 1
            """,
            (device_id,),
        ).fetchone()
    finally:
        conn.close()

    if service is None:
        raise HTTPException(
            status_code=400, detail="device is not registered or has no enabled service"
        )

    target = {
        "device_id": device_id, "host": service[0],
        "service_type": service[1], "port": service[2],
    }
    if not is_applicable(target, test_id):
        raise HTTPException(
            status_code=400, detail="test does not apply to this device's services"
        )
```

- [ ] **Step 6: Run the full API suite**

Run from `lab/auditor/api/`: `pytest -v`

Expected: PASS. `test_scan_jobs.py` will need its fixtures updated to register a device first (previously any whitelisted `device_id` worked without a `devices` row).

- [ ] **Step 7: Commit**

```bash
git add policies/catalog/scan_tests.py policies/catalog/test_scan_tests.py lab/auditor/api/main.py lab/auditor/api/test_scan_jobs.py
git commit -m "refactor(scan): key tests by service type instead of device name

Replaces allowed_devices and DEVICE_SCHEME with applicable_service_types and
a resolved target dict, so a registered device is scannable without a code
change and an MQTT-only device is never offered an HTTP test."
```

---

### Task 7: Worker re-validation

**Files:**
- Modify: `lab/auditor/worker/job_runner.py`
- Modify: `lab/auditor/worker/test_job_runner.py`

**Interfaces:**
- Consumes: `device_validation.validate_host`, `validate_port`, `ValidationError`; `scan_tests.is_applicable`
- Produces: `resolve_target(job: dict) -> dict` raising `ValidationError` on an untrusted row
- Requires: `GET /scan-jobs` to include `host`, `service_type` and `port` on each job (Step 0 below)

> **Why Step 0 exists:** the worker gets jobs from `GET /scan-jobs?status=pending`, and the
> `scan_jobs` table has no `host`/`service_type`/`port` columns — it only stores `device_id` and
> `test_id`. The target must be resolved by joining `devices` and `device_services` in the API
> response. Without this, `resolve_target` raises `KeyError` on every job. The join is deliberately
> done in the *response* rather than by adding columns to `scan_jobs`, so the job record stays a
> pure audit row and the target is always resolved from current device state.

- [ ] **Step 0: Include the resolved target in the scan-jobs response**

In `lab/auditor/api/main.py`, find the `GET /scan-jobs` route and change its query to LEFT JOIN the
device tables, adding the three fields to each returned job:

```python
        rows = conn.execute(
            """
            SELECT j.id, j.device_id, j.test_id, j.status, j.tool, j.tool_version,
                   j.command, j.raw_output, j.observations, j.error, j.evidence_id,
                   j.created_at, j.updated_at,
                   d.host, s.service_type, s.port
            FROM scan_jobs j
            LEFT JOIN devices d ON d.device_id = j.device_id
            LEFT JOIN LATERAL (
                SELECT service_type, port FROM device_services
                WHERE device_id = j.device_id AND enabled = true
                ORDER BY id LIMIT 1
            ) s ON true
            WHERE (%s IS NULL OR j.status = %s)
            ORDER BY j.created_at
            """,
            (status, status),
        ).fetchall()
```

Map `host`, `service_type` and `port` into each job dict alongside the existing fields. Keep every
existing field in the response — `test_scan_jobs.py` asserts on them.

- [ ] **Step 1: Write the failing adversarial test**

Append to `lab/auditor/worker/test_job_runner.py`:

```python
import pytest

from device_validation import ValidationError
from job_runner import resolve_target


def test_rejects_malicious_host_written_directly_to_the_database():
    # Simulates a row that bypassed the API entirely (buggy or older version).
    # The worker must not trust the database.
    job = {
        "id": 1, "device_id": "evil", "test_id": "TEST-NET-PORTSCAN",
        "host": "--script=http-shellshock", "service_type": "http", "port": 80,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_rejects_out_of_range_host_from_the_database():
    job = {
        "id": 2, "device_id": "evil", "test_id": "TEST-NET-PORTSCAN",
        "host": "10.0.0.5", "service_type": "http", "port": 80,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_rejects_job_whose_device_was_deregistered():
    # The LEFT JOIN yields NULLs when the device row is gone, so the job must
    # fail cleanly rather than crash the poll loop.
    job = {
        "id": 4, "device_id": "gone", "test_id": "TEST-NET-PORTSCAN",
        "host": None, "service_type": None, "port": None,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_accepts_a_legitimate_target():
    job = {
        "id": 3, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "http", "port": 80,
    }
    assert resolve_target(job) == {
        "device_id": "device-insecure", "host": "device-insecure",
        "service_type": "http", "port": 80,
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `lab/auditor/worker/`: `pytest test_job_runner.py -v -k resolve_target`

Expected: FAIL — `ImportError: cannot import name 'resolve_target'`

- [ ] **Step 3: Implement re-validation**

In `lab/auditor/worker/job_runner.py`, change the import line and add `resolve_target`, then rewrite the guard in `process_job`:

```python
from device_validation import ValidationError, validate_host, validate_port
from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable


def resolve_target(job: dict) -> dict:
    """Re-validate the target read from the database before building a command.

    The database is untrusted input: a row written by a buggy or older API
    version must still be refused here. This is the second of the two
    independent validation passes.
    """
    return {
        "device_id": job["device_id"],
        "host": validate_host(job.get("host", "")),
        "service_type": job.get("service_type", ""),
        "port": validate_port(job.get("port")),
    }
```

Replace the `is_allowed` guard in `process_job` (currently `job_runner.py:44-47`) with:

```python
    try:
        target = resolve_target(job)
    except ValidationError as exc:
        _patch(job_id, {"status": "failed", "error": f"invalid target: {exc.message}"})
        return

    if not is_applicable(target, test_id):
        _patch(job_id, {"status": "failed", "error": "test does not apply to this service"})
        return

    spec = SCAN_CATALOG[test_id]
    _patch(job_id, {"status": "running"})

    command = spec["build_command"](target)
```

Also update the `parse_observations` call further down in the same function to pass `target` instead of `device_id`.

- [ ] **Step 4: Run tests to verify they pass**

Run from `lab/auditor/worker/`: `pytest test_job_runner.py -v`

Expected: PASS, all tests including the 3 new ones.

- [ ] **Step 5: Make the worker able to import `device_validation`**

`device_validation.py` lives in `lab/auditor/api/`. Mount it into the worker so both import the identical module. In `lab/docker-compose.yml`, add to `auditor-worker`'s volumes:

```yaml
      - ./auditor/api/device_validation.py:/work/device_validation.py:ro
```

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/worker/job_runner.py lab/auditor/worker/test_job_runner.py lab/docker-compose.yml
git commit -m "feat(worker): re-validate scan targets read from the database

The worker treats the DB as untrusted input, so a malicious row written
outside the API is still refused before any command is built."
```

---

### Task 8: Controls verdict rollup endpoint

**Files:**
- Modify: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/test_controls_verdicts.py`

**Interfaces:**
- Consumes: existing `GET /controls` machinery
- Produces: `GET /controls/{control_id}/verdicts` → `{"control_id": str, "verdicts": [{device_id, status, severity, reason, verdict_id, timestamp}], "counts": {"PASS": int, "FAIL": int, "PARTIAL": int, "INCONCLUSIVE": int}}`

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_controls_verdicts.py`:

```python
import psycopg
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


def _insert_verdict(conn, verdict_id, control_id, device_id, status):
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                              evidence_ids, reason, saudi_source, remediation, timestamp)
        VALUES (%s, %s, %s, %s, 'high', '[]'::jsonb, 'because', '{}'::jsonb, 'fix it', now())
        """,
        (verdict_id, control_id, device_id, status),
    )


def test_rollup_groups_devices_by_status(postgres_url):
    conn = psycopg.connect(postgres_url)
    _insert_verdict(conn, "V-1", "SA-IOT-002", "device-insecure", "FAIL")
    _insert_verdict(conn, "V-2", "SA-IOT-002", "device-hardened", "PASS")
    conn.commit()
    conn.close()

    body = client.get("/controls/SA-IOT-002/verdicts").json()
    assert body["control_id"] == "SA-IOT-002"
    assert body["counts"]["PASS"] == 1
    assert body["counts"]["FAIL"] == 1
    assert body["counts"]["PARTIAL"] == 0
    devices = {v["device_id"]: v["status"] for v in body["verdicts"]}
    assert devices == {"device-insecure": "FAIL", "device-hardened": "PASS"}


def test_control_with_no_verdicts_returns_zero_counts():
    body = client.get("/controls/SA-IOT-005/verdicts").json()
    assert body["verdicts"] == []
    assert body["counts"] == {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0}


def test_path_traversal_control_id_rejected():
    response = client.get("/controls/..%2F..%2Fetc%2Fpasswd/verdicts")
    assert response.status_code == 400
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `lab/auditor/api/`: `pytest test_controls_verdicts.py -v`

Expected: FAIL — route returns 404.

- [ ] **Step 3: Implement the rollup**

Add to `lab/auditor/api/main.py`. Reuse the existing `control_id` guard — find the regex already used by `GET /controls/{id}` (`^[A-Za-z0-9\-]+$`) and apply the same check before any work:

```python
VERDICT_STATUSES = ("PASS", "FAIL", "PARTIAL", "INCONCLUSIVE")


@app.get("/controls/{control_id}/verdicts")
def get_control_verdicts(control_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9\-]+", control_id):
        raise HTTPException(status_code=400, detail="invalid control_id")

    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT verdict_id, device_id, status, severity, reason, timestamp
            FROM verdicts WHERE control_id = %s ORDER BY device_id
            """,
            (control_id,),
        ).fetchall()
    finally:
        conn.close()

    verdicts = [
        {
            "verdict_id": r[0], "device_id": r[1], "status": r[2],
            "severity": r[3], "reason": r[4], "timestamp": r[5].isoformat(),
        }
        for r in rows
    ]
    counts = {status: 0 for status in VERDICT_STATUSES}
    for verdict in verdicts:
        if verdict["status"] in counts:
            counts[verdict["status"]] += 1

    return {"control_id": control_id, "verdicts": verdicts, "counts": counts}
```

- [ ] **Step 4: Run tests to verify they pass**

Run from `lab/auditor/api/`: `pytest test_controls_verdicts.py -v`

Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/api/main.py lab/auditor/api/test_controls_verdicts.py
git commit -m "feat(api): add per-control verdict rollup endpoint

Additive - GET /controls and /controls/{id} keep their existing shape."
```

---

### Task 9: Frontend API client and types

**Files:**
- Modify: `lab/auditor/web/src/lib/types.ts`
- Modify: `lab/auditor/web/src/lib/api.ts`
- Create: `lab/auditor/web/src/lib/serviceIcons.ts`
- Modify: `lab/auditor/web/src/lib/api.test.ts`

**Interfaces:**
- Consumes: Tasks 3, 4, 8 endpoints
- Produces: types `DeviceService`, `Device`, `DeviceDetail`, `ControlVerdictRollup`; functions `fetchDevices()`, `fetchDevice(id)`, `createDevice(payload)`, `updateDevice(id, patch)`, `deleteDevice(id)`, `fetchControlVerdicts(id)`; `serviceIcon(type)`

- [ ] **Step 1: Add the types**

Append to `lab/auditor/web/src/lib/types.ts`:

```typescript
export type ServiceType = "http" | "https" | "mqtt" | "mqtts" | "telnet" | "ssh";
export type DeviceTier = "insecure" | "partial" | "hardened" | "unknown";

export interface DeviceService {
  id: number;
  service_type: ServiceType;
  port: number;
  published_port: number | null;
  enabled: boolean;
}

export interface Device {
  device_id: string;
  display_name: string;
  description: string;
  tier: DeviceTier;
  host: string | null;
  vendor: string | null;
  model: string | null;
  location: string | null;
  owner: string | null;
  notes: string | null;
  source: "seeded" | "manual" | null;
  registered: boolean;
  evidence_count: number;
  verdict_count: number;
  services: DeviceService[];
}

export interface DeviceDetail {
  device: Device;
  services: DeviceService[];
  evidence: Array<{
    evidence_id: string;
    test_id: string;
    tool: string;
    finding: string;
    confidence: string;
    timestamp: string;
  }>;
  verdicts: Array<{
    verdict_id: string;
    control_id: string;
    status: string;
    severity: string;
    reason: string;
    timestamp: string;
  }>;
  scan_jobs: Array<{
    id: number;
    test_id: string;
    status: string;
    created_at: string;
  }>;
}

export interface ControlVerdictRollup {
  control_id: string;
  verdicts: Array<{
    verdict_id: string;
    device_id: string;
    status: string;
    severity: string;
    reason: string;
    timestamp: string;
  }>;
  counts: { PASS: number; FAIL: number; PARTIAL: number; INCONCLUSIVE: number };
}

export interface ApiFieldError {
  field: string;
  detail: string;
}
```

- [ ] **Step 2: Write the failing API client test**

Append to `lab/auditor/web/src/lib/api.test.ts`:

```typescript
import { describe, expect, it, vi, afterEach } from "vitest";
import { createDevice, fetchDevice } from "./api";

afterEach(() => vi.restoreAllMocks());

describe("device api", () => {
  it("posts a device and returns the created record", async () => {
    const created = { device_id: "test-camera", registered: true, services: [] };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => created,
      }),
    );
    const result = await createDevice({
      device_id: "test-camera",
      display_name: "Test Camera",
      tier: "insecure",
      host: "test-camera",
      services: [{ service_type: "http", port: 80, published_port: 8091 }],
    });
    expect(result.device_id).toBe("test-camera");
  });

  it("throws a field-tagged error on 400 so the form can highlight the field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ field: "host", detail: "IP must be inside 172.30.0.0/24" }),
      }),
    );
    await expect(
      createDevice({
        device_id: "bad",
        display_name: "Bad",
        tier: "unknown",
        host: "10.0.0.5",
        services: [{ service_type: "http", port: 80, published_port: null }],
      }),
    ).rejects.toMatchObject({ field: "host" });
  });

  it("fetches a single device detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ device: { device_id: "d1" }, evidence: [], verdicts: [] }),
      }),
    );
    const detail = await fetchDevice("d1");
    expect(detail.device.device_id).toBe("d1");
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run from `lab/auditor/web/`: `npm test -- api.test.ts`

Expected: FAIL — `createDevice` / `fetchDevice` are not exported.

- [ ] **Step 4: Implement the client functions**

Append to `lab/auditor/web/src/lib/api.ts`. Reuse the existing base-URL helper in that file (derived from `window.location`, per ERR-020) — do **not** introduce a hardcoded URL:

```typescript
import type {
  ControlVerdictRollup,
  Device,
  DeviceDetail,
  ApiFieldError,
} from "./types";

export interface CreateDevicePayload {
  device_id: string;
  display_name: string;
  description?: string;
  tier: string;
  host: string;
  vendor?: string | null;
  model?: string | null;
  location?: string | null;
  owner?: string | null;
  notes?: string | null;
  services: Array<{
    service_type: string;
    port: number;
    published_port: number | null;
  }>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    let body: Partial<ApiFieldError> = {};
    try {
      body = await response.json();
    } catch {
      // Non-JSON error body; fall through to the generic message.
    }
    const error = new Error(body.detail ?? `Request failed (${response.status})`);
    (error as Error & { field?: string }).field = body.field;
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function fetchDevices(): Promise<Device[]> {
  return request<Device[]>("/devices");
}

export function fetchDevice(deviceId: string): Promise<DeviceDetail> {
  return request<DeviceDetail>(`/devices/${deviceId}`);
}

export function createDevice(payload: CreateDevicePayload): Promise<Device> {
  return request<Device>("/devices", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateDevice(
  deviceId: string,
  patch: Partial<CreateDevicePayload>,
): Promise<Device> {
  return request<Device>(`/devices/${deviceId}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export function deleteDevice(deviceId: string): Promise<void> {
  return request<void>(`/devices/${deviceId}`, { method: "DELETE" });
}

export function fetchControlVerdicts(controlId: string): Promise<ControlVerdictRollup> {
  return request<ControlVerdictRollup>(`/controls/${controlId}/verdicts`);
}
```

> If `api.ts` does not already export a function named `apiBaseUrl`, use whatever the existing base-URL helper in that file is called and keep the name consistent.

- [ ] **Step 5: Create the icon mapping**

Create `lab/auditor/web/src/lib/serviceIcons.ts`. Icons are presentation, not data, so they stay in the frontend:

```typescript
import type { LucideIcon } from "lucide-react";
import { Globe, Lock, Radio, RadioTower, Terminal, KeyRound } from "lucide-react";
import type { ServiceType } from "./types";

const SERVICE_ICONS: Record<ServiceType, LucideIcon> = {
  http: Globe,
  https: Lock,
  mqtt: Radio,
  mqtts: RadioTower,
  telnet: Terminal,
  ssh: KeyRound,
};

export function serviceIcon(serviceType: ServiceType): LucideIcon {
  return SERVICE_ICONS[serviceType] ?? Globe;
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run from `lab/auditor/web/`: `npm test -- api.test.ts`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add lab/auditor/web/src/lib/types.ts lab/auditor/web/src/lib/api.ts lab/auditor/web/src/lib/api.test.ts lab/auditor/web/src/lib/serviceIcons.ts
git commit -m "feat(web): add device and control-rollup API client

Errors carry the API's field name so the registration form can highlight
the offending input rather than showing a generic toast."
```

---

### Task 10: Registration form and Devices page

**Files:**
- Create: `lab/auditor/web/src/components/devices/RegisterDeviceForm.tsx`
- Create: `lab/auditor/web/src/components/devices/RegisterDeviceForm.test.tsx`
- Modify: `lab/auditor/web/src/pages/DevicesPage.tsx`
- Modify: `lab/auditor/web/src/pages/DevicesPage.test.tsx`

**Interfaces:**
- Consumes: `createDevice`, `fetchDevices`, `serviceIcon`, `Device`, `DeviceService`
- Produces: `<RegisterDeviceForm onRegistered={(device: Device) => void} onCancel={() => void} />`

- [ ] **Step 1: Write the failing form tests**

Create `lab/auditor/web/src/components/devices/RegisterDeviceForm.test.tsx`:

```typescript
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, afterEach } from "vitest";
import RegisterDeviceForm from "./RegisterDeviceForm";
import * as api from "../../lib/api";

afterEach(() => vi.restoreAllMocks());

describe("RegisterDeviceForm", () => {
  it("submits the device with its services", async () => {
    const createDevice = vi
      .spyOn(api, "createDevice")
      .mockResolvedValue({ device_id: "test-camera" } as never);
    const onRegistered = vi.fn();

    render(<RegisterDeviceForm onRegistered={onRegistered} onCancel={() => {}} />);

    fireEvent.change(screen.getByLabelText(/device id/i), {
      target: { value: "test-camera" },
    });
    fireEvent.change(screen.getByLabelText(/display name/i), {
      target: { value: "Test Camera" },
    });
    fireEvent.change(screen.getByLabelText(/host/i), {
      target: { value: "test-camera" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register device/i }));

    await waitFor(() => expect(createDevice).toHaveBeenCalled());
    const payload = createDevice.mock.calls[0][0];
    expect(payload.device_id).toBe("test-camera");
    expect(payload.services.length).toBeGreaterThan(0);
    await waitFor(() => expect(onRegistered).toHaveBeenCalled());
  });

  it("shows the API error against the field that caused it", async () => {
    const error = new Error("IP must be inside 172.30.0.0/24") as Error & {
      field?: string;
    };
    error.field = "host";
    vi.spyOn(api, "createDevice").mockRejectedValue(error);

    render(<RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />);
    fireEvent.change(screen.getByLabelText(/device id/i), {
      target: { value: "bad" },
    });
    fireEvent.change(screen.getByLabelText(/display name/i), {
      target: { value: "Bad" },
    });
    fireEvent.change(screen.getByLabelText(/host/i), {
      target: { value: "10.0.0.5" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register device/i }));

    expect(await screen.findByText(/172\.30\.0\.0\/24/)).toBeInTheDocument();
  });

  it("can add and remove service rows", async () => {
    render(<RegisterDeviceForm onRegistered={() => {}} onCancel={() => {}} />);
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /add service/i }));
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(2);
    fireEvent.click(screen.getAllByRole("button", { name: /remove service/i })[1]);
    expect(screen.getAllByLabelText(/service type/i)).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run from `lab/auditor/web/`: `npm test -- RegisterDeviceForm`

Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement the form**

Create `lab/auditor/web/src/components/devices/RegisterDeviceForm.tsx`. Match the existing dark theme, amber accent, and lucide icons used by `RunScanPage.tsx`:

```typescript
import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { createDevice } from "../../lib/api";
import type { Device, ServiceType } from "../../lib/types";

const SERVICE_TYPES: ServiceType[] = ["http", "https", "mqtt", "mqtts", "telnet", "ssh"];
const TIERS = ["insecure", "partial", "hardened", "unknown"];

// Quick-picks keep the services repeater from being tedious for the common cases.
const QUICK_PICKS: Record<string, ServiceRow[]> = {
  "Smart camera (HTTP)": [{ service_type: "http", port: "80", published_port: "" }],
  "Smart camera (HTTPS)": [{ service_type: "https", port: "443", published_port: "" }],
  "MQTT broker": [{ service_type: "mqtt", port: "1883", published_port: "" }],
  "MQTT broker (TLS)": [{ service_type: "mqtts", port: "8883", published_port: "" }],
};

interface ServiceRow {
  service_type: ServiceType;
  port: string;
  published_port: string;
}

interface Props {
  onRegistered: (device: Device) => void;
  onCancel: () => void;
}

const EMPTY_SERVICE: ServiceRow = { service_type: "http", port: "80", published_port: "" };

export default function RegisterDeviceForm({ onRegistered, onCancel }: Props) {
  const [fields, setFields] = useState({
    device_id: "",
    display_name: "",
    description: "",
    tier: "unknown",
    host: "",
    vendor: "",
    model: "",
    location: "",
    owner: "",
    notes: "",
  });
  const [services, setServices] = useState<ServiceRow[]>([{ ...EMPTY_SERVICE }]);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function setField(name: string, value: string) {
    setFields((current) => ({ ...current, [name]: value }));
  }

  function updateService(index: number, patch: Partial<ServiceRow>) {
    setServices((current) =>
      current.map((row, i) => (i === index ? { ...row, ...patch } : row)),
    );
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const device = await createDevice({
        ...fields,
        services: services.map((row) => ({
          service_type: row.service_type,
          port: Number(row.port),
          published_port: row.published_port ? Number(row.published_port) : null,
        })),
      });
      onRegistered(device);
    } catch (caught) {
      const err = caught as Error & { field?: string };
      setError({ field: err.field, message: err.message });
    } finally {
      setSubmitting(false);
    }
  }

  const fieldError = (name: string) =>
    error?.field === name ? (
      <p className="mt-1 text-sm text-red-400">{error.message}</p>
    ) : null;

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block">
          <span className="text-sm text-slate-300">Device ID</span>
          <input
            aria-label="Device ID"
            value={fields.device_id}
            onChange={(e) => setField("device_id", e.target.value)}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100"
            required
          />
          {fieldError("device_id")}
        </label>
        <label className="block">
          <span className="text-sm text-slate-300">Display name</span>
          <input
            aria-label="Display name"
            value={fields.display_name}
            onChange={(e) => setField("display_name", e.target.value)}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            required
          />
          {fieldError("display_name")}
        </label>
        <label className="block">
          <span className="text-sm text-slate-300">Host (container name or 172.30.0.x)</span>
          <input
            aria-label="Host"
            value={fields.host}
            onChange={(e) => setField("host", e.target.value)}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100"
            required
          />
          {fieldError("host")}
        </label>
        <label className="block">
          <span className="text-sm text-slate-300">Security tier</span>
          <select
            aria-label="Security tier"
            value={fields.tier}
            onChange={(e) => setField("tier", e.target.value)}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
          >
            {TIERS.map((tier) => (
              <option key={tier} value={tier}>{tier}</option>
            ))}
          </select>
          {fieldError("tier")}
        </label>
      </div>

      <label className="block">
        <span className="text-sm text-slate-300">Description</span>
        <textarea
          aria-label="Description"
          value={fields.description}
          onChange={(e) => setField("description", e.target.value)}
          rows={2}
          className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
        />
      </label>

      <div className="grid gap-4 sm:grid-cols-2">
        {(["vendor", "model", "location", "owner"] as const).map((name) => (
          <label key={name} className="block">
            <span className="text-sm capitalize text-slate-300">{name}</span>
            <input
              aria-label={name}
              value={fields[name]}
              onChange={(e) => setField(name, e.target.value)}
              className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
            />
          </label>
        ))}
      </div>

      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <span className="text-sm text-slate-300">Services</span>
          {Object.keys(QUICK_PICKS).map((label) => (
            <button
              key={label}
              type="button"
              onClick={() => setServices(QUICK_PICKS[label].map((row) => ({ ...row })))}
              className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:border-amber-500 hover:text-amber-400"
            >
              {label}
            </button>
          ))}
        </div>

        <div className="space-y-2">
          {services.map((row, index) => (
            <div key={index} className="flex flex-wrap items-end gap-2">
              <label className="block">
                <span className="text-xs text-slate-400">Service type</span>
                <select
                  aria-label="Service type"
                  value={row.service_type}
                  onChange={(e) =>
                    updateService(index, { service_type: e.target.value as ServiceType })
                  }
                  className="mt-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-100"
                >
                  {SERVICE_TYPES.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-xs text-slate-400">Port</span>
                <input
                  aria-label={`Port ${index + 1}`}
                  value={row.port}
                  onChange={(e) => updateService(index, { port: e.target.value })}
                  className="mt-1 w-24 rounded border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-sm text-slate-100"
                />
              </label>
              <label className="block">
                <span className="text-xs text-slate-400">Published port</span>
                <input
                  aria-label={`Published port ${index + 1}`}
                  value={row.published_port}
                  onChange={(e) => updateService(index, { published_port: e.target.value })}
                  className="mt-1 w-32 rounded border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-sm text-slate-100"
                />
              </label>
              <button
                type="button"
                aria-label="Remove service"
                onClick={() => setServices((c) => c.filter((_, i) => i !== index))}
                className="rounded border border-slate-700 p-2 text-slate-400 hover:border-red-500 hover:text-red-400"
              >
                <Trash2 size={16} />
              </button>
            </div>
          ))}
        </div>

        <button
          type="button"
          onClick={() => setServices((c) => [...c, { ...EMPTY_SERVICE }])}
          className="mt-2 inline-flex items-center gap-1 text-sm text-amber-400 hover:text-amber-300"
        >
          <Plus size={14} /> Add service
        </button>
        {fieldError("services")}
      </div>

      {error && !error.field && (
        <p className="text-sm text-red-400">{error.message}</p>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={submitting}
          className="rounded bg-amber-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-amber-400 disabled:opacity-50"
        >
          {submitting ? "Registering…" : "Register device"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-slate-500"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run from `lab/auditor/web/`: `npm test -- RegisterDeviceForm`

Expected: PASS, 3 tests.

- [ ] **Step 5: Wire the form into the Devices page**

Modify `lab/auditor/web/src/pages/DevicesPage.tsx`: add a "Register device" button that toggles the form, show a `registered`/`unregistered` badge per row, link each row to `/devices/:id`, and refetch after a successful registration. Keep the existing card/table styling. Unregistered rows render muted (`text-slate-500`) with a "Register" affordance.

- [ ] **Step 6: Update the Devices page test**

Modify `lab/auditor/web/src/pages/DevicesPage.test.tsx` to add a case asserting an unregistered device renders with an "Unregistered" label, using a fixture entry with `registered: false`.

- [ ] **Step 7: Run the full frontend suite**

Run from `lab/auditor/web/`: `npm test`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add lab/auditor/web/src/components/devices lab/auditor/web/src/pages/DevicesPage.tsx lab/auditor/web/src/pages/DevicesPage.test.tsx
git commit -m "feat(web): add device registration form and registry view

Validation errors from the API highlight the specific field that caused
them; unregistered devices with evidence stay visible and offer registration."
```

---

### Task 11: Device detail page

**Files:**
- Create: `lab/auditor/web/src/pages/DeviceDetailPage.tsx`
- Create: `lab/auditor/web/src/pages/DeviceDetailPage.test.tsx`
- Modify: `lab/auditor/web/src/App.tsx`

**Interfaces:**
- Consumes: `fetchDevice`, `DeviceDetail`, `serviceIcon`
- Produces: route `/devices/:deviceId`

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/src/pages/DeviceDetailPage.test.tsx`:

```typescript
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { describe, expect, it, vi, afterEach } from "vitest";
import DeviceDetailPage from "./DeviceDetailPage";
import * as api from "../lib/api";

afterEach(() => vi.restoreAllMocks());

const DETAIL = {
  device: {
    device_id: "device-insecure",
    display_name: "Smart Camera — Insecure",
    description: "Default creds, plain HTTP.",
    tier: "insecure",
    host: "device-insecure",
    vendor: "AcmeCam",
    model: null, location: null, owner: null, notes: null,
    source: "seeded", registered: true,
    evidence_count: 1, verdict_count: 1, services: [],
  },
  services: [
    { id: 1, service_type: "http", port: 80, published_port: 8081, enabled: true },
  ],
  evidence: [
    {
      evidence_id: "EV-1", test_id: "TEST-NET-PORTSCAN", tool: "nmap",
      finding: "Telnet exposed", confidence: "high",
      timestamp: "2026-07-08T10:00:00+00:00",
    },
  ],
  verdicts: [
    {
      verdict_id: "V-1", control_id: "SA-IOT-002", status: "FAIL",
      severity: "high", reason: "default creds accepted",
      timestamp: "2026-07-08T10:05:00+00:00",
    },
  ],
  scan_jobs: [],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/devices/device-insecure"]}>
      <Routes>
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("DeviceDetailPage", () => {
  it("shows the device, its services, evidence and verdicts together", async () => {
    vi.spyOn(api, "fetchDevice").mockResolvedValue(DETAIL as never);
    renderPage();

    expect(await screen.findByText("Smart Camera — Insecure")).toBeInTheDocument();
    expect(screen.getByText("AcmeCam")).toBeInTheDocument();
    expect(screen.getByText(/8081/)).toBeInTheDocument();
    expect(screen.getByText("Telnet exposed")).toBeInTheDocument();
    expect(screen.getByText("SA-IOT-002")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();
  });

  it("renders an error state when the device is missing", async () => {
    vi.spyOn(api, "fetchDevice").mockRejectedValue(new Error("device not found"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/device not found/i)).toBeInTheDocument(),
    );
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run from `lab/auditor/web/`: `npm test -- DeviceDetailPage`

Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement the page**

Create `lab/auditor/web/src/pages/DeviceDetailPage.tsx` using `useParams()` from `react-router`, the existing `useFetch` hook in `src/lib/useFetch.ts`, and the existing `Card`, `SeverityBadge`, `StatTile`, and `state.tsx` loading/error components. Sections in order: header (display name, tier badge, host, `registered`/`source`), inventory metadata grid (vendor, model, location, owner, notes), services list (icon via `serviceIcon`, `port` and `published_port` shown as distinct values), evidence table, verdicts table, scan history table. Reuse `EvidencePage`'s and `VerdictsPage`'s row markup so the styling matches.

- [ ] **Step 4: Add the route**

In `lab/auditor/web/src/App.tsx`, add inside the existing `<Routes>`:

```typescript
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
```

with the matching import at the top of the file.

- [ ] **Step 5: Run tests to verify they pass**

Run from `lab/auditor/web/`: `npm test -- DeviceDetailPage`

Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/web/src/pages/DeviceDetailPage.tsx lab/auditor/web/src/pages/DeviceDetailPage.test.tsx lab/auditor/web/src/App.tsx
git commit -m "feat(web): add device detail page

One page per device: inventory metadata, services, evidence, verdicts and
scan history."
```

---

### Task 12: Controls pages, and make Console + Run Scan data-driven

This task deletes the hardcoded modules. **It must run after Task 5's seed has been applied to the target database**, or the dashboard reads an empty table and every device disappears.

**Files:**
- Create: `lab/auditor/web/src/pages/ControlsPage.tsx` (+ `.test.tsx`)
- Create: `lab/auditor/web/src/pages/ControlDetailPage.tsx`
- Modify: `lab/auditor/web/src/pages/DeviceConsolePage.tsx` (+ `.test.tsx`)
- Modify: `lab/auditor/web/src/pages/RunScanPage.tsx` (+ `.test.tsx`)
- Modify: `lab/auditor/web/src/components/layout/Sidebar.tsx`, `src/App.tsx`
- Delete: `lab/auditor/web/src/lib/deviceMeta.ts`, `lab/auditor/web/src/lib/consoleDevices.ts`

**Interfaces:**
- Consumes: `fetchDevices`, `fetchControlVerdicts`, existing `fetchControls`
- Produces: routes `/controls` and `/controls/:controlId`

- [ ] **Step 1: Write the failing Controls page test**

Create `lab/auditor/web/src/pages/ControlsPage.test.tsx`:

```typescript
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi, afterEach } from "vitest";
import ControlsPage from "./ControlsPage";
import * as api from "../lib/api";

afterEach(() => vi.restoreAllMocks());

const CONTROLS = [
  {
    control_id: "SA-IOT-002",
    title: "Default credentials must be changed",
    severity: "high",
    saudi_source: { framework: "CGIoT-1:2024", reference: "2-1-3" },
  },
];

describe("ControlsPage", () => {
  it("lists controls with their Saudi source reference", async () => {
    vi.spyOn(api, "fetchControls").mockResolvedValue(CONTROLS as never);
    render(
      <MemoryRouter>
        <ControlsPage />
      </MemoryRouter>,
    );
    expect(await screen.findByText("SA-IOT-002")).toBeInTheDocument();
    expect(
      screen.getByText("Default credentials must be changed"),
    ).toBeInTheDocument();
    expect(screen.getByText(/CGIoT-1:2024/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run from `lab/auditor/web/`: `npm test -- ControlsPage`

Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement the Controls pages**

Create `ControlsPage.tsx` (list: control ID in mono, title, severity badge, `framework §reference`, PASS/FAIL counts, linking to detail) and `ControlDetailPage.tsx` (full control — applicability, required evidence, pass/fail conditions, remediation — plus the `fetchControlVerdicts` rollup showing which devices pass and fail, each device linking to its detail page). Reuse `VerdictsPage`'s status-colored markup.

- [ ] **Step 4: Add routes and the sidebar entry**

In `src/App.tsx` add:

```typescript
        <Route path="/controls" element={<ControlsPage />} />
        <Route path="/controls/:controlId" element={<ControlDetailPage />} />
```

In `src/components/layout/Sidebar.tsx` add a seventh nav item after Verdicts, importing `ShieldCheck` from lucide-react:

```typescript
  { to: "/controls", label: "Controls", icon: ShieldCheck, end: false },
```

- [ ] **Step 5: Make Device Console data-driven and delete the hardcoded modules**

Rewrite `DeviceConsolePage.tsx` to call `fetchDevices()` instead of importing `CONSOLE_DEVICES`. For each registered device, render a card per `http`/`https` service that has a non-null `published_port`; the base URL becomes `` `${service.service_type}://${window.location.hostname}:${service.published_port}` `` (same runtime-derivation pattern as ERR-020). Keep `CONSOLE_ENDPOINTS` and the existing `viewable`/`window.open` behavior exactly as they are. Devices with no browser-reachable HTTP service render an explanatory line instead of buttons.

Then delete both hardcoded modules:

```bash
git rm lab/auditor/web/src/lib/deviceMeta.ts lab/auditor/web/src/lib/consoleDevices.ts
```

Fix every remaining import of them — `grep -rn "deviceMeta\|consoleDevices" lab/auditor/web/src` must return nothing.

- [ ] **Step 6: Make Run Scan data-driven**

In `RunScanPage.tsx`, populate the device dropdown from `fetchDevices()` (registered devices only) and filter the offered tests by the device's service types, mirroring `applicable_service_types` from Task 6.

- [ ] **Step 7: Run the full frontend suite and typecheck**

Run from `lab/auditor/web/`:

```bash
npm test
npx tsc --noEmit
```

Expected: all tests PASS, no type errors. Update `DeviceConsolePage.test.tsx` and `RunScanPage.test.tsx` fixtures to the new API-driven shape.

- [ ] **Step 8: Commit**

```bash
git add -A lab/auditor/web/src
git commit -m "feat(web): add controls pages and make console/run-scan data-driven

Deletes deviceMeta.ts and consoleDevices.ts - device identity now comes from
the API alone, so a registered device gets console buttons and scan targets
with no code change."
```

---

### Task 13: Deploy and verify on the build PC

No new code. This is the step that decides whether the feature actually works, following the project's pattern that curl-passing and test-passing both missed bugs a real browser caught (the CORS bug, the unbundled fonts).

**Files:** none modified (unless verification finds a bug — then fix, and log it under `docs/errors/` per the project convention)

- [ ] **Step 1: Push and pull**

```bash
git push origin main
```

Then on the PC over ssh-mcp (PowerShell — use `;` not `&&`):

```powershell
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull
```

- [ ] **Step 2: Capture the pre-migration audit baseline**

```powershell
curl.exe -s http://localhost:8000/summary
```

Expected, and record it verbatim: `{"total_evidence": 12, "total_verdicts": 8, "verdicts_by_status": {"PASS": 4, "FAIL": 4, "PARTIAL": 0, "INCONCLUSIVE": 0}}`

- [ ] **Step 3: Apply the migration to the PC's existing volume**

```powershell
cd C:\Users\osama\Projects\kaust-iot-security-lab\lab; docker compose exec -T auditor-database psql -U auditor -d auditor -f - < ..\lab\auditor\db\migrations\001-devices.sql
```

Verify both tables exist:

```powershell
docker compose exec auditor-database psql -U auditor -d auditor -c "\dt"
```

Expected: `devices` and `device_services` present alongside `evidence`, `verdicts`, `scan_jobs`.

- [ ] **Step 4: Seed the six devices**

```powershell
docker compose exec -e DATABASE_URL=postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor auditor-worker python -m policies.engine.seed_devices
```

Expected: `Seeded 6 devices`. Run it a second time; expected: `Seeded 0 devices` (idempotency confirmed on the real database, not just in tests).

- [ ] **Step 5: Confirm the audit record is unchanged**

```powershell
curl.exe -s http://localhost:8000/summary
```

Expected: **byte-identical** to Step 2. If it differs, stop — the migration touched the audit record and must be investigated before going further.

- [ ] **Step 6: Rebuild and recreate the stack**

```powershell
docker compose build auditor-api auditor-worker auditor-web; docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate
docker compose ps
```

Expected: 11 services Up.

- [ ] **Step 7: Drive the acceptance flow in a real browser with Playwright**

Against `http://100.99.182.30:8080`:

1. Open `/devices` — all six seeded devices appear, correctly labelled.
2. Register a new device through the form (`device_id: test-camera`, host `device-insecure`, service `http:80` published `8081`) — it appears in the list.
3. Open `/devices/test-camera` — metadata, services and empty evidence/verdict sections render.
4. Attempt to register a device with host `10.0.0.5` — the form shows the field-level rejection.
5. Open `/console` — device cards render from the API, and clicking "Device info" on `device-insecure` returns live data.
6. Open `/run-scan` — run a real nmap scan against `device-insecure`, type a finding, record evidence.
7. Open `/devices/device-insecure` — the new evidence appears.
8. Open `/controls` and `/controls/SA-IOT-002` — the control renders with its PASS/FAIL device rollup.

- [ ] **Step 8: Capture screenshots and get sign-off**

Screenshot each new/changed screen (Devices with the form open, Device Detail, Controls list, Control detail, Console, Run Scan) and present them to the owner. **Do not mark this task complete without explicit visual sign-off** — a passing `tsc` and green tests are not sufficient evidence for this project.

- [ ] **Step 9: Commit any fixes and log any errors**

If verification found bugs, fix them, add `docs/errors/NNN-*.md` per the convention in `docs/errors/README.md`, and update its index.

---

### Task 14: Cleanup — telnet-sim healthcheck and stray PC evidence

Independent of the feature. Bundled here because both are known open items recorded in CLAUDE.md.

**Files:**
- Modify: `lab/docker-compose.yml:32-36`
- Commit (on the PC): `document-store/raw/EV-2026-07-08-0001.txt`, `EV-2026-07-08-0002.txt`, `EV-2026-07-12-0001.txt`

- [ ] **Step 1: Diagnose the failing healthcheck**

The current check is `["CMD", "nc", "-z", "localhost", "23"]`, failing with exit 1 and empty output. Determine which of these it is:

```powershell
docker compose exec telnet-sim sh -c "command -v nc || echo NO_NC"
docker compose exec telnet-sim sh -c "nc -z localhost 23; echo exit=$?"
```

Most likely `nc` is absent from the image, or it's a BusyBox build whose `nc` has no `-z` flag. Confirm which before changing anything.

- [ ] **Step 2: Fix the healthcheck**

If `nc` is missing or lacks `-z`, replace the check in `lab/docker-compose.yml` with one that uses only what the image has. A Python-based check works if the image has Python:

```yaml
    healthcheck:
      test: ["CMD", "python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 23), timeout=2)"]
      interval: 10s
      timeout: 3s
      retries: 3
```

Choose the variant that matches what Step 1 found; do not guess.

- [ ] **Step 3: Verify it goes healthy**

```powershell
docker compose up -d telnet-sim; Start-Sleep -Seconds 40; docker compose ps telnet-sim
```

Expected: `Up (healthy)`.

- [ ] **Step 4: Commit the fix and log the error**

Add `docs/errors/022-telnet-sim-healthcheck-*.md` per the convention, add its index line to `docs/errors/README.md`, then:

```bash
git add lab/docker-compose.yml docs/errors/
git commit -m "fix(lab): repair telnet-sim healthcheck

The check used a flag the container's nc does not support, so the service
reported unhealthy while running correctly."
```

- [ ] **Step 5: Commit the stray PC evidence files**

On the PC, review the three untracked files first — confirm they are genuine evidence artifacts and contain no unintended content — then commit and push using the PC's deploy-key remote:

```powershell
cd C:\Users\osama\Projects\kaust-iot-security-lab; git add document-store/raw/EV-2026-07-08-0001.txt document-store/raw/EV-2026-07-08-0002.txt document-store/raw/EV-2026-07-12-0001.txt; git commit -m "chore(evidence): commit raw output captured on the build PC"; git push
```

- [ ] **Step 6: Update CLAUDE.md**

Update §0 "Next steps" (both cleanup items now done) and add a §8 changelog row covering the device registration feature, the security-boundary change and its rationale, and the two cleanups. Commit.

---

## Verification Checklist

Before considering this plan complete:

- [ ] `pytest` passes from `lab/auditor/api/`, `lab/auditor/worker/`, and repo root
- [ ] `npm test` and `npx tsc --noEmit` pass from `lab/auditor/web/`
- [ ] `grep -rn "deviceMeta\|consoleDevices" lab/auditor/web/src` returns nothing
- [ ] `grep -rn "allowed_devices\|DEVICE_SCHEME" policies lab` returns nothing
- [ ] `GET /summary` on the PC is byte-identical before and after migration
- [ ] `seed_devices` run twice reports 6 then 0
- [ ] All 11 containers Up, telnet-sim healthy
- [ ] Owner has signed off on screenshots of every new screen
