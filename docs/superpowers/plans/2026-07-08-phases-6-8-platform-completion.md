# Phases 6-8 Platform Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the full 11-container IoTGuard lab architecture by adding `auditor-api` (FastAPI), `auditor-database` (PostgreSQL), `auditor-web` (Flutter Web dashboard), and `traffic-capture` (tcpdump), wiring them into the existing lab, and migrating the Phase 0-5 evidence/verdict corpus into the new database.

**Architecture:** `auditor-worker` keeps running the same test catalog it already runs, but instead of writing evidence/verdict JSON directly to `document-store/`, it `POST`s to `auditor-api`, which validates against the existing JSON schemas and persists to `auditor-database`. `auditor-web` is a thin Flutter Web dashboard that only reads from `auditor-api` (4 screens: Overview, Devices, Evidence, Verdicts). `traffic-capture` runs `tcpdump` on `audit-network`, the one architectural piece never built in Phases 0-5.

**Tech Stack:** FastAPI + `psycopg` (sync) for the API, PostgreSQL 16 for the database, Flutter Web (Dart) for the dashboard, `tcpdump` in a minimal Alpine image for traffic capture. Same repo, same `lab/docker-compose.yml`.

## Global Constraints

- **No authentication on `auditor-api`** — internal-network is already the trust boundary; `auditor-web` is the only client.
- **Controls stay as YAML files** (`policies/controls/*.yaml`) — `auditor-api` reads them live at request time. No `controls` table, no database copy.
- **No `devices` table** — the `/devices` endpoint derives its list via `SELECT DISTINCT device_id FROM evidence`.
- **Raw tool output is unchanged** — `document-store/raw/*.txt` files are still written directly to disk by the worker. Only structured evidence/verdict JSON moves to the API.
- **No `eval`/`exec` anywhere** — this rule from Phases 0-5 still applies to every new file in this plan.
- **Flutter SDK is NOT installed on the build PC.** All Flutter commands (`pub get`, `test`, `build web`) run via Docker using the `ghcr.io/cirruslabs/flutter:stable` image, invoked over ssh-mcp on the PC — never assume a local `flutter` binary exists on the laptop or the PC.
- **PostgreSQL-dependent tests require a running Postgres** — these run via a short-lived `docker run postgres:16-alpine` container, verified on the PC over ssh-mcp, matching how Phase 0-5 verified `yara-python`-dependent tests inside `auditor-worker`'s container rather than on the laptop.
- **Windows/PowerShell quirks from Phases 0-5 still apply:** no `&&` (use `;`), stderr from successful commands gets wrapped as a `NativeCommandError` (check actual results, don't trust the error label alone), ssh-mcp has a ~1000-character command limit (write files in chunks via `Set-Content`/`Add-Content` without `-NoNewline` on any but a deliberate final chunk, then verify with `Get-Content`).
- **Dark security-console design tokens** (exact values, from the approved spec): background `#0F172A`, surface `#1E293B`, primary text `#F1F5F9`, muted text `#94A3B8`, accent `#22D3EE`, status Pass `#4ADE80`, Fail `#F87171`, Partial `#FBBF24`, Inconclusive `#94A3B8`. Monospace font (e.g. `JetBrains Mono`, falling back to `monospace`) for IDs/hashes/timestamps; regular sans-serif (e.g. `Inter`, falling back to Flutter's default) for everything else. No emoji icons anywhere — use `Icons.*` (Material Icons, already bundled with Flutter).
- **Evidence/verdict JSON schemas are unchanged** — `policies/schema/evidence.schema.json` and `policies/schema/verdict.schema.json` from Phase 0 are the validation source of truth for `auditor-api`'s `POST` endpoints; don't redefine them.

---

## Phase 6: Backend (`auditor-api` + `auditor-database`)

### Task 1: `auditor-database` schema + Dockerfile + compose wiring

**Files:**
- Create: `lab/auditor/db/init.sql`
- Create: `lab/auditor/db/Dockerfile`
- Modify: `lab/docker-compose.yml` (add `auditor-database` service)

**Interfaces:**
- Produces: a running PostgreSQL 16 instance reachable at `auditor-database:5432` (database `auditor`, user `auditor`, password `auditor-lab-pw`) on `internal-network`, with `evidence` and `verdicts` tables already created on first boot.

- [ ] **Step 1: Write the schema**

Create `lab/auditor/db/init.sql`:

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

CREATE INDEX idx_evidence_device_id ON evidence(device_id);
CREATE INDEX idx_evidence_test_id ON evidence(test_id);
CREATE INDEX idx_verdicts_control_id ON verdicts(control_id);
CREATE INDEX idx_verdicts_device_id ON verdicts(device_id);
```

- [ ] **Step 2: Write the Dockerfile**

Create `lab/auditor/db/Dockerfile`:

```dockerfile
FROM postgres:16-alpine
COPY init.sql /docker-entrypoint-initdb.d/init.sql
```

(Postgres's official image auto-executes every `.sql` file under `/docker-entrypoint-initdb.d/` on first container start, when the data directory is empty.)

- [ ] **Step 3: Wire into compose**

Add to `lab/docker-compose.yml`, inside the `services:` block (after `auditor-worker`):

```yaml
  auditor-database:
    build: ./auditor/db
    environment:
      - POSTGRES_DB=auditor
      - POSTGRES_USER=auditor
      - POSTGRES_PASSWORD=auditor-lab-pw
    volumes:
      - auditor-db-data:/var/lib/postgresql/data
    networks:
      - internal-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auditor -d auditor"]
      interval: 10s
      timeout: 3s
      retries: 5
```

Add `auditor-db-data:` to the `volumes:` top-level block at the bottom of the file (alongside the existing `mqtt-secure-passwd:`).

- [ ] **Step 4: Build and verify on the PC**

Commit first (Step 5), then over ssh-mcp on the PC:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose build auditor-database --provenance=false
docker compose up -d auditor-database
```

Wait ~10s, then:

```
docker compose exec auditor-database psql -U auditor -d auditor -c "\dt"
```

Expected output lists both `evidence` and `verdicts` tables. Then:

```
docker compose down
```

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/db/init.sql lab/auditor/db/Dockerfile lab/docker-compose.yml
git commit -m "feat(auditor-database): add PostgreSQL schema for evidence and verdicts"
```

---

### Task 2: `auditor-api` skeleton — health check + DB connection

**Files:**
- Create: `lab/auditor/api/Dockerfile`
- Create: `lab/auditor/api/requirements.txt`
- Create: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/db.py`
- Create: `lab/auditor/api/test_health.py`
- Modify: `lab/docker-compose.yml` (add `auditor-api` service)

**Interfaces:**
- Produces: `get_connection() -> psycopg.Connection` in `lab/auditor/api/db.py`, reading `DATABASE_URL` from the environment. `app = FastAPI()` in `lab/auditor/api/main.py` with a `GET /health` route returning `{"status": "ok"}`.

- [ ] **Step 1: Write requirements**

Create `lab/auditor/api/requirements.txt`:

```
fastapi==0.115.6
uvicorn==0.34.0
psycopg[binary]==3.2.10
pyyaml==6.0.2
jsonschema==4.23.0
pytest==8.3.4
httpx==0.28.1
```

- [ ] **Step 2: Write the DB connection module**

Create `lab/auditor/api/db.py`:

```python
import os

import psycopg


def get_connection() -> psycopg.Connection:
    database_url = os.environ["DATABASE_URL"]
    return psycopg.connect(database_url)
```

- [ ] **Step 3: Write the failing test**

Create `lab/auditor/api/test_health.py`:

```python
from fastapi.testclient import TestClient

from main import app


def test_health_returns_ok():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it fails**

This test needs `main.py` to exist first, so write a stub before running — this is one of the rare cases where the stub and the real implementation are the same size, so write the real thing directly:

- [ ] **Step 5: Write the FastAPI app**

Create `lab/auditor/api/main.py`:

```python
from fastapi import FastAPI

app = FastAPI(title="auditor-api")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
```

- [ ] **Step 6: Run test to verify it passes**

Run (from `lab/auditor/api/`, using the repo-root `.venv` after installing this directory's requirements into it — or a fresh venv in this directory; either is fine, name it `.venv` and keep it gitignored):

```
pip install -r requirements.txt
pytest test_health.py -v
```

Expected: `1 passed`.

- [ ] **Step 7: Write the Dockerfile**

Create `lab/auditor/api/Dockerfile`:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 8: Wire into compose**

Add to `lab/docker-compose.yml`, after `auditor-database`:

```yaml
  auditor-api:
    build: ./auditor/api
    environment:
      - DATABASE_URL=postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor
      - PYTHONPATH=/work
    volumes:
      - ../policies:/work/policies:ro
    networks:
      - internal-network
    depends_on:
      auditor-database:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)"]
      interval: 10s
      timeout: 3s
      retries: 3
```

- [ ] **Step 9: Build and verify on the PC**

Commit first (Step 10), then over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose build auditor-database auditor-api --provenance=false
docker compose up -d auditor-database auditor-api
```

Wait ~15s for both healthchecks, then:

```
docker compose exec auditor-api python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/health').read())"
```

Expected: `b'{"status":"ok"}'`. Then:

```
docker compose down
```

- [ ] **Step 10: Commit**

```bash
git add lab/auditor/api/ lab/docker-compose.yml
git commit -m "feat(auditor-api): add FastAPI skeleton with health check"
```

---

### Task 3: `POST /evidence` + `GET /evidence` + `GET /evidence/{evidence_id}`

**Files:**
- Modify: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/test_evidence.py`
- Create: `lab/auditor/api/conftest.py`

**Interfaces:**
- Consumes: `get_connection()` from `db.py` (Task 2).
- Produces: `POST /evidence` (body: the same JSON shape as `policies/schema/evidence.schema.json`, returns `201` with the stored record, or `422` if it fails schema validation), `GET /evidence` (optional `?device_id=`, `?test_id=` query params, returns a JSON array), `GET /evidence/{evidence_id}` (returns the record or `404`).

- [ ] **Step 1: Write the Postgres test fixture**

Create `lab/auditor/api/conftest.py`:

```python
import subprocess
import time

import psycopg
import pytest

TEST_DB_URL = "postgresql://auditor:auditor-lab-pw@localhost:55432/auditor"
CONTAINER_NAME = "auditor-api-test-db"


@pytest.fixture(scope="session")
def postgres_url():
    subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", CONTAINER_NAME,
            "-e", "POSTGRES_DB=auditor",
            "-e", "POSTGRES_USER=auditor",
            "-e", "POSTGRES_PASSWORD=auditor-lab-pw",
            "-p", "55432:5432",
            "postgres:16-alpine",
        ],
        check=True,
    )
    try:
        for _ in range(30):
            try:
                conn = psycopg.connect(TEST_DB_URL)
                conn.close()
                break
            except psycopg.OperationalError:
                time.sleep(1)
        else:
            raise RuntimeError("test postgres did not become ready in time")

        with open("../db/init.sql") as f:
            schema_sql = f.read()
        conn = psycopg.connect(TEST_DB_URL)
        conn.execute(schema_sql)
        conn.commit()
        conn.close()

        yield TEST_DB_URL
    finally:
        subprocess.run(["docker", "stop", CONTAINER_NAME], check=False)


@pytest.fixture(autouse=True)
def clean_tables(postgres_url):
    conn = psycopg.connect(postgres_url)
    conn.execute("TRUNCATE evidence, verdicts")
    conn.commit()
    conn.close()
```

- [ ] **Step 2: Write the failing tests**

Create `lab/auditor/api/test_evidence.py`:

```python
import os

import pytest
from fastapi.testclient import TestClient

VALID_EVIDENCE = {
    "evidence_id": "EV-2026-07-08-9001",
    "device_id": "device-insecure",
    "test_id": "TEST-NET-PORTSCAN",
    "tool": "nmap",
    "tool_version": "7.95",
    "command": "nmap -sV -p- device-insecure",
    "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Port 80 open",
    "observations": {"open_ports": [80]},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9001.txt",
    "confidence": "high",
    "sha256": "a" * 64,
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_post_evidence_returns_201(client):
    response = client.post("/evidence", json=VALID_EVIDENCE)
    assert response.status_code == 201
    assert response.json()["evidence_id"] == "EV-2026-07-08-9001"


def test_post_evidence_rejects_invalid_payload(client):
    bad = dict(VALID_EVIDENCE)
    del bad["finding"]
    response = client.post("/evidence", json=bad)
    assert response.status_code == 422


def test_get_evidence_list_returns_posted_record(client):
    client.post("/evidence", json=VALID_EVIDENCE)
    response = client.get("/evidence")
    assert response.status_code == 200
    ids = [e["evidence_id"] for e in response.json()]
    assert "EV-2026-07-08-9001" in ids


def test_get_evidence_filters_by_device_id(client):
    client.post("/evidence", json=VALID_EVIDENCE)
    other = dict(VALID_EVIDENCE, evidence_id="EV-2026-07-08-9002", device_id="device-hardened")
    client.post("/evidence", json=other)

    response = client.get("/evidence", params={"device_id": "device-hardened"})
    ids = [e["evidence_id"] for e in response.json()]
    assert ids == ["EV-2026-07-08-9002"]


def test_get_evidence_by_id_returns_record(client):
    client.post("/evidence", json=VALID_EVIDENCE)
    response = client.get("/evidence/EV-2026-07-08-9001")
    assert response.status_code == 200
    assert response.json()["finding"] == "Port 80 open"


def test_get_evidence_by_id_404_when_missing(client):
    response = client.get("/evidence/EV-DOES-NOT-EXIST")
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_evidence.py -v`
Expected: FAIL (no `/evidence` routes exist yet — `main.py` only has `/health`). This step requires Docker on the machine running the test; if running locally without Docker, skip straight to implementation and verify on the PC in Step 4 instead.

- [ ] **Step 3: Implement the evidence endpoints**

Replace `lab/auditor/api/main.py` with:

```python
import json
from pathlib import Path

import jsonschema
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from db import get_connection

app = FastAPI(title="auditor-api")

SCHEMA_PATH = Path("/work/policies/schema/evidence.schema.json")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _load_evidence_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


@app.post("/evidence", status_code=201)
def post_evidence(evidence: dict):
    schema = _load_evidence_schema()
    try:
        jsonschema.validate(evidence, schema)
    except jsonschema.ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc.message))

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO evidence (
                evidence_id, device_id, test_id, tool, tool_version, command,
                timestamp, finding, observations, raw_output_path, confidence, sha256
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                evidence["evidence_id"], evidence["device_id"], evidence["test_id"],
                evidence["tool"], evidence["tool_version"], evidence["command"],
                evidence["timestamp"], evidence["finding"],
                json.dumps(evidence["observations"]), evidence["raw_output_path"],
                evidence["confidence"], evidence["sha256"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return evidence


def _row_to_evidence(row: tuple) -> dict:
    (evidence_id, device_id, test_id, tool, tool_version, command,
     timestamp, finding, observations, raw_output_path, confidence, sha256) = row
    return {
        "evidence_id": evidence_id, "device_id": device_id, "test_id": test_id,
        "tool": tool, "tool_version": tool_version, "command": command,
        "timestamp": timestamp.isoformat(), "finding": finding,
        "observations": observations, "raw_output_path": raw_output_path,
        "confidence": confidence, "sha256": sha256,
    }


@app.get("/evidence")
def get_evidence(device_id: str | None = None, test_id: str | None = None):
    conn = get_connection()
    try:
        query = "SELECT evidence_id, device_id, test_id, tool, tool_version, command, timestamp, finding, observations, raw_output_path, confidence, sha256 FROM evidence WHERE 1=1"
        params: list = []
        if device_id is not None:
            query += " AND device_id = %s"
            params.append(device_id)
        if test_id is not None:
            query += " AND test_id = %s"
            params.append(test_id)
        query += " ORDER BY evidence_id"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_evidence(row) for row in rows]


@app.get("/evidence/{evidence_id}")
def get_evidence_by_id(evidence_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT evidence_id, device_id, test_id, tool, tool_version, command, timestamp, finding, observations, raw_output_path, confidence, sha256 FROM evidence WHERE evidence_id = %s",
            (evidence_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return _row_to_evidence(row)
```

- [ ] **Step 4: Run tests and verify on the PC**

Commit first (Step 5), then over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab\auditor\api
docker build -t auditor-api-test . --provenance=false
docker run --rm --network host -v ${PWD}/../../../policies:/work/policies:ro -e DATABASE_URL=postgresql://auditor:auditor-lab-pw@localhost:55432/auditor -w /app auditor-api-test sh -c "pip install pytest httpx -q && pytest test_evidence.py test_health.py -v"
```

(This runs the API's own test suite inside its built image, which already has all dependencies installed, against the throwaway Postgres fixture the tests themselves spin up via `docker run` — note this requires Docker socket access from inside the test container. If `docker run` isn't reachable from inside this container in practice, run the tests directly on the PC's host Python instead: install `lab/auditor/api/requirements.txt` into a venv on the PC, `cd` to `lab/auditor/api`, and run `pytest test_evidence.py test_health.py -v` there — the fixture's own `docker run postgres:16-alpine` calls only need the PC's Docker daemon, not a container-in-container setup.)

Expected: `7 passed` (6 from `test_evidence.py` + 1 from `test_health.py`).

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/api/
git commit -m "feat(auditor-api): add POST/GET evidence endpoints with schema validation"
```

---

### Task 4: `POST /verdicts` + `GET /verdicts` + `GET /verdicts/{verdict_id}`

**Files:**
- Modify: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/test_verdicts.py`

**Interfaces:**
- Consumes: `get_connection()` (Task 2), `postgres_url`/`clean_tables` fixtures (Task 3's `conftest.py`).
- Produces: `POST /verdicts`, `GET /verdicts` (optional `?control_id=`, `?device_id=`), `GET /verdicts/{verdict_id}`. Same validate-then-insert pattern as Task 3, against `policies/schema/verdict.schema.json`.

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_verdicts.py`:

```python
import pytest
from fastapi.testclient import TestClient

VALID_VERDICT = {
    "verdict_id": "VD-2026-07-08-9001",
    "control_id": "SA-IOT-002",
    "device_id": "device-insecure",
    "status": "FAIL",
    "severity": "high",
    "evidence_ids": ["EV-2026-07-08-9001"],
    "matched": "fail",
    "reason": "observations.default_creds equals True",
    "saudi_source": "CGIoT-1:2024 §2-2-2",
    "remediation": "Force password change on first boot",
    "timestamp": "2026-07-08T08:06:42Z",
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_post_verdict_returns_201(client):
    response = client.post("/verdicts", json=VALID_VERDICT)
    assert response.status_code == 201
    assert response.json()["verdict_id"] == "VD-2026-07-08-9001"


def test_post_verdict_rejects_invalid_payload(client):
    bad = dict(VALID_VERDICT)
    del bad["status"]
    response = client.post("/verdicts", json=bad)
    assert response.status_code == 422


def test_get_verdicts_filters_by_control_id(client):
    client.post("/verdicts", json=VALID_VERDICT)
    other = dict(VALID_VERDICT, verdict_id="VD-2026-07-08-9002", control_id="SA-IOT-003")
    client.post("/verdicts", json=other)

    response = client.get("/verdicts", params={"control_id": "SA-IOT-003"})
    ids = [v["verdict_id"] for v in response.json()]
    assert ids == ["VD-2026-07-08-9002"]


def test_get_verdict_by_id_returns_record(client):
    client.post("/verdicts", json=VALID_VERDICT)
    response = client.get("/verdicts/VD-2026-07-08-9001")
    assert response.status_code == 200
    assert response.json()["status"] == "FAIL"


def test_get_verdict_by_id_404_when_missing(client):
    response = client.get("/verdicts/VD-DOES-NOT-EXIST")
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_verdicts.py -v` (same execution context as Task 3 Step 4)
Expected: FAIL (`/verdicts` routes don't exist yet).

- [ ] **Step 3: Implement the verdict endpoints**

Add to `lab/auditor/api/main.py` (after the evidence routes):

```python
VERDICT_SCHEMA_PATH = Path("/work/policies/schema/verdict.schema.json")


def _load_verdict_schema() -> dict:
    return json.loads(VERDICT_SCHEMA_PATH.read_text())


@app.post("/verdicts", status_code=201)
def post_verdict(verdict: dict):
    schema = _load_verdict_schema()
    try:
        jsonschema.validate(verdict, schema)
    except jsonschema.ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc.message))

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO verdicts (
                verdict_id, control_id, device_id, status, severity,
                evidence_ids, matched, reason, saudi_source, remediation, timestamp
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                verdict["verdict_id"], verdict["control_id"], verdict["device_id"],
                verdict["status"], verdict["severity"],
                json.dumps(verdict["evidence_ids"]), json.dumps(verdict.get("matched")),
                verdict["reason"], json.dumps(verdict["saudi_source"]),
                verdict["remediation"], verdict["timestamp"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return verdict


def _row_to_verdict(row: tuple) -> dict:
    (verdict_id, control_id, device_id, status, severity,
     evidence_ids, matched, reason, saudi_source, remediation, timestamp) = row
    return {
        "verdict_id": verdict_id, "control_id": control_id, "device_id": device_id,
        "status": status, "severity": severity, "evidence_ids": evidence_ids,
        "matched": matched, "reason": reason, "saudi_source": saudi_source,
        "remediation": remediation, "timestamp": timestamp.isoformat(),
    }


@app.get("/verdicts")
def get_verdicts(control_id: str | None = None, device_id: str | None = None):
    conn = get_connection()
    try:
        query = "SELECT verdict_id, control_id, device_id, status, severity, evidence_ids, matched, reason, saudi_source, remediation, timestamp FROM verdicts WHERE 1=1"
        params: list = []
        if control_id is not None:
            query += " AND control_id = %s"
            params.append(control_id)
        if device_id is not None:
            query += " AND device_id = %s"
            params.append(device_id)
        query += " ORDER BY verdict_id"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_verdict(row) for row in rows]


@app.get("/verdicts/{verdict_id}")
def get_verdict_by_id(verdict_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT verdict_id, control_id, device_id, status, severity, evidence_ids, matched, reason, saudi_source, remediation, timestamp FROM verdicts WHERE verdict_id = %s",
            (verdict_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="verdict not found")
    return _row_to_verdict(row)
```

- [ ] **Step 4: Run tests and verify on the PC**

Same execution pattern as Task 3 Step 4, substituting `test_verdicts.py`.
Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/api/
git commit -m "feat(auditor-api): add POST/GET verdict endpoints with schema validation"
```

---

### Task 5: `GET /controls` + `GET /controls/{control_id}`

**Files:**
- Modify: `lab/auditor/api/main.py`
- Modify: `lab/docker-compose.yml` (mount `policies/` read-only, already added in Task 2 Step 8 — confirm it's present)
- Create: `lab/auditor/api/test_controls.py`

**Interfaces:**
- Produces: `GET /controls` (reads every `*.yaml` under `/work/policies/controls/`, returns a JSON array), `GET /controls/{control_id}` (returns one control or `404`).

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_controls.py`:

```python
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_get_controls_returns_all_five():
    response = client.get("/controls")
    assert response.status_code == 200
    control_ids = {c["control_id"] for c in response.json()}
    assert control_ids == {
        "SA-IOT-001", "SA-IOT-002", "SA-IOT-003", "SA-IOT-004", "SA-IOT-005",
    }


def test_get_control_by_id_returns_real_control():
    response = client.get("/controls/SA-IOT-002")
    assert response.status_code == 200
    assert response.json()["title"] == "No default or hard-coded credentials"


def test_get_control_by_id_404_when_missing():
    response = client.get("/controls/SA-IOT-999")
    assert response.status_code == 404
```

This test suite needs no Postgres — it only reads YAML files — so it can run without the `postgres_url` fixture. It does need `/work/policies/controls/*.yaml` to be reachable at that exact path; when running locally (not via the PC's Docker container), set the `CONTROLS_DIR` environment variable instead (see Step 2 for how the code reads it).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_controls.py -v`
Expected: FAIL (`/controls` route doesn't exist).

- [ ] **Step 3: Implement the controls endpoints**

Add to `lab/auditor/api/main.py` (after the verdict routes):

```python
import os

import yaml

CONTROLS_DIR = Path(os.environ.get("CONTROLS_DIR", "/work/policies/controls"))


def _load_all_controls() -> list[dict]:
    controls = []
    for path in sorted(CONTROLS_DIR.glob("*.yaml")):
        controls.append(yaml.safe_load(path.read_text()))
    return controls


@app.get("/controls")
def get_controls():
    return _load_all_controls()


@app.get("/controls/{control_id}")
def get_control_by_id(control_id: str):
    path = CONTROLS_DIR / f"{control_id}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail="control not found")
    return yaml.safe_load(path.read_text())
```

- [ ] **Step 4: Run tests to verify they pass**

From `lab/auditor/api/`, with the repo's real `policies/controls/` reachable:

```
CONTROLS_DIR=../../../policies/controls pytest test_controls.py -v
```

(On Windows PowerShell: `$env:CONTROLS_DIR = "../../../policies/controls"; pytest test_controls.py -v`)

Expected: `3 passed`.

- [ ] **Step 5: Verify on the PC with the real container mount**

Over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose build auditor-api --provenance=false
docker compose up -d auditor-database auditor-api
```

Wait ~15s, then:

```
docker compose exec auditor-api python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/controls').read()[:200])"
```

Expected: JSON starting with `[{"control_id":"SA-IOT-001"`. Then:

```
docker compose down
```

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/api/
git commit -m "feat(auditor-api): add GET controls endpoints reading live YAML"
```

---

### Task 6: `GET /devices` + `GET /summary`

**Files:**
- Modify: `lab/auditor/api/main.py`
- Create: `lab/auditor/api/test_devices_summary.py`

**Interfaces:**
- Consumes: `postgres_url`/`clean_tables` fixtures (Task 3's `conftest.py`).
- Produces: `GET /devices` (returns `[{"device_id": str, "evidence_count": int, "verdict_count": int}, ...]`), `GET /summary` (returns `{"total_evidence": int, "total_verdicts": int, "verdicts_by_status": {"PASS": int, "FAIL": int, "PARTIAL": int, "INCONCLUSIVE": int}}`).

- [ ] **Step 1: Write the failing tests**

Create `lab/auditor/api/test_devices_summary.py`:

```python
import pytest
from fastapi.testclient import TestClient

EVIDENCE_A = {
    "evidence_id": "EV-2026-07-08-9001", "device_id": "device-insecure",
    "test_id": "TEST-NET-PORTSCAN", "tool": "nmap", "tool_version": "7.95",
    "command": "nmap -sV -p- device-insecure", "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Port 80 open", "observations": {"open_ports": [80]},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9001.txt",
    "confidence": "high", "sha256": "a" * 64,
}
EVIDENCE_B = dict(EVIDENCE_A, evidence_id="EV-2026-07-08-9002", device_id="device-hardened")

VERDICT_FAIL = {
    "verdict_id": "VD-2026-07-08-9001", "control_id": "SA-IOT-002",
    "device_id": "device-insecure", "status": "FAIL", "severity": "high",
    "evidence_ids": ["EV-2026-07-08-9001"], "matched": "fail",
    "reason": "observations.default_creds equals True",
    "saudi_source": "CGIoT-1:2024 §2-2-2",
    "remediation": "Force password change", "timestamp": "2026-07-08T08:06:42Z",
}
VERDICT_PASS = dict(
    VERDICT_FAIL, verdict_id="VD-2026-07-08-9002", device_id="device-hardened",
    status="PASS", matched="pass",
)


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_get_devices_returns_counts(client):
    client.post("/evidence", json=EVIDENCE_A)
    client.post("/evidence", json=EVIDENCE_B)
    client.post("/verdicts", json=VERDICT_FAIL)

    response = client.get("/devices")
    by_id = {d["device_id"]: d for d in response.json()}
    assert by_id["device-insecure"]["evidence_count"] == 1
    assert by_id["device-insecure"]["verdict_count"] == 1
    assert by_id["device-hardened"]["evidence_count"] == 1
    assert by_id["device-hardened"]["verdict_count"] == 0


def test_get_summary_returns_aggregate_counts(client):
    client.post("/evidence", json=EVIDENCE_A)
    client.post("/evidence", json=EVIDENCE_B)
    client.post("/verdicts", json=VERDICT_FAIL)
    client.post("/verdicts", json=VERDICT_PASS)

    response = client.get("/summary")
    body = response.json()
    assert body["total_evidence"] == 2
    assert body["total_verdicts"] == 2
    assert body["verdicts_by_status"]["FAIL"] == 1
    assert body["verdicts_by_status"]["PASS"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_devices_summary.py -v` (same execution context as Task 3 Step 4)
Expected: FAIL (`/devices` and `/summary` routes don't exist).

- [ ] **Step 3: Implement the endpoints**

Add to `lab/auditor/api/main.py` (after the controls routes):

```python
@app.get("/devices")
def get_devices():
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT
                d.device_id,
                COALESCE(e.evidence_count, 0) AS evidence_count,
                COALESCE(v.verdict_count, 0) AS verdict_count
            FROM (
                SELECT device_id FROM evidence
                UNION
                SELECT device_id FROM verdicts
            ) d
            LEFT JOIN (
                SELECT device_id, COUNT(*) AS evidence_count FROM evidence GROUP BY device_id
            ) e ON e.device_id = d.device_id
            LEFT JOIN (
                SELECT device_id, COUNT(*) AS verdict_count FROM verdicts GROUP BY device_id
            ) v ON v.device_id = d.device_id
            ORDER BY d.device_id
            """
        ).fetchall()
    finally:
        conn.close()
    return [
        {"device_id": device_id, "evidence_count": evidence_count, "verdict_count": verdict_count}
        for device_id, evidence_count, verdict_count in rows
    ]


@app.get("/summary")
def get_summary():
    conn = get_connection()
    try:
        total_evidence = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        total_verdicts = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        status_rows = conn.execute(
            "SELECT status, COUNT(*) FROM verdicts GROUP BY status"
        ).fetchall()
    finally:
        conn.close()
    verdicts_by_status = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0}
    for status, count in status_rows:
        verdicts_by_status[status] = count
    return {
        "total_evidence": total_evidence,
        "total_verdicts": total_verdicts,
        "verdicts_by_status": verdicts_by_status,
    }
```

- [ ] **Step 4: Run tests and verify on the PC**

Same execution pattern as Task 3 Step 4, substituting `test_devices_summary.py`.
Expected: `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/api/
git commit -m "feat(auditor-api): add GET devices and summary aggregate endpoints"
```

---

### Task 7: Worker adapter — `record_evidence.py` posts to the API instead of writing files

**Files:**
- Modify: `lab/auditor/worker/tests/record_evidence.py`
- Modify: `lab/auditor/worker/tests/test_record_evidence.py`
- Modify: `lab/auditor/worker/requirements.txt` (add `requests`)
- Modify: `lab/docker-compose.yml` (`auditor-worker` gets `AUDITOR_API_URL` env var and a `depends_on` on `auditor-api`)

**Interfaces:**
- Consumes: `auditor-api`'s `POST /evidence` (Task 3).
- Produces: `record_evidence.py`'s CLI interface is unchanged (same `--device`, `--test-id`, etc. flags from Phase 4) — only its persistence mechanism changes from `json.dump()` to an HTTP `POST`. Raw output copying to `document-store/raw/` is unchanged.

- [ ] **Step 1: Read the current implementation**

Before changing anything, read `lab/auditor/worker/tests/record_evidence.py` in full — this plan assumes its current structure (a `main()` that builds the evidence dict, computes `sha256`, copies the raw file, then previously called something like `_write_evidence_json(evidence)`). Locate that write call; it's the only thing this task replaces.

- [ ] **Step 2: Write the failing test**

Add to `lab/auditor/worker/tests/test_record_evidence.py` (keep all existing tests in this file; add this one):

```python
def test_record_evidence_posts_to_api(monkeypatch, tmp_path):
    import record_evidence

    posted = {}

    class FakeResponse:
        status_code = 201

        def raise_for_status(self):
            pass

    def fake_post(url, json, timeout):
        posted["url"] = url
        posted["json"] = json
        return FakeResponse()

    monkeypatch.setattr(record_evidence.requests, "post", fake_post)
    monkeypatch.setenv("AUDITOR_API_URL", "http://auditor-api:8000")

    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("nmap output here")

    record_evidence.record_evidence(
        device="device-insecure",
        test_id="TEST-NET-PORTSCAN",
        tool="nmap",
        tool_version="7.95",
        command="nmap -sV -p- device-insecure",
        finding="Port 80 open",
        raw_file=str(raw_file),
        confidence="high",
        observations={"open_ports": [80]},
    )

    assert posted["url"] == "http://auditor-api:8000/evidence"
    assert posted["json"]["device_id"] == "device-insecure"
    assert posted["json"]["finding"] == "Port 80 open"
```

(This test names a `record_evidence(...)` function taking keyword arguments matching the CLI flags — if the existing code structures this differently, e.g. as inline `main()` logic, extract a `record_evidence(...)` function with this signature as part of this task, since Step 3 needs something testable without going through `argparse`.)

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest lab/auditor/worker/tests/test_record_evidence.py::test_record_evidence_posts_to_api -v`
Expected: FAIL (`record_evidence.requests` doesn't exist yet, or the function doesn't accept these arguments).

- [ ] **Step 4: Replace the file-write with an API POST**

In `lab/auditor/worker/tests/record_evidence.py`:
1. Add `import requests` near the top.
2. Add `import os` if not already present.
3. Find the function that currently builds the evidence dict and writes it to `document-store/evidence/{evidence_id}.json` (this may be inline in `main()` — extract it into a `record_evidence(device, test_id, tool, tool_version, command, finding, raw_file, confidence, observations)` function if it isn't already one, keeping all existing behavior: sequence-number generation, `sha256` computation, and raw-file copying to `document-store/raw/`).
4. Replace the JSON file write with:

```python
    api_url = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")
    response = requests.post(f"{api_url}/evidence", json=evidence, timeout=10)
    response.raise_for_status()
```

   (where `evidence` is the dict that used to be `json.dump()`-ed — keep every other field exactly as before: `evidence_id`, `device_id`, `test_id`, `tool`, `tool_version`, `command`, `timestamp`, `finding`, `observations`, `raw_output_path`, `confidence`, `sha256`.)
5. Keep `main()` (the `argparse` CLI entry point) calling this function with the parsed arguments, so the CLI invocation used throughout `lab/auditor/worker/tests/run_catalog.md` (`python lab/auditor/worker/tests/record_evidence.py --device ... --test-id ...`) is unchanged.

- [ ] **Step 5: Add `requests` to the worker's dependencies**

Add to `lab/auditor/worker/requirements.txt`:

```
requests==2.32.3
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest lab/auditor/worker/tests/test_record_evidence.py -v`
Expected: all tests pass, including the new `test_record_evidence_posts_to_api` and every pre-existing test in this file (the existing tests write to a temp `document-store` and check the JSON file directly — since Step 4 removed the file write, update any pre-existing test that asserted "a JSON file was written" to instead assert "a `POST` was made with this JSON body," using the same `fake_post` monkeypatch pattern as Step 2's new test. Read each existing test in this file before editing it — don't delete assertions, redirect them from filesystem checks to HTTP-call checks.)

- [ ] **Step 7: Wire the worker's API URL into compose**

In `lab/docker-compose.yml`, modify the `auditor-worker` service (add these two entries; keep everything else in the service definition as-is):

```yaml
  auditor-worker:
    # ... existing config unchanged ...
    environment:
      - PYTHONPATH=/work
      - AUDITOR_API_URL=http://auditor-api:8000
    depends_on:
      - auditor-api
```

- [ ] **Step 8: Verify end-to-end on the PC**

Over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose build auditor-worker auditor-api auditor-database device-insecure --provenance=false
docker compose up -d auditor-database auditor-api device-insecure auditor-worker
```

Wait ~15s, then run one real evidence-recording call inside the worker container:

```
docker compose exec auditor-worker sh -c "cd /work && python lab/auditor/worker/tests/record_evidence.py --device device-insecure --test-id TEST-NET-PORTSCAN --tool nmap --tool-version 7.95 --command 'echo test' --finding 'end-to-end wiring check' --raw-file /etc/hostname --confidence high --observations '{\"check\": true}'"
```

Then confirm it landed in the database via the API:

```
docker compose exec auditor-api python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/evidence').read())"
```

Expected: the JSON array includes an entry with `"finding":"end-to-end wiring check"`. Then:

```
docker compose down
```

- [ ] **Step 9: Commit**

```bash
git add lab/auditor/worker/ lab/docker-compose.yml
git commit -m "feat(auditor-worker): record_evidence.py posts to auditor-api instead of writing files directly"
```

---

### Task 8: Worker adapter — verdict generation posts to the API and reads evidence from it

**Files:**
- Modify: `policies/engine/generate_verdicts.py`
- Modify: `policies/engine/test_generate_verdicts.py`
- Modify: `lab/docker-compose.yml` (mount `policies/engine/generate_verdicts.py` is already in `auditor-worker`'s `policies` mount from Task 2's compose block — confirm; add `requests` to whichever requirements file the module doing this now needs it, most likely `lab/auditor/worker/requirements.txt` since `generate_verdicts.py` runs inside `auditor-worker`)

**Interfaces:**
- Consumes: `GET /evidence` and `POST /verdicts` (Tasks 3-4).
- Produces: `generate_verdicts(api_url: str) -> list[dict]` — replaces the Task 30 signature `generate_verdicts(evidence_dir, controls_dir, output_dir)`. Controls are still read from local YAML (`policies/controls/`, unchanged — this doesn't move to the API from the worker's perspective, only from `auditor-web`'s).

- [ ] **Step 1: Write the failing test**

Modify `policies/engine/test_generate_verdicts.py`: keep the existing test file's structure, but change the fixture data source and assertions to work against a fake API instead of a temp directory. Replace its contents with:

```python
import responses

from policies.engine.generate_verdicts import generate_verdicts

EVIDENCE_FAIL = {
    "evidence_id": "EV-2026-07-08-9001", "device_id": "device-insecure",
    "test_id": "TEST-AUTH-DEFAULT-CREDS", "tool": "curl", "tool_version": "8.9.1",
    "command": "curl POST login", "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Default creds accepted", "observations": {"default_creds": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9001.txt",
    "confidence": "high", "sha256": "a" * 64,
}
EVIDENCE_PASS = dict(
    EVIDENCE_FAIL, evidence_id="EV-2026-07-08-9002", device_id="device-hardened",
    observations={"default_creds": False},
)


@responses.activate
def test_generate_verdicts_produces_fail_and_pass_across_devices(tmp_path):
    api_url = "http://auditor-api:8000"
    responses.add(responses.GET, f"{api_url}/evidence", json=[EVIDENCE_FAIL, EVIDENCE_PASS])
    responses.add(responses.POST, f"{api_url}/verdicts", json={}, status=201)

    control_dir = tmp_path / "controls"
    control_dir.mkdir()
    (control_dir / "SA-IOT-002.yaml").write_text(
        """
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
severity: high
conditions:
  fail:
    field: observations.default_creds
    op: equals
    value: true
  pass:
    field: observations.default_creds
    op: equals
    value: false
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: Force password change on first boot
"""
    )

    verdicts = generate_verdicts(api_url=api_url, controls_dir=str(control_dir))

    statuses = {(v["device_id"]): v["status"] for v in verdicts}
    assert statuses["device-insecure"] == "FAIL"
    assert statuses["device-hardened"] == "PASS"

    post_calls = [c for c in responses.calls if c.request.method == "POST"]
    assert len(post_calls) == 2
```

**Important context on `evaluate()`'s real contract** (from `policies/engine/policy_engine.py`, written in Phase 0-5's Task 28 — read the actual file before writing this task's code, don't rely solely on this summary): `evaluate(control: dict, evidence: dict, verdict_id: Optional[str] = None) -> dict` returns the **complete** verdict dict already assembled — `control_id`, `device_id`, `status` (uppercase, via an internal `STATUS_MAP`), `severity`, `evidence_ids` (a one-element list built from `evidence["evidence_id"]`), `matched` (the lowercase status string, e.g. `"fail"`), `reason`, `saudi_source` (formatted as a string, `f"{control['saudi_source'][0]['framework']} §{control['saudi_source'][0]['reference']}"` — note `control["saudi_source"]` is a **list**, `evaluate()` uses only its first entry), `remediation`, and `timestamp`. If `verdict_id` is passed, it's prepended to the returned dict. **`generate_verdicts()` does not need to reassemble any of these fields itself — it only needs to compute the `verdict_id` and pass it to `evaluate()`.** Also note `control["required_evidence"]` is a list of `{"test_id": ...}` dicts, not plain strings (matches the real committed control YAML files, e.g. `policies/controls/SA-IOT-002.yaml`).

- [ ] **Step 2: Add the `responses` test dependency**

Add to `requirements-dev.txt` (repo root):

```
responses==0.25.3
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest policies/engine/test_generate_verdicts.py -v`
Expected: FAIL (`generate_verdicts` doesn't accept `api_url`/`controls_dir` keyword arguments yet).

- [ ] **Step 4: Rewrite `generate_verdicts.py` to use the API**

Read the current `policies/engine/generate_verdicts.py` in full first (from Task 30) — it currently has a `generate_verdicts(evidence_dir, controls_dir, output_dir)` function that reads evidence/controls from local files, calls `evaluate(control, evidence, verdict_id=verdict_id)` (which returns the **complete** verdict dict, see the note above Step 1's test), validates with `validate_verdict()`, and writes each result to a local JSON file — plus a `main()`. Replace the whole file with:

```python
import sys
from pathlib import Path

import requests
import yaml

from policies.engine.policy_engine import evaluate


def generate_verdicts(api_url: str, controls_dir: str) -> list[dict]:
    evidence_response = requests.get(f"{api_url}/evidence", timeout=10)
    evidence_response.raise_for_status()
    evidence_records = sorted(evidence_response.json(), key=lambda e: e["evidence_id"])

    controls = []
    for path in sorted(Path(controls_dir).glob("*.yaml")):
        controls.append(yaml.safe_load(path.read_text()))

    verdicts = []
    seq_by_date: dict[str, int] = {}
    for evidence in evidence_records:
        for control in controls:
            required_test_ids = {req["test_id"] for req in control["required_evidence"]}
            if evidence["test_id"] not in required_test_ids:
                continue
            date_str = evidence["timestamp"][:10]
            seq_by_date[date_str] = seq_by_date.get(date_str, 0) + 1
            verdict_id = f"VD-{date_str}-{seq_by_date[date_str]:04d}"
            verdict = evaluate(control, evidence, verdict_id=verdict_id)
            post_response = requests.post(f"{api_url}/verdicts", json=verdict, timeout=10)
            post_response.raise_for_status()
            verdicts.append(verdict)
    return verdicts


def main():
    api_url = "http://auditor-api:8000"
    controls_dir = "/work/policies/controls"
    verdicts = generate_verdicts(api_url=api_url, controls_dir=controls_dir)
    print(f"Generated {len(verdicts)} verdicts")
    for v in verdicts:
        print(f"  {v['control_id']} / {v['device_id']} -> {v['status']}")


if __name__ == "__main__":
    sys.exit(main() or 0)
```

`evaluate()` already returns every field the API's `POST /verdicts` schema requires (`matched` as the lowercase status string, `saudi_source` as a formatted string, `status` as the uppercase enum via `STATUS_MAP`) — `generate_verdicts()` only computes the `verdict_id` and passes it through, it does not reassemble any other field. This matches the real, already-approved `policies/engine/policy_engine.py` from Phase 0-5 exactly — read that file before writing this task's code to confirm, don't guess from this summary alone.

- [ ] **Step 5: Add `responses` and `requests` where needed, run tests to verify they pass**

Run: `pip install -r requirements-dev.txt` (repo root), then `pytest policies/engine/test_generate_verdicts.py -v`
Expected: `1 passed`.

- [ ] **Step 6: Verify on the PC against the real API**

Over ssh-mcp, after Tasks 3-7 are deployed:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose up -d auditor-database auditor-api
```

Wait ~15s, then run the real generator against the (empty, at this point) API:

```
docker compose exec auditor-worker sh -c "cd /work && python -m policies.engine.generate_verdicts"
```

Expected: `Generated 0 verdicts` (empty database is fine here — Task 9 migrates the real historical evidence). Then:

```
docker compose down
```

- [ ] **Step 7: Commit**

```bash
git add policies/engine/ requirements-dev.txt
git commit -m "feat(policy-engine): generate_verdicts.py reads evidence from and writes verdicts to auditor-api"
```

---

### Task 9: Migrate the existing 12 evidence + 8 verdict JSON files into the database

**Files:**
- Create: `policies/engine/migrate_existing_records.py`
- Create: `policies/engine/test_migrate_existing_records.py`

**Interfaces:**
- Consumes: `POST /evidence`, `POST /verdicts` (Tasks 3-4).
- Produces: `migrate_existing_records(evidence_dir: str, verdicts_dir: str, api_url: str) -> tuple[int, int]` — returns `(evidence_count, verdict_count)` migrated.

- [ ] **Step 1: Write the failing test**

Create `policies/engine/test_migrate_existing_records.py`:

```python
import json

import responses

from policies.engine.migrate_existing_records import migrate_existing_records


@responses.activate
def test_migrate_existing_records_posts_every_file(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    verdicts_dir = tmp_path / "verdicts"
    verdicts_dir.mkdir()

    evidence = {"evidence_id": "EV-2026-07-08-0013", "device_id": "device-insecure"}
    (evidence_dir / "EV-2026-07-08-0013.json").write_text(json.dumps(evidence))

    verdict = {"verdict_id": "VD-2026-07-08-0001", "control_id": "SA-IOT-003"}
    (verdicts_dir / "VD-2026-07-08-0001.json").write_text(json.dumps(verdict))

    api_url = "http://auditor-api:8000"
    responses.add(responses.POST, f"{api_url}/evidence", json=evidence, status=201)
    responses.add(responses.POST, f"{api_url}/verdicts", json=verdict, status=201)

    evidence_count, verdict_count = migrate_existing_records(
        evidence_dir=str(evidence_dir), verdicts_dir=str(verdicts_dir), api_url=api_url,
    )

    assert evidence_count == 1
    assert verdict_count == 1
    post_bodies = [json.loads(c.request.body) for c in responses.calls]
    assert evidence in post_bodies
    assert verdict in post_bodies
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest policies/engine/test_migrate_existing_records.py -v`
Expected: FAIL (`policies.engine.migrate_existing_records` doesn't exist).

- [ ] **Step 3: Implement the migration script**

Create `policies/engine/migrate_existing_records.py`:

```python
import json
import sys
from pathlib import Path

import requests


def migrate_existing_records(evidence_dir: str, verdicts_dir: str, api_url: str) -> tuple[int, int]:
    evidence_count = 0
    for path in sorted(Path(evidence_dir).glob("*.json")):
        record = json.loads(path.read_text())
        response = requests.post(f"{api_url}/evidence", json=record, timeout=10)
        response.raise_for_status()
        evidence_count += 1

    verdict_count = 0
    for path in sorted(Path(verdicts_dir).glob("*.json")):
        record = json.loads(path.read_text())
        response = requests.post(f"{api_url}/verdicts", json=record, timeout=10)
        response.raise_for_status()
        verdict_count += 1

    return evidence_count, verdict_count


def main():
    evidence_count, verdict_count = migrate_existing_records(
        evidence_dir="/work/document-store/evidence",
        verdicts_dir="/work/document-store/verdicts",
        api_url="http://auditor-api:8000",
    )
    print(f"Migrated {evidence_count} evidence records and {verdict_count} verdicts")


if __name__ == "__main__":
    sys.exit(main() or 0)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest policies/engine/test_migrate_existing_records.py -v`
Expected: `1 passed`.

- [ ] **Step 5: Run the real migration on the PC**

Over ssh-mcp, with `auditor-database` and `auditor-api` up (from Task 8 Step 6):

```
cd C:\Users\osama\Projects\kaust-iot-security-lab\lab
docker compose up -d auditor-database auditor-api
```

Wait ~15s, then:

```
docker compose exec auditor-worker sh -c "cd /work && python -m policies.engine.migrate_existing_records"
```

Expected: `Migrated 12 evidence records and 8 verdicts`. Then confirm via the API:

```
docker compose exec auditor-api python -c "import urllib.request, json; print(json.loads(urllib.request.urlopen('http://localhost:8000/summary').read()))"
```

Expected: `{'total_evidence': 12, 'total_verdicts': 8, ...}`. Then:

```
docker compose down
```

- [ ] **Step 6: Commit**

```bash
git add policies/engine/migrate_existing_records.py policies/engine/test_migrate_existing_records.py
git commit -m "feat(policy-engine): add one-time migration of existing evidence/verdict JSON into auditor-database"
```

---

## Phase 7: Frontend (`auditor-web`)

### Task 10: Flutter project scaffold + API client + data models

**Files:**
- Create: `lab/auditor/web/pubspec.yaml`
- Create: `lab/auditor/web/lib/main.dart`
- Create: `lab/auditor/web/lib/models.dart`
- Create: `lab/auditor/web/lib/api_client.dart`
- Create: `lab/auditor/web/test/api_client_test.dart`
- Create: `lab/auditor/web/analysis_options.yaml`

**Interfaces:**
- Produces: `Evidence`, `Verdict`, `Device`, `Summary`, `Control` classes in `models.dart` (each with a `fromJson(Map<String, dynamic>)` factory); `ApiClient` class in `api_client.dart` with methods `getEvidence()`, `getVerdicts()`, `getDevices()`, `getSummary()`, `getControls()`, each returning a `Future<List<...>>` or `Future<...>`.

- [ ] **Step 1: Write the pubspec**

Create `lab/auditor/web/pubspec.yaml`:

```yaml
name: auditor_web
description: IoTGuard auditor dashboard
publish_to: 'none'
version: 1.0.0

environment:
  sdk: '>=3.5.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter
  http: ^1.2.2

dev_dependencies:
  flutter_test:
    sdk: flutter

flutter:
  uses-material-design: true
```

- [ ] **Step 2: Write the data models**

Create `lab/auditor/web/lib/models.dart`:

```dart
class Evidence {
  final String evidenceId;
  final String deviceId;
  final String testId;
  final String tool;
  final String toolVersion;
  final String command;
  final String timestamp;
  final String finding;
  final Map<String, dynamic> observations;
  final String rawOutputPath;
  final String confidence;
  final String sha256;

  Evidence({
    required this.evidenceId,
    required this.deviceId,
    required this.testId,
    required this.tool,
    required this.toolVersion,
    required this.command,
    required this.timestamp,
    required this.finding,
    required this.observations,
    required this.rawOutputPath,
    required this.confidence,
    required this.sha256,
  });

  factory Evidence.fromJson(Map<String, dynamic> json) {
    return Evidence(
      evidenceId: json['evidence_id'] as String,
      deviceId: json['device_id'] as String,
      testId: json['test_id'] as String,
      tool: json['tool'] as String,
      toolVersion: json['tool_version'] as String,
      command: json['command'] as String,
      timestamp: json['timestamp'] as String,
      finding: json['finding'] as String,
      observations: json['observations'] as Map<String, dynamic>,
      rawOutputPath: json['raw_output_path'] as String,
      confidence: json['confidence'] as String,
      sha256: json['sha256'] as String,
    );
  }
}

class Verdict {
  final String verdictId;
  final String controlId;
  final String deviceId;
  final String status;
  final String severity;
  final List<dynamic> evidenceIds;
  final String reason;
  final Map<String, dynamic> saudiSource;
  final String remediation;
  final String timestamp;

  Verdict({
    required this.verdictId,
    required this.controlId,
    required this.deviceId,
    required this.status,
    required this.severity,
    required this.evidenceIds,
    required this.reason,
    required this.saudiSource,
    required this.remediation,
    required this.timestamp,
  });

  factory Verdict.fromJson(Map<String, dynamic> json) {
    return Verdict(
      verdictId: json['verdict_id'] as String,
      controlId: json['control_id'] as String,
      deviceId: json['device_id'] as String,
      status: json['status'] as String,
      severity: json['severity'] as String,
      evidenceIds: json['evidence_ids'] as List<dynamic>,
      reason: json['reason'] as String,
      saudiSource: json['saudi_source'] as Map<String, dynamic>,
      remediation: json['remediation'] as String,
      timestamp: json['timestamp'] as String,
    );
  }
}

class Device {
  final String deviceId;
  final int evidenceCount;
  final int verdictCount;

  Device({
    required this.deviceId,
    required this.evidenceCount,
    required this.verdictCount,
  });

  factory Device.fromJson(Map<String, dynamic> json) {
    return Device(
      deviceId: json['device_id'] as String,
      evidenceCount: json['evidence_count'] as int,
      verdictCount: json['verdict_count'] as int,
    );
  }
}

class Summary {
  final int totalEvidence;
  final int totalVerdicts;
  final Map<String, dynamic> verdictsByStatus;

  Summary({
    required this.totalEvidence,
    required this.totalVerdicts,
    required this.verdictsByStatus,
  });

  factory Summary.fromJson(Map<String, dynamic> json) {
    return Summary(
      totalEvidence: json['total_evidence'] as int,
      totalVerdicts: json['total_verdicts'] as int,
      verdictsByStatus: json['verdicts_by_status'] as Map<String, dynamic>,
    );
  }
}

class Control {
  final String controlId;
  final String title;
  final Map<String, dynamic> saudiSource;
  final String remediation;

  Control({
    required this.controlId,
    required this.title,
    required this.saudiSource,
    required this.remediation,
  });

  factory Control.fromJson(Map<String, dynamic> json) {
    return Control(
      controlId: json['control_id'] as String,
      title: json['title'] as String,
      saudiSource: json['saudi_source'] as Map<String, dynamic>,
      remediation: json['remediation'] as String,
    );
  }
}
```

- [ ] **Step 3: Write the failing test**

Create `lab/auditor/web/test/api_client_test.dart`:

```dart
import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('getEvidence parses the response body into Evidence objects', () async {
    final mockClient = MockClient((request) async {
      expect(request.url.toString(), 'http://auditor-api:8000/evidence');
      return http.Response(
        jsonEncode([
          {
            'evidence_id': 'EV-2026-07-08-0013',
            'device_id': 'device-insecure',
            'test_id': 'TEST-NET-PORTSCAN',
            'tool': 'nmap',
            'tool_version': '7.95',
            'command': 'nmap -sV -p- device-insecure',
            'timestamp': '2026-07-08T08:06:42Z',
            'finding': 'Port 80 open',
            'observations': {'open_ports': [80]},
            'raw_output_path': 'document-store/raw/EV-2026-07-08-0013.txt',
            'confidence': 'high',
            'sha256': 'a' * 64,
          }
        ]),
        200,
      );
    });

    final client = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);
    final result = await client.getEvidence();

    expect(result.length, 1);
    expect(result.first.evidenceId, 'EV-2026-07-08-0013');
    expect(result.first.finding, 'Port 80 open');
  });

  test('getSummary parses aggregate counts', () async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'total_evidence': 12,
          'total_verdicts': 8,
          'verdicts_by_status': {'PASS': 4, 'FAIL': 4, 'PARTIAL': 0, 'INCONCLUSIVE': 0},
        }),
        200,
      );
    });

    final client = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);
    final result = await client.getSummary();

    expect(result.totalEvidence, 12);
    expect(result.verdictsByStatus['PASS'], 4);
  });
}
```

- [ ] **Step 4: Add `http`'s testing package**

Add to `pubspec.yaml`'s `dev_dependencies:` (already present as `http` main dependency covers `package:http/testing.dart` — no extra package needed since `http`'s test helpers ship in the same package).

- [ ] **Step 5: Run test to verify it fails**

Run (via Docker, since Flutter isn't installed locally): from `lab/auditor/web/`,

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test
```

Expected: FAIL (`package:auditor_web/api_client.dart` doesn't exist).

- [ ] **Step 6: Implement the API client**

Create `lab/auditor/web/lib/api_client.dart`:

```dart
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'models.dart';

class ApiClient {
  final String baseUrl;
  final http.Client httpClient;

  ApiClient({required this.baseUrl, http.Client? httpClient})
      : httpClient = httpClient ?? http.Client();

  Future<List<Evidence>> getEvidence() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/evidence'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((e) => Evidence.fromJson(e as Map<String, dynamic>)).toList();
  }

  Future<List<Verdict>> getVerdicts() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/verdicts'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((v) => Verdict.fromJson(v as Map<String, dynamic>)).toList();
  }

  Future<List<Device>> getDevices() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/devices'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((d) => Device.fromJson(d as Map<String, dynamic>)).toList();
  }

  Future<Summary> getSummary() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/summary'));
    return Summary.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<List<Control>> getControls() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/controls'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((c) => Control.fromJson(c as Map<String, dynamic>)).toList();
  }
}
```

- [ ] **Step 7: Write a placeholder `main.dart` so the project builds**

Create `lab/auditor/web/lib/main.dart`:

```dart
import 'package:flutter/material.dart';

void main() {
  runApp(const AuditorApp());
}

class AuditorApp extends StatelessWidget {
  const AuditorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'IoTGuard Auditor',
      home: Scaffold(body: Center(child: Text('IoTGuard Auditor Dashboard'))),
    );
  }
}
```

- [ ] **Step 8: Write a minimal lint config**

Create `lab/auditor/web/analysis_options.yaml`:

```yaml
include: package:flutter_lints/flutter.yaml
```

Add `flutter_lints: ^5.0.0` to `pubspec.yaml`'s `dev_dependencies:`.

- [ ] **Step 9: Run test to verify it passes**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test"
```

Expected: `2 tests passed` (or similar summary from `flutter test`'s output).

- [ ] **Step 10: Verify on the PC**

Over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab\auditor\web
docker run --rm -v ${PWD}:/app -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test"
```

Expected: same `2 tests passed` result, confirmed reproducible on the PC.

- [ ] **Step 11: Commit**

```bash
git add lab/auditor/web/
git commit -m "feat(auditor-web): scaffold Flutter project with API client and data models"
```

---

### Task 11: Theme (dark security-console design tokens)

**Files:**
- Create: `lab/auditor/web/lib/theme.dart`
- Create: `lab/auditor/web/test/theme_test.dart`

**Interfaces:**
- Produces: `auditorDarkTheme` (a `ThemeData`), `statusColor(String status) -> Color` in `theme.dart`.

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/test/theme_test.dart`:

```dart
import 'package:auditor_web/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('statusColor maps each known status to its design token', () {
    expect(statusColor('PASS'), const Color(0xFF4ADE80));
    expect(statusColor('FAIL'), const Color(0xFFF87171));
    expect(statusColor('PARTIAL'), const Color(0xFFFBBF24));
    expect(statusColor('INCONCLUSIVE'), const Color(0xFF94A3B8));
  });

  test('auditorDarkTheme uses the dark security-console background', () {
    expect(auditorDarkTheme.scaffoldBackgroundColor, const Color(0xFF0F172A));
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test test/theme_test.dart
```

Expected: FAIL (`package:auditor_web/theme.dart` doesn't exist).

- [ ] **Step 3: Implement the theme**

Create `lab/auditor/web/lib/theme.dart`:

```dart
import 'package:flutter/material.dart';

const Color kBackground = Color(0xFF0F172A);
const Color kSurface = Color(0xFF1E293B);
const Color kPrimaryText = Color(0xFFF1F5F9);
const Color kMutedText = Color(0xFF94A3B8);
const Color kAccent = Color(0xFF22D3EE);
const Color kStatusPass = Color(0xFF4ADE80);
const Color kStatusFail = Color(0xFFF87171);
const Color kStatusPartial = Color(0xFFFBBF24);
const Color kStatusInconclusive = Color(0xFF94A3B8);

Color statusColor(String status) {
  switch (status) {
    case 'PASS':
      return kStatusPass;
    case 'FAIL':
      return kStatusFail;
    case 'PARTIAL':
      return kStatusPartial;
    default:
      return kStatusInconclusive;
  }
}

final ThemeData auditorDarkTheme = ThemeData(
  brightness: Brightness.dark,
  scaffoldBackgroundColor: kBackground,
  colorScheme: const ColorScheme.dark(
    primary: kAccent,
    surface: kSurface,
    onSurface: kPrimaryText,
  ),
  cardColor: kSurface,
  textTheme: const TextTheme(
    bodyMedium: TextStyle(color: kPrimaryText),
    bodySmall: TextStyle(color: kMutedText),
  ),
  fontFamily: 'Inter',
);

const String kMonospaceFontFamily = 'JetBrains Mono';
```

- [ ] **Step 4: Run test to verify it passes**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test test/theme_test.dart"
```

Expected: `2 tests passed`.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/web/lib/theme.dart lab/auditor/web/test/theme_test.dart
git commit -m "feat(auditor-web): add dark security-console theme and status colors"
```

---

### Task 12: Navigation shell (`NavigationRail` + 4 screen placeholders)

**Files:**
- Modify: `lab/auditor/web/lib/main.dart`
- Create: `lab/auditor/web/lib/screens/overview_screen.dart`
- Create: `lab/auditor/web/lib/screens/devices_screen.dart`
- Create: `lab/auditor/web/lib/screens/evidence_screen.dart`
- Create: `lab/auditor/web/lib/screens/verdicts_screen.dart`
- Create: `lab/auditor/web/test/navigation_test.dart`

**Interfaces:**
- Produces: `HomeShell` widget in `main.dart` hosting a `NavigationRail` with 4 destinations, each rendering one of `OverviewScreen`, `DevicesScreen`, `EvidenceScreen`, `VerdictsScreen` (each currently a placeholder `Scaffold` with a `Text` label — filled in by Tasks 13-16).

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/test/navigation_test.dart`:

```dart
import 'package:auditor_web/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('tapping each nav rail destination shows its screen', (tester) async {
    await tester.pumpWidget(const AuditorApp());

    expect(find.text('Overview'), findsWidgets);

    await tester.tap(find.text('Devices').last);
    await tester.pumpAndSettle();
    expect(find.text('Devices Screen'), findsOneWidget);

    await tester.tap(find.text('Evidence').last);
    await tester.pumpAndSettle();
    expect(find.text('Evidence Screen'), findsOneWidget);

    await tester.tap(find.text('Verdicts').last);
    await tester.pumpAndSettle();
    expect(find.text('Verdicts Screen'), findsOneWidget);
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test test/navigation_test.dart
```

Expected: FAIL (`AuditorApp` currently just shows a static Scaffold, no nav rail).

- [ ] **Step 3: Write the 4 placeholder screens**

Create `lab/auditor/web/lib/screens/overview_screen.dart`:

```dart
import 'package:flutter/material.dart';

class OverviewScreen extends StatelessWidget {
  const OverviewScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return const Center(child: Text('Overview Screen'));
  }
}
```

Create `lab/auditor/web/lib/screens/devices_screen.dart`:

```dart
import 'package:flutter/material.dart';

class DevicesScreen extends StatelessWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return const Center(child: Text('Devices Screen'));
  }
}
```

Create `lab/auditor/web/lib/screens/evidence_screen.dart`:

```dart
import 'package:flutter/material.dart';

class EvidenceScreen extends StatelessWidget {
  const EvidenceScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return const Center(child: Text('Evidence Screen'));
  }
}
```

Create `lab/auditor/web/lib/screens/verdicts_screen.dart`:

```dart
import 'package:flutter/material.dart';

class VerdictsScreen extends StatelessWidget {
  const VerdictsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return const Center(child: Text('Verdicts Screen'));
  }
}
```

- [ ] **Step 4: Implement the navigation shell**

Replace `lab/auditor/web/lib/main.dart` with:

```dart
import 'package:flutter/material.dart';

import 'screens/devices_screen.dart';
import 'screens/evidence_screen.dart';
import 'screens/overview_screen.dart';
import 'screens/verdicts_screen.dart';
import 'theme.dart';

void main() {
  runApp(const AuditorApp());
}

class AuditorApp extends StatelessWidget {
  const AuditorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'IoTGuard Auditor',
      theme: auditorDarkTheme,
      home: const HomeShell(),
    );
  }
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _selectedIndex = 0;

  static const _screens = [
    OverviewScreen(),
    DevicesScreen(),
    EvidenceScreen(),
    VerdictsScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: _selectedIndex,
            onDestinationSelected: (index) => setState(() => _selectedIndex = index),
            labelType: NavigationRailLabelType.all,
            destinations: const [
              NavigationRailDestination(
                icon: Icon(Icons.dashboard_outlined),
                selectedIcon: Icon(Icons.dashboard),
                label: Text('Overview'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.devices_outlined),
                selectedIcon: Icon(Icons.devices),
                label: Text('Devices'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.fact_check_outlined),
                selectedIcon: Icon(Icons.fact_check),
                label: Text('Evidence'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.verified_outlined),
                selectedIcon: Icon(Icons.verified),
                label: Text('Verdicts'),
              ),
            ],
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: _screens[_selectedIndex]),
        ],
      ),
    );
  }
}
```

- [ ] **Step 5: Run test to verify it passes**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test test/navigation_test.dart"
```

Expected: `1 passed`.

- [ ] **Step 6: Run the full test suite so far**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test
```

Expected: all tests from Tasks 10-12 pass together.

- [ ] **Step 7: Commit**

```bash
git add lab/auditor/web/
git commit -m "feat(auditor-web): add NavigationRail shell with 4 screen placeholders"
```

---

### Task 13: Overview screen (stat cards from `/summary`)

**Files:**
- Modify: `lab/auditor/web/lib/screens/overview_screen.dart`
- Create: `lab/auditor/web/test/overview_screen_test.dart`

**Interfaces:**
- Consumes: `ApiClient.getSummary()` (Task 10), `statusColor()` (Task 11).
- Produces: `OverviewScreen({required ApiClient apiClient})` — now requires an `ApiClient` (this changes its constructor from Task 12's no-arg version; update `main.dart`'s `_screens` list in Step 4 below to pass a real client).

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/test/overview_screen_test.dart`:

```dart
import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/overview_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('shows total evidence and verdict-by-status counts', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'total_evidence': 12,
          'total_verdicts': 8,
          'verdicts_by_status': {'PASS': 4, 'FAIL': 4, 'PARTIAL': 0, 'INCONCLUSIVE': 0},
        }),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: OverviewScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('12'), findsOneWidget);
    expect(find.text('8'), findsOneWidget);
    expect(find.text('PASS: 4'), findsOneWidget);
    expect(find.text('FAIL: 4'), findsOneWidget);
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test test/overview_screen_test.dart
```

Expected: FAIL (`OverviewScreen` doesn't accept an `apiClient` parameter yet).

- [ ] **Step 3: Implement the screen**

Replace `lab/auditor/web/lib/screens/overview_screen.dart` with:

```dart
import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';

class OverviewScreen extends StatefulWidget {
  final ApiClient apiClient;

  const OverviewScreen({super.key, required this.apiClient});

  @override
  State<OverviewScreen> createState() => _OverviewScreenState();
}

class _OverviewScreenState extends State<OverviewScreen> {
  late Future<Summary> _summaryFuture;

  @override
  void initState() {
    super.initState();
    _summaryFuture = widget.apiClient.getSummary();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Summary>(
      future: _summaryFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final summary = snapshot.data!;
        return Padding(
          padding: const EdgeInsets.all(24),
          child: Wrap(
            spacing: 16,
            runSpacing: 16,
            children: [
              _StatCard(label: 'Total Evidence', value: '${summary.totalEvidence}'),
              _StatCard(label: 'Total Verdicts', value: '${summary.totalVerdicts}'),
              ...summary.verdictsByStatus.entries.map(
                (entry) => _StatCard(
                  label: entry.key,
                  value: '${entry.key}: ${entry.value}',
                  color: statusColor(entry.key),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _StatCard extends StatelessWidget {
  final String label;
  final String value;
  final Color? color;

  const _StatCard({required this.label, required this.value, this.color});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: kSurface,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Text(value, style: TextStyle(fontSize: 20, color: color ?? kPrimaryText)),
      ),
    );
  }
}
```

- [ ] **Step 4: Update `main.dart` to pass a real `ApiClient`**

In `lab/auditor/web/lib/main.dart`, add near the top of the file:

```dart
import 'api_client.dart';
```

Inside `_HomeShellState`, replace the `static const _screens` list with an instance field built in `initState` (since `OverviewScreen` now needs a constructor argument):

```dart
class _HomeShellState extends State<HomeShell> {
  int _selectedIndex = 0;
  late final ApiClient _apiClient;
  late final List<Widget> _screens;

  @override
  void initState() {
    super.initState();
    _apiClient = ApiClient(baseUrl: const String.fromEnvironment(
      'AUDITOR_API_URL',
      defaultValue: 'http://localhost:8000',
    ));
    _screens = [
      OverviewScreen(apiClient: _apiClient),
      const DevicesScreen(),
      const EvidenceScreen(),
      const VerdictsScreen(),
    ];
  }

  @override
  Widget build(BuildContext context) {
    // ... unchanged from Task 12 ...
  }
}
```

(Keep the rest of `_HomeShellState.build()` exactly as Task 12 left it — only `initState` and the field declarations change. `String.fromEnvironment` reads a compile-time define, set via `--dart-define=AUDITOR_API_URL=...` when building for the container in Task 14.)

- [ ] **Step 5: Run test to verify it passes**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test test/overview_screen_test.dart"
```

Expected: `1 passed`.

- [ ] **Step 6: Run the full suite**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test
```

Expected: all prior tests still pass (fix `test/navigation_test.dart` if `HomeShell`'s changed construction breaks it — it shouldn't, since `HomeShell`'s own constructor is unchanged).

- [ ] **Step 7: Commit**

```bash
git add lab/auditor/web/
git commit -m "feat(auditor-web): add Overview screen with summary stat cards"
```

---

### Task 14: Devices screen (list from `/devices`)

**Files:**
- Modify: `lab/auditor/web/lib/screens/devices_screen.dart`
- Modify: `lab/auditor/web/lib/main.dart`
- Create: `lab/auditor/web/test/devices_screen_test.dart`

**Interfaces:**
- Consumes: `ApiClient.getDevices()` (Task 10).
- Produces: `DevicesScreen({required ApiClient apiClient})`.

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/test/devices_screen_test.dart`:

```dart
import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/devices_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('lists each device with its evidence and verdict counts', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode([
          {'device_id': 'device-insecure', 'evidence_count': 5, 'verdict_count': 2},
          {'device_id': 'device-hardened', 'evidence_count': 3, 'verdict_count': 4},
        ]),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: DevicesScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('device-insecure'), findsOneWidget);
    expect(find.text('device-hardened'), findsOneWidget);
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test test/devices_screen_test.dart
```

Expected: FAIL.

- [ ] **Step 3: Implement the screen**

Replace `lab/auditor/web/lib/screens/devices_screen.dart` with:

```dart
import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';

class DevicesScreen extends StatefulWidget {
  final ApiClient apiClient;

  const DevicesScreen({super.key, required this.apiClient});

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  late Future<List<Device>> _devicesFuture;

  @override
  void initState() {
    super.initState();
    _devicesFuture = widget.apiClient.getDevices();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<Device>>(
      future: _devicesFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final devices = snapshot.data!;
        return ListView.builder(
          itemCount: devices.length,
          itemBuilder: (context, index) {
            final device = devices[index];
            return ListTile(
              leading: const Icon(Icons.devices_outlined),
              title: Text(device.deviceId),
              subtitle: Text(
                '${device.evidenceCount} evidence · ${device.verdictCount} verdicts',
              ),
            );
          },
        );
      },
    );
  }
}
```

- [ ] **Step 4: Update `main.dart`**

In `_HomeShellState.initState()`, replace `const DevicesScreen()` with `DevicesScreen(apiClient: _apiClient)`.

- [ ] **Step 5: Run test to verify it passes, then the full suite**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test"
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/web/
git commit -m "feat(auditor-web): add Devices screen listing devices with evidence/verdict counts"
```

---

### Task 15: Evidence screen (list + detail from `/evidence`)

**Files:**
- Modify: `lab/auditor/web/lib/screens/evidence_screen.dart`
- Modify: `lab/auditor/web/lib/main.dart`
- Create: `lab/auditor/web/test/evidence_screen_test.dart`

**Interfaces:**
- Consumes: `ApiClient.getEvidence()` (Task 10), `kMonospaceFontFamily` (Task 11).
- Produces: `EvidenceScreen({required ApiClient apiClient})`.

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/test/evidence_screen_test.dart`:

```dart
import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/evidence_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

Map<String, dynamic> _evidenceJson(String id, String finding) => {
      'evidence_id': id,
      'device_id': 'device-insecure',
      'test_id': 'TEST-NET-PORTSCAN',
      'tool': 'nmap',
      'tool_version': '7.95',
      'command': 'nmap -sV -p- device-insecure',
      'timestamp': '2026-07-08T08:06:42Z',
      'finding': finding,
      'observations': {'open_ports': [80]},
      'raw_output_path': 'document-store/raw/$id.txt',
      'confidence': 'high',
      'sha256': 'a' * 64,
    };

void main() {
  testWidgets('lists evidence and opens a detail panel on tap', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode([_evidenceJson('EV-2026-07-08-0013', 'Port 80 open')]),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: EvidenceScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('EV-2026-07-08-0013'), findsOneWidget);

    await tester.tap(find.text('EV-2026-07-08-0013'));
    await tester.pumpAndSettle();

    expect(find.text('Port 80 open'), findsWidgets);
    expect(find.text('document-store/raw/EV-2026-07-08-0013.txt'), findsOneWidget);
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test test/evidence_screen_test.dart
```

Expected: FAIL.

- [ ] **Step 3: Implement the screen**

Replace `lab/auditor/web/lib/screens/evidence_screen.dart` with:

```dart
import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';

class EvidenceScreen extends StatefulWidget {
  final ApiClient apiClient;

  const EvidenceScreen({super.key, required this.apiClient});

  @override
  State<EvidenceScreen> createState() => _EvidenceScreenState();
}

class _EvidenceScreenState extends State<EvidenceScreen> {
  late Future<List<Evidence>> _evidenceFuture;

  @override
  void initState() {
    super.initState();
    _evidenceFuture = widget.apiClient.getEvidence();
  }

  void _showDetail(BuildContext context, Evidence evidence) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: kSurface,
        title: Text(evidence.evidenceId, style: const TextStyle(fontFamily: kMonospaceFontFamily)),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('Finding: ${evidence.finding}'),
              const SizedBox(height: 8),
              Text('Tool: ${evidence.tool} ${evidence.toolVersion}'),
              Text('Confidence: ${evidence.confidence}'),
              const SizedBox(height: 8),
              Text(evidence.rawOutputPath, style: const TextStyle(fontFamily: kMonospaceFontFamily)),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Close')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<Evidence>>(
      future: _evidenceFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final evidence = snapshot.data!;
        return ListView.builder(
          itemCount: evidence.length,
          itemBuilder: (context, index) {
            final e = evidence[index];
            return ListTile(
              title: Text(e.evidenceId, style: const TextStyle(fontFamily: kMonospaceFontFamily)),
              subtitle: Text('${e.deviceId} · ${e.testId} · ${e.finding}'),
              onTap: () => _showDetail(context, e),
            );
          },
        );
      },
    );
  }
}
```

- [ ] **Step 4: Update `main.dart`**

In `_HomeShellState.initState()`, replace `const EvidenceScreen()` with `EvidenceScreen(apiClient: _apiClient)`.

- [ ] **Step 5: Run test to verify it passes, then the full suite**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test"
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/web/
git commit -m "feat(auditor-web): add Evidence screen with list and detail dialog"
```

---

### Task 16: Verdicts screen (list + detail from `/verdicts`)

**Files:**
- Modify: `lab/auditor/web/lib/screens/verdicts_screen.dart`
- Modify: `lab/auditor/web/lib/main.dart`
- Create: `lab/auditor/web/test/verdicts_screen_test.dart`

**Interfaces:**
- Consumes: `ApiClient.getVerdicts()` (Task 10), `statusColor()` (Task 11).
- Produces: `VerdictsScreen({required ApiClient apiClient})`.

- [ ] **Step 1: Write the failing test**

Create `lab/auditor/web/test/verdicts_screen_test.dart`:

```dart
import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/verdicts_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

Map<String, dynamic> _verdictJson(String id, String controlId, String status) => {
      'verdict_id': id,
      'control_id': controlId,
      'device_id': 'device-insecure',
      'status': status,
      'severity': 'high',
      'evidence_ids': ['EV-2026-07-08-0015'],
      'reason': 'Default credentials accepted',
      'saudi_source': {'framework': 'CGIoT-1:2024', 'reference': '2-2-2'},
      'remediation': 'Force password change',
      'timestamp': '2026-07-08T08:06:42Z',
    };

void main() {
  testWidgets('lists verdicts with status chips and opens detail on tap', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode([_verdictJson('VD-2026-07-08-0003', 'SA-IOT-002', 'FAIL')]),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: VerdictsScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('FAIL'), findsOneWidget);
    expect(find.text('SA-IOT-002'), findsOneWidget);

    await tester.tap(find.text('SA-IOT-002'));
    await tester.pumpAndSettle();

    expect(find.text('Default credentials accepted'), findsOneWidget);
    expect(find.text('Force password change'), findsOneWidget);
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable flutter test test/verdicts_screen_test.dart
```

Expected: FAIL.

- [ ] **Step 3: Implement the screen**

Replace `lab/auditor/web/lib/screens/verdicts_screen.dart` with:

```dart
import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';

class VerdictsScreen extends StatefulWidget {
  final ApiClient apiClient;

  const VerdictsScreen({super.key, required this.apiClient});

  @override
  State<VerdictsScreen> createState() => _VerdictsScreenState();
}

class _VerdictsScreenState extends State<VerdictsScreen> {
  late Future<List<Verdict>> _verdictsFuture;

  @override
  void initState() {
    super.initState();
    _verdictsFuture = widget.apiClient.getVerdicts();
  }

  void _showDetail(BuildContext context, Verdict verdict) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: kSurface,
        title: Text(verdict.controlId),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(verdict.reason),
              const SizedBox(height: 8),
              Text('${verdict.saudiSource['framework']} §${verdict.saudiSource['reference']}'),
              const SizedBox(height: 8),
              Text(verdict.remediation),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Close')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<Verdict>>(
      future: _verdictsFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final verdicts = snapshot.data!;
        return ListView.builder(
          itemCount: verdicts.length,
          itemBuilder: (context, index) {
            final v = verdicts[index];
            return ListTile(
              leading: CircleAvatar(
                backgroundColor: statusColor(v.status),
                child: Text(v.status[0], style: const TextStyle(color: kBackground)),
              ),
              title: Text(v.controlId),
              subtitle: Text('${v.deviceId} · ${v.status}'),
              trailing: Text(v.status, style: TextStyle(color: statusColor(v.status))),
              onTap: () => _showDetail(context, v),
            );
          },
        );
      },
    );
  }
}
```

- [ ] **Step 4: Update `main.dart`**

In `_HomeShellState.initState()`, replace `const VerdictsScreen()` with `VerdictsScreen(apiClient: _apiClient)`.

- [ ] **Step 5: Run test to verify it passes, then the full suite**

```
docker run --rm -v "${PWD}:/app" -w /app ghcr.io/cirruslabs/flutter:stable sh -c "flutter pub get && flutter test"
```

Expected: all tests across Tasks 10-16 pass together.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/web/
git commit -m "feat(auditor-web): add Verdicts screen with status chips and detail dialog"
```

---

### Task 17: `auditor-web` Dockerfile + compose wiring

**Files:**
- Create: `lab/auditor/web/Dockerfile`
- Modify: `lab/docker-compose.yml` (add `auditor-web` service)

**Interfaces:**
- Produces: a container serving the compiled Flutter web app on port 80, published to the host at `:8080` per the spec.

- [ ] **Step 1: Write the multi-stage Dockerfile**

Create `lab/auditor/web/Dockerfile`:

```dockerfile
FROM ghcr.io/cirruslabs/flutter:stable AS build
WORKDIR /app
COPY pubspec.yaml .
RUN flutter pub get
COPY . .
RUN flutter build web --release --dart-define=AUDITOR_API_URL=http://localhost:8000

FROM nginx:alpine
COPY --from=build /app/build/web /usr/share/nginx/html
EXPOSE 80
```

(`AUDITOR_API_URL=http://localhost:8000` here assumes `docker-compose.dev.yml` also publishes `auditor-api`'s port to the host for the browser to reach directly — since the compiled Flutter Web app runs in the user's browser, not inside the `internal-network`, it cannot reach `auditor-api` by its Docker service name. Confirm this against `lab/docker-compose.dev.yml`'s existing pattern in Step 2 before finalizing; if `auditor-api` isn't already host-published there, add it.)

- [ ] **Step 2: Check and update `docker-compose.dev.yml`**

Read the existing `lab/docker-compose.dev.yml` in full. If it doesn't already publish `auditor-api`'s port 8000 to the host, add:

```yaml
services:
  auditor-api:
    ports:
      - "8000:8000"
```

- [ ] **Step 3: Wire `auditor-web` into the main compose file**

Add to `lab/docker-compose.yml`, after `auditor-api`:

```yaml
  auditor-web:
    build: ./auditor/web
    ports:
      - "8080:80"
    networks:
      - internal-network
    depends_on:
      - auditor-api
```

- [ ] **Step 4: Build and verify on the PC**

Commit first (Step 5), then over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose -f docker-compose.yml -f docker-compose.dev.yml build auditor-web auditor-api auditor-database --provenance=false
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d auditor-database auditor-api auditor-web
```

Wait ~30s (Flutter web build takes longer than the other images), then:

```
curl -s -o NUL -w "%{http_code}" http://localhost:8080
```

Expected: `200`. Then:

```
docker compose down
```

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/web/Dockerfile lab/docker-compose.yml lab/docker-compose.dev.yml
git commit -m "feat(auditor-web): add Dockerfile and wire into compose, published at :8080"
```

---

## Phase 8: Polish & Demo

### Task 18: `traffic-capture` service

**Files:**
- Create: `lab/traffic-capture/Dockerfile`
- Modify: `lab/docker-compose.yml` (add `traffic-capture` service)

**Interfaces:**
- Produces: a container running `tcpdump` on `audit-network`, writing `.pcap` files to a mounted `document-store/pcap/` directory.

- [ ] **Step 1: Write the Dockerfile**

Create `lab/traffic-capture/Dockerfile`:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache tcpdump
ENTRYPOINT ["sh", "-c", "tcpdump -i eth0 -w /pcap/capture-$(date +%Y%m%d-%H%M%S).pcap"]
```

- [ ] **Step 2: Wire into compose**

Add to `lab/docker-compose.yml`, inside the `audit-network` group of services (near `telnet-sim`):

```yaml
  traffic-capture:
    build: ./traffic-capture
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ../document-store/pcap:/pcap
    networks:
      - audit-network
```

- [ ] **Step 3: Add the pcap directory**

Create `document-store/pcap/.gitkeep` (empty file, matching the existing `.gitkeep` pattern already used for `document-store/evidence/`, `document-store/raw/`, `document-store/verdicts/`).

Add to `.gitignore`, alongside the existing `document-store/raw/` entry:

```
document-store/pcap/*.pcap
```

- [ ] **Step 4: Build and verify on the PC**

Commit first (Step 5), then over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose build traffic-capture --provenance=false
docker compose up -d device-insecure traffic-capture
```

Wait ~10s, generate some traffic, then check a capture file exists:

```
docker compose exec device-insecure python -c "import urllib.request; urllib.request.urlopen('http://localhost/health', timeout=2)"
Start-Sleep -Seconds 3
docker compose exec traffic-capture ls /pcap
```

Expected: a `capture-*.pcap` file listed with non-zero size. Then:

```
docker compose down
```

- [ ] **Step 5: Commit**

```bash
git add lab/traffic-capture/ lab/docker-compose.yml document-store/pcap/.gitkeep .gitignore
git commit -m "feat(traffic-capture): add tcpdump service capturing audit-network traffic"
```

---

### Task 19: Update `lab/README.md` and `lab/.env.example` for the full stack

**Files:**
- Modify: `lab/README.md`
- Modify: `lab/.env.example`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Read the current README in full**

Read `lab/README.md` (written in Phase 3, Task 21) before editing — this task extends it, not replaces it.

- [ ] **Step 2: Add a new section covering the full stack**

Append to `lab/README.md`:

```markdown
## Full Stack (Phases 6-8)

Beyond the Day-1/2/3 core, the lab now includes:

- **auditor-database** (PostgreSQL) — stores evidence and verdicts. Schema auto-created on first boot from
  `lab/auditor/db/init.sql`.
- **auditor-api** (FastAPI, `:8000` internal / `:8000` host-published via `docker-compose.dev.yml`) — REST
  API for evidence, verdicts, controls, devices, and summary stats. No authentication (network-isolated).
- **auditor-web** (Flutter Web, `:8080` host-published) — the dashboard. Open http://localhost:8080 after
  bringing the stack up.
- **traffic-capture** — `tcpdump` on `audit-network`, writes `.pcap` files to `document-store/pcap/`.

### Bring up the full stack

```
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

### One-time migration of Phase 0-5 evidence

If `document-store/evidence/*.json` and `document-store/verdicts/*.json` already contain records from
before Phases 6-8 (they will, from the Phase 0-5 sprint), load them into the database once:

```
docker compose exec auditor-worker sh -c "cd /work && python -m policies.engine.migrate_existing_records"
```

### Verify

- Dashboard: http://localhost:8080 — should show the Overview screen with non-zero evidence/verdict counts
  after migration.
- API directly: http://localhost:8000/summary
```

- [ ] **Step 3: Update `.env.example` if new environment variables were introduced**

Read `lab/.env.example`. If `AUDITOR_API_URL`, `DATABASE_URL`, or Postgres credentials aren't already
documented there, add them with the same values used in `docker-compose.yml`.

- [ ] **Step 4: Commit**

```bash
git add lab/README.md lab/.env.example
git commit -m "docs: update lab README for the full Phases 6-8 stack"
```

---

### Task 20: End-to-end acceptance verification

**Files:**
- Create: `docs/architecture/phases-6-8-acceptance.md`

**Interfaces:** None (documentation + verification only).

- [ ] **Step 1: Bring up the entire stack on the PC**

Over ssh-mcp:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab
git pull
cd lab
docker compose -f docker-compose.yml -f docker-compose.dev.yml build --provenance=false
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Wait ~45s for every healthcheck (Postgres, API, Flutter web build, all 3 device profiles, both brokers).

- [ ] **Step 2: Run the migration**

```
docker compose exec auditor-worker sh -c "cd /work && python -m policies.engine.migrate_existing_records"
```

Expected: `Migrated 12 evidence records and 8 verdicts`.

- [ ] **Step 3: Verify the dashboard end-to-end**

```
curl -s http://localhost:8080 | Select-String "IoTGuard"
curl -s http://localhost:8000/summary
```

Expected: the dashboard's HTML/JS bundle is served (contains the app title somewhere in its compiled JS or index.html), and `/summary` returns `{"total_evidence":12,"total_verdicts":8,...}`.

- [ ] **Step 4: Confirm all 4 controls' PASS/FAIL pairs survived migration**

```
curl -s http://localhost:8000/verdicts | python -c "import sys, json; vs = json.load(sys.stdin); statuses = {}; [statuses.setdefault(v['control_id'], set()).add(v['status']) for v in vs]; print(statuses)"
```

Expected: at least 4 control IDs each mapping to a set containing both `'PASS'` and `'FAIL'` (matching the
Phase 0-5 acceptance results — migration must not have lost or altered any verdict).

- [ ] **Step 5: Tear down**

```
docker compose down
```

- [ ] **Step 6: Write the acceptance doc**

Create `docs/architecture/phases-6-8-acceptance.md`, following the structure of
`docs/architecture/phases-0-5-acceptance.md` (Phase 0-5's own acceptance doc) — one checklist section per
phase (6, 7, 8), each item checked off with the exact command run and its real output from Steps 1-4 above.
Include the full test counts from every task in this plan (auditor-api's pytest suite, the worker adapter
tests, `generate_verdicts`/`migrate_existing_records` tests, and Flutter's `flutter test` summary).

- [ ] **Step 7: Update `CLAUDE.md`**

Update `CLAUDE.md` §0 (Current Status) to record Phases 6-8 as complete, following the same pattern used
when Phase 0-5 completed (see the existing §8 changelog entry dated the day Phase 0-5 finished, as a
template for tone and content). Add a new §8 changelog row summarizing what Phases 6-8 added.

- [ ] **Step 8: Commit**

```bash
git add docs/architecture/phases-6-8-acceptance.md CLAUDE.md
git commit -m "docs: Phases 6-8 acceptance verification, full stack complete"
```
