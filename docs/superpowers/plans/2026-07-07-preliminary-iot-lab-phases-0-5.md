# Preliminary IoT Security Lab — Phases 0-5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the graded core of the KAUST IoT preliminary sprint — a Dockerized 3-device IoT lab (insecure/partial/hardened smart camera), a manual assessment toolbox that produces reproducible evidence, and a deterministic policy-as-code engine that turns evidence + Saudi NCA (CGIoT-1:2024) controls into Pass/Fail verdicts. Phases 0-5 alone satisfy Day-1, Day-2, and Day-3 acceptance criteria; `auditor-api`/`auditor-database`/`auditor-web` (Phases 6-8) are a separate follow-up plan.

**Architecture:** One FastAPI "smart-camera" image reused for all three device postures (config-driven, not code-driven), two real Mosquitto brokers (plaintext + TLS), a Telnet-banner simulator, a toolbox `auditor-worker` container (nmap/openssl/yara/syft/grype) dual-homed across an untrusted `audit-network` and a trusted `internal-network`, and a filesystem-based `document-store` for evidence/verdict JSON. Evidence and verdicts are deterministic Python — no LLM in the decision path.

**Tech Stack:** Python 3.12 (containers) / Python 3.14 (local laptop tooling — same stdlib-level code, no version-specific syntax used), FastAPI, Uvicorn, Pydantic v2 + pydantic-settings, paho-mqtt 1.6.x, PyYAML, jsonschema, yara-python, pytest, Docker Compose v2, Eclipse Mosquitto, OpenSSL (containerized, not host-installed).

## Global Constraints

- **Determinism rule (non-negotiable):** evidence collection and verdict logic are deterministic Python. Verdict conditions are structured `{field, op, value}` triples evaluated by a fixed operator table — **never** `eval`/`exec` on arbitrary expressions.
- **Trust boundaries (spec §3):** only `auditor-web`/dev tooling talks to the host; devices/brokers are never published to the host port range. `auditor-worker` is the only container on both `audit-network` (172.30.0.0/24) and `internal-network` (172.31.0.0/24).
- **Difference between device postures is data, not code:** one smart-camera image, three env-var profiles (`lab/devices/smart-camera/profiles/{insecure,partial,hardened}.env`).
- **Dev machine split (Workflow B):** pure-Python work (FastAPI app logic, policy engine, schema validators, firmware generator) is written and unit-tested **locally on the laptop** with `pytest` — no Docker required for that. Anything requiring Docker/Compose/networking runs **on the 32 GB PC** (`OSRA-PC2025-V2`) via the `mcp__ssh-mcp__exec` tool, after `git push` (laptop) → `git pull` (PC). Every PC-side step in this plan is explicitly marked **(PC via ssh-mcp)**.
- **PC shell is Windows PowerShell 5.1, not bash:** use `;` to chain commands, never `&&`. `docker`/`docker compose` work directly from this PowerShell session (Docker Desktop WSL2 backend, verified working — no need to invoke `wsl` explicitly).
- **PowerShell stderr quirk:** redirecting a native command's stderr (`2>&1`) wraps it in a `NativeCommandError` and makes the tool call report an error even when the command actually succeeded (git does this routinely — it writes "Cloning into..." to stderr). When a PC step "fails" with a `NativeCommandError`, follow up with a state-check command (`docker compose ps`, `Test-Path`, `git log`) before concluding it actually failed.
- **Line endings:** all shell scripts (`*.sh`) must be committed with LF endings — Windows `core.autocrlf=true` on the PC would otherwise corrupt shebangs when Docker copies them into Linux containers. Enforced via `.gitattributes` in Task 1.
- **No secrets in the repo beyond intentional lab fixtures:** the hardcoded passwords/API keys/private keys baked into `device-insecure` and the firmware archives are **intentional training fixtures** for a sandboxed, non-internet-facing lab — call this out in code comments where it might otherwise look like a real leak.
- **Container base images:** `python:3.12-slim` for Python services, `alpine:3.20` for tiny utilities (telnet-sim, cert-init), `eclipse-mosquitto:2` for brokers.
- **Every error hit during implementation gets its own file in `docs/errors/`** per `docs/errors/ERROR_TEMPLATE.md` (CLAUDE.md §6 — mandatory, not optional).
- **Docker on the PC needs two workarounds (see ERR-003, ERR-004):** (1) the PC's `~/.docker/config.json` has had `credsStore` removed since Docker Desktop's credential helper can't reach the interactive-session credential vault over a headless SSH session — anonymous pulls of public images work fine without it. (2) `docker build`/`docker compose ... --build` may report a spurious `image "...": already exists` error at the final export step even though the image built successfully (a buildx/containerd-store attestation-manifest quirk) — add `--provenance=false` to `docker build` invocations, and after any build "failure," check `docker images`/`docker compose ps` before concluding it actually failed.

---

## File Structure

```
lab/
  docker-compose.yml
  docker-compose.dev.yml
  .env.example
  README.md
  .gitattributes                          # (repo root actually — see Task 1)
  devices/smart-camera/
    Dockerfile
    entrypoint.sh
    requirements.txt
    app/
      __init__.py
      config.py
      mqtt_publisher.py
      main.py
    tests/
      test_config.py
      test_main.py
    profiles/
      insecure.env
      partial.env
      hardened.env
    docs/
      privacy_insecure.md
      privacy_partial.md
      privacy_hardened.md
  telnet-sim/
    Dockerfile
    banner_server.py
  mqtt/
    insecure/mosquitto.conf
    secure/mosquitto.conf
  certs/
    Dockerfile
    generate.sh
    .gitignore                            # ignore generated *.key/*.crt, keep scripts
  auditor/
    worker/
      Dockerfile
      requirements.txt
      tests/
        record_evidence.py
        test_record_evidence.py
        run_catalog.md                    # manual test-catalog runbook (Day-2 procedure)
      firmware/
        generate_firmware.py
        scan_firmware.py
        test_generate_firmware.py
        test_scan_firmware.py
        rules/iot_secrets.yar
policies/
  schema/
    evidence.schema.json
    verdict.schema.json
    control.schema.json
    validate.py
    test_validate.py
  engine/
    policy_engine.py
    test_policy_engine.py
  controls/
    SA-IOT-001.yaml
    SA-IOT-002.yaml
    SA-IOT-003.yaml
    SA-IOT-004.yaml
    SA-IOT-005.yaml
document-store/
  evidence/.gitkeep
  raw/.gitkeep
  verdicts/.gitkeep
  firmware/.gitkeep
docs/architecture/
  architecture-diagram.md
  trust-boundary-diagram.md
  threat-model-stride.md
  device-inventory.md
```

`policies/` and `document-store/` sit at the repo root (not under `lab/`) so the policy engine and evidence store are shared, reusable spine — matching spec §9's top-level layout.

---

### Task 1: Repo skeleton, `.gitattributes`, and shared Python tooling baseline

**Files:**
- Create: all directories listed in File Structure above (as `.gitkeep` placeholders where empty)
- Create: `.gitattributes` (repo root)
- Create: `lab/.env.example`
- Create: `requirements-dev.txt` (repo root — pytest, jsonschema, pyyaml for local test runs across `policies/` and firmware modules)

**Interfaces:**
- Produces: the directory skeleton every later task writes into. No code interfaces yet.

- [ ] **Step 1: Create the directory skeleton (laptop, bash)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
mkdir -p lab/devices/smart-camera/app lab/devices/smart-camera/tests lab/devices/smart-camera/profiles lab/devices/smart-camera/docs
mkdir -p lab/telnet-sim
mkdir -p lab/mqtt/insecure lab/mqtt/secure
mkdir -p lab/certs
mkdir -p lab/auditor/worker/tests lab/auditor/worker/firmware/rules
mkdir -p policies/schema policies/engine policies/controls
mkdir -p document-store/evidence document-store/raw document-store/verdicts document-store/firmware
mkdir -p docs/architecture
touch document-store/evidence/.gitkeep document-store/raw/.gitkeep document-store/verdicts/.gitkeep document-store/firmware/.gitkeep
```

- [ ] **Step 2: Add `.gitattributes` to force LF on shell scripts and Python files**

Create `.gitattributes` at the repo root:

```gitattributes
* text=auto eol=lf
*.sh text eol=lf
*.py text eol=lf
*.yaml text eol=lf
*.yml text eol=lf
*.json text eol=lf
*.bat text eol=crlf
```

- [ ] **Step 3: Create `lab/.env.example` with all profile toggles from spec §4**

```dotenv
# Device identity
DEVICE_ID=device-insecure
DEVICE_VENDOR=AcmeCam
DEVICE_MODEL=AC-100
DEVICE_MAC=AA:BB:CC:00:11:22
FIRMWARE_VERSION=1.0.0-old

# Transport / TLS
TRANSPORT=http            # http | https
TLS_PROFILE=none          # none | weak | strong
TLS_KEYFILE=
TLS_CERTFILE=

# Credentials
CRED_MODE=default         # default | strong
ADMIN_USER=admin
ADMIN_PASS=admin

# API key exposure
EXPOSE_API_KEY=true
API_KEY=sk-insecure-hardcoded-key-000111222

# Admin endpoint auth
REQUIRE_ADMIN_AUTH=false

# Logging
LOGGING_MODE=off          # off | basic | security

# MQTT
MQTT_HOST=mqtt-broker-insecure
MQTT_PORT=1883
MQTT_TLS=false
MQTT_CA_CERT=

# Privacy doc
PRIVACY_DOC_PATH=docs/privacy_insecure.md
```

- [ ] **Step 4: Create `requirements-dev.txt` at repo root**

```
pytest==8.3.3
pyyaml==6.0.2
jsonschema==4.23.0
```

- [ ] **Step 5: Create a local venv and install dev requirements (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
python -m venv .venv
".venv/Scripts/pip" install -r requirements-dev.txt
```

Expected: no errors; `.venv/Scripts/pytest --version` prints a version string.

- [ ] **Step 6: Add `.venv/` to `.gitignore`, commit skeleton**

Check `.gitignore` already has a `.venv/` entry (it may already exclude venvs) — if not, append it:

```bash
grep -q '^\.venv/' .gitignore || echo '.venv/' >> .gitignore
```

- [ ] **Step 7: Commit**

```bash
git add .gitattributes .gitignore lab/.env.example requirements-dev.txt document-store lab docs/architecture policies auditor 2>/dev/null
git add -A -- 'document-store/*/.gitkeep'
git status
git commit -m "chore: scaffold lab/policies/document-store directory skeleton"
```

---

### Task 2: Evidence, verdict, and control JSON Schemas + Python validator (TDD)

**Files:**
- Create: `policies/schema/evidence.schema.json`
- Create: `policies/schema/verdict.schema.json`
- Create: `policies/schema/control.schema.json`
- Create: `policies/schema/validate.py`
- Test: `policies/schema/test_validate.py`

**Interfaces:**
- Produces: `validate_evidence(record: dict) -> None` (raises `jsonschema.ValidationError` on failure), `validate_verdict(record: dict) -> None`, `validate_control(record: dict) -> None`. Every later task that writes evidence/verdict/control data imports these.

- [ ] **Step 1: Write the failing tests first**

Create `policies/schema/test_validate.py`:

```python
import pytest
from jsonschema import ValidationError
from policies.schema.validate import validate_evidence, validate_verdict, validate_control

VALID_EVIDENCE = {
    "evidence_id": "EV-2026-07-08-0007",
    "device_id": "device-insecure",
    "test_id": "TEST-NET-PORTSCAN",
    "tool": "nmap",
    "tool_version": "7.94",
    "command": "nmap -sV -p- device-insecure",
    "timestamp": "2026-07-08T10:15:32Z",
    "finding": "Telnet (23/tcp) open; plaintext management exposed",
    "observations": {"open_ports": [23, 80, 1883], "telnet_open": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-0007.txt",
    "confidence": "high",
    "sha256": "3f2a" + "0" * 60,
}

VALID_VERDICT = {
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
    "timestamp": "2026-07-08T10:16:04Z",
}

VALID_CONTROL = {
    "control_id": "SA-IOT-002",
    "title": "No default or hard-coded credentials",
    "saudi_source": [{"framework": "CGIoT-1:2024", "reference": "2-2-2", "clause": "..."}],
    "applicability": {"device_type": ["smart-camera"]},
    "required_evidence": [{"test_id": "TEST-AUTH-DEFAULT-CREDS"}],
    "automated_test_ids": ["TEST-AUTH-DEFAULT-CREDS"],
    "severity": "high",
    "conditions": {
        "pass": {"field": "observations.default_creds", "op": "equals", "value": False},
        "fail": {"field": "observations.default_creds", "op": "equals", "value": True},
        "partial": None,
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    },
    "remediation": "Force a unique strong password on first boot; remove all vendor defaults.",
}


def test_valid_evidence_passes():
    validate_evidence(VALID_EVIDENCE)  # should not raise


def test_evidence_missing_field_fails():
    with pytest.raises(ValidationError):
        validate_evidence({"evidence_id": "EV-2026-07-08-0007"})


def test_evidence_bad_confidence_enum_fails():
    bad = dict(VALID_EVIDENCE)
    bad["confidence"] = "extreme"
    with pytest.raises(ValidationError):
        validate_evidence(bad)


def test_evidence_bad_sha256_shape_fails():
    bad = dict(VALID_EVIDENCE)
    bad["sha256"] = "not-a-hash"
    with pytest.raises(ValidationError):
        validate_evidence(bad)


def test_valid_verdict_passes():
    validate_verdict(VALID_VERDICT)


def test_verdict_bad_status_enum_fails():
    bad = dict(VALID_VERDICT)
    bad["status"] = "MAYBE"
    with pytest.raises(ValidationError):
        validate_verdict(bad)


def test_valid_control_passes():
    validate_control(VALID_CONTROL)


def test_control_missing_conditions_fails():
    bad = dict(VALID_CONTROL)
    del bad["conditions"]
    with pytest.raises(ValidationError):
        validate_control(bad)
```

- [ ] **Step 2: Run the tests to verify they fail (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/schema/test_validate.py -v
```

Expected: `ModuleNotFoundError: No module named 'policies.schema.validate'` (or import error) — the module doesn't exist yet. Also create empty `policies/__init__.py` and `policies/schema/__init__.py` so the package imports resolve once the module exists.

```bash
touch policies/__init__.py policies/schema/__init__.py
```

- [ ] **Step 3: Write `policies/schema/evidence.schema.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "EvidenceRecord",
  "type": "object",
  "required": [
    "evidence_id", "device_id", "test_id", "tool", "tool_version",
    "command", "timestamp", "finding", "observations",
    "raw_output_path", "confidence", "sha256"
  ],
  "properties": {
    "evidence_id": {"type": "string", "pattern": "^EV-\\d{4}-\\d{2}-\\d{2}-\\d{4}$"},
    "device_id": {"type": "string"},
    "test_id": {"type": "string"},
    "tool": {"type": "string"},
    "tool_version": {"type": "string"},
    "command": {"type": "string"},
    "timestamp": {"type": "string"},
    "finding": {"type": "string"},
    "observations": {"type": "object"},
    "raw_output_path": {"type": "string"},
    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}
  },
  "additionalProperties": false
}
```

- [ ] **Step 4: Write `policies/schema/verdict.schema.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "VerdictRecord",
  "type": "object",
  "required": [
    "verdict_id", "control_id", "device_id", "status", "severity",
    "evidence_ids", "matched", "reason", "saudi_source", "remediation", "timestamp"
  ],
  "properties": {
    "verdict_id": {"type": "string", "pattern": "^VD-\\d{4}-\\d{2}-\\d{2}-\\d{4}$"},
    "control_id": {"type": "string"},
    "device_id": {"type": "string"},
    "status": {"type": "string", "enum": ["PASS", "FAIL", "PARTIAL", "INCONCLUSIVE"]},
    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    "evidence_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
    "matched": {"type": "string", "enum": ["pass", "fail", "partial", "inconclusive"]},
    "reason": {"type": "string"},
    "saudi_source": {"type": "string"},
    "remediation": {"type": "string"},
    "timestamp": {"type": "string"}
  },
  "additionalProperties": false
}
```

- [ ] **Step 5: Write `policies/schema/control.schema.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ControlDefinition",
  "type": "object",
  "required": [
    "control_id", "title", "saudi_source", "applicability",
    "required_evidence", "automated_test_ids", "severity", "conditions", "remediation"
  ],
  "properties": {
    "control_id": {"type": "string", "pattern": "^SA-IOT-\\d{3}$"},
    "title": {"type": "string"},
    "saudi_source": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["framework", "reference"],
        "properties": {
          "framework": {"type": "string"},
          "reference": {"type": "string"},
          "clause": {"type": "string"}
        }
      }
    },
    "applicability": {
      "type": "object",
      "required": ["device_type"],
      "properties": {"device_type": {"type": "array", "items": {"type": "string"}}}
    },
    "required_evidence": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["test_id"],
        "properties": {"test_id": {"type": "string"}}
      }
    },
    "automated_test_ids": {"type": "array", "items": {"type": "string"}},
    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    "conditions": {
      "type": "object",
      "required": ["pass", "fail", "partial", "inconclusive"],
      "properties": {
        "pass": {"type": ["object", "null"]},
        "fail": {"type": ["object", "null"]},
        "partial": {"type": ["object", "null"]},
        "inconclusive": {"type": ["object", "null"]}
      }
    },
    "remediation": {"type": "string"}
  },
  "additionalProperties": false
}
```

- [ ] **Step 6: Write `policies/schema/validate.py`**

```python
import json
from pathlib import Path
from jsonschema import validate

SCHEMA_DIR = Path(__file__).parent


def _load_schema(name: str) -> dict:
    with open(SCHEMA_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


EVIDENCE_SCHEMA = _load_schema("evidence.schema.json")
VERDICT_SCHEMA = _load_schema("verdict.schema.json")
CONTROL_SCHEMA = _load_schema("control.schema.json")


def validate_evidence(record: dict) -> None:
    validate(instance=record, schema=EVIDENCE_SCHEMA)


def validate_verdict(record: dict) -> None:
    validate(instance=record, schema=VERDICT_SCHEMA)


def validate_control(record: dict) -> None:
    validate(instance=record, schema=CONTROL_SCHEMA)
```

- [ ] **Step 7: Run the tests to verify they pass (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/schema/test_validate.py -v
```

Expected: 8 passed.

- [ ] **Step 8: Commit**

```bash
git add policies/__init__.py policies/schema
git commit -m "feat: add evidence/verdict/control JSON schemas and validator"
```

---

### Task 3: `docker-compose.yml` skeleton with the two networks

**Files:**
- Create: `lab/docker-compose.yml`
- Create: `lab/docker-compose.dev.yml`

**Interfaces:**
- Produces: the `audit-network` (172.30.0.0/24) and `internal-network` (172.31.0.0/24) networks that every later service task attaches to, by name `lab_audit-network` / `lab_internal-network` (Compose project-prefixed) or as declared below with explicit names to avoid prefix ambiguity.

- [ ] **Step 1: Write `lab/docker-compose.yml` with just networks + a version comment**

```yaml
name: kaust-iot-lab

networks:
  audit-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
  internal-network:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.31.0.0/24

services: {}
```

Note: `internal: true` on `internal-network` blocks it from having a default route to the host/internet, reinforcing the trust boundary — `auditor-worker` (the only dual-homed container, added in Task 22) is deliberately also attached to `audit-network` so it can still reach the internet-independent lab devices and, later, publish evidence to the backend.

- [ ] **Step 2: Write `lab/docker-compose.dev.yml` (optional host-port overrides for developer convenience)**

```yaml
# Overlay for local development only — exposes device ports to localhost.
# Usage: docker compose -f docker-compose.yml -f docker-compose.dev.yml up
# Default (docker-compose.yml alone) does NOT expose these, per the brief:
# "services reachable only inside the lab".
services:
  device-insecure:
    ports:
      - "8081:80"
  mqtt-broker-insecure:
    ports:
      - "18830:1883"
```

(Actual service definitions for `device-insecure` / `mqtt-broker-insecure` are added in Task 11; this overlay only adds `ports:` to them and is inert until those services exist.)

- [ ] **Step 3: Validate the compose file config (PC via ssh-mcp)**

Push first:

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/docker-compose.yml lab/docker-compose.dev.yml
git commit -m "feat: add compose network skeleton (audit-network, internal-network)"
git push
```

Then on the PC:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab; docker compose config
```

Expected: prints the resolved compose config (two networks, no services) with no errors.

- [ ] **Step 4: Commit already done in Step 3 (nothing further to commit here)**

---

### Task 4: `smart-camera` config module (TDD)

**Files:**
- Create: `lab/devices/smart-camera/requirements.txt`
- Create: `lab/devices/smart-camera/app/__init__.py`
- Create: `lab/devices/smart-camera/app/config.py`
- Test: `lab/devices/smart-camera/tests/test_config.py`

**Interfaces:**
- Produces: `Settings` (pydantic-settings `BaseSettings` subclass) and a module-level `settings` instance with fields: `device_id, device_vendor, device_model, device_mac, device_type, firmware_version, cred_mode, admin_user, admin_pass, expose_api_key, api_key, require_admin_auth, logging_mode, privacy_doc_path, mqtt_host, mqtt_port, mqtt_tls, mqtt_ca_cert`. Consumed by Task 5's `app/main.py` and Task 6's `app/mqtt_publisher.py`.

- [ ] **Step 1: Write `lab/devices/smart-camera/requirements.txt`**

```
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.13.4
pydantic-settings==2.5.2
python-multipart==0.0.9
paho-mqtt==1.6.1
pytest==8.3.3
httpx==0.27.2
```

> **Errata (2026-07-08):** originally pinned `pydantic==2.9.2`, which depends on `pydantic-core==2.23.4` —
> no prebuilt wheel exists for Python 3.14 on Windows, and building it from source needs a working
> Rust+MSVC toolchain that isn't present in this environment. `pydantic==2.13.4` (paired with
> `pydantic-core==2.46.4`, which does ship a `cp314-win_amd64` wheel) is a drop-in replacement —
> verified compatible with `fastapi==0.115.0` and `pydantic-settings==2.5.2` with no other version
> changes needed. See `docs/errors/002-pydantic-core-no-py314-wheel.md`.

- [ ] **Step 2: Install into a dedicated venv for this component (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
python -m venv .venv
".venv/Scripts/pip" install -r requirements.txt
```

- [ ] **Step 3: Write the failing test first**

Create `lab/devices/smart-camera/tests/test_config.py`:

```python
import os
import importlib


def _fresh_settings(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from app import config as config_module
    importlib.reload(config_module)
    return config_module.Settings()


def test_defaults_match_insecure_profile(monkeypatch):
    monkeypatch.delenv("DEVICE_ID", raising=False)
    settings = _fresh_settings(monkeypatch)
    assert settings.device_id == "device-insecure"
    assert settings.admin_user == "admin"
    assert settings.admin_pass == "admin"
    assert settings.expose_api_key is True


def test_env_overrides_are_respected(monkeypatch):
    settings = _fresh_settings(
        monkeypatch,
        DEVICE_ID="device-hardened",
        ADMIN_PASS="Str0ng-Uniqu3-P@ss",
        EXPOSE_API_KEY="false",
        MQTT_TLS="true",
    )
    assert settings.device_id == "device-hardened"
    assert settings.admin_pass == "Str0ng-Uniqu3-P@ss"
    assert settings.expose_api_key is False
    assert settings.mqtt_tls is True
```

- [ ] **Step 4: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/test_config.py -v
```

Expected: `ModuleNotFoundError: No module named 'app'` (or `app.config`).

- [ ] **Step 5: Write `lab/devices/smart-camera/app/__init__.py` (empty) and `app/config.py`**

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    device_id: str = "device-insecure"
    device_vendor: str = "AcmeCam"
    device_model: str = "AC-100"
    device_mac: str = "AA:BB:CC:00:11:22"
    device_type: str = "smart-camera"
    firmware_version: str = "1.0.0-old"

    cred_mode: str = "default"  # default | strong
    admin_user: str = "admin"
    admin_pass: str = "admin"

    expose_api_key: bool = True
    # Intentional training fixture for the sandboxed insecure device profile —
    # never a real credential; overridden to empty/unused on partial & hardened.
    api_key: str = "sk-insecure-hardcoded-key-000111222"

    require_admin_auth: bool = False

    logging_mode: str = "off"  # off | basic | security

    privacy_doc_path: str = "docs/privacy_insecure.md"

    mqtt_host: str = "mqtt-broker-insecure"
    mqtt_port: int = 1883
    mqtt_tls: bool = False
    mqtt_ca_cert: str = ""

    class Config:
        case_sensitive = False


settings = Settings()
```

- [ ] **Step 6: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/test_config.py -v
```

Expected: 2 passed.

- [ ] **Step 7: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/devices/smart-camera/requirements.txt lab/devices/smart-camera/app lab/devices/smart-camera/tests/test_config.py
git commit -m "feat(smart-camera): add env-driven settings module"
```

---

### Task 5: `smart-camera` FastAPI app (TDD)

**Files:**
- Create: `lab/devices/smart-camera/app/main.py`
- Test: `lab/devices/smart-camera/tests/test_main.py`

**Interfaces:**
- Consumes: `app.config.settings` (Task 4).
- Produces: FastAPI `app` object with routes `GET /`, `POST /login`, `GET /api/device/info`, `GET /api/config`, `POST /api/config`, `GET /api/firmware/version`, `GET /api/admin/reset`, `GET /privacy`, `GET /health`. Consumed by Task 6 (MQTT startup hook), Task 7 (Dockerfile CMD), and manually exercised in Task 11's acceptance check.

- [ ] **Step 1: Write the failing test first**

Create `lab/devices/smart-camera/tests/test_main.py`:

```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_page_loads():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Login" in resp.text


def test_login_success_with_default_creds():
    resp = client.post("/login", data={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_login_fails_with_wrong_creds():
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["device_type"] == "smart-camera"
    assert body["mac"] == "AA:BB:CC:00:11:22"


def test_config_leaks_api_key_when_exposed():
    resp = client.get("/api/config")
    assert resp.status_code == 200
    assert "api_key" in resp.json()


def test_config_post_echoes_payload():
    resp = client.post("/api/config", json={"logging_mode": "basic"})
    assert resp.status_code == 200
    assert resp.json()["received"] == {"logging_mode": "basic"}


def test_firmware_version_endpoint():
    resp = client.get("/api/firmware/version")
    assert resp.status_code == 200
    assert "version" in resp.json()


def test_admin_reset_unauthenticated_allowed_when_not_required():
    resp = client.get("/api/admin/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "reset-triggered"


def test_privacy_endpoint_returns_text_even_if_file_missing():
    resp = client.get("/privacy")
    assert resp.status_code == 200


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/test_main.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.main'`.

- [ ] **Step 3: Write `lab/devices/smart-camera/app/main.py`**

```python
from fastapi import FastAPI, Form, HTTPException, Header
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.config import settings

app = FastAPI(title="Smart Camera Device Simulator")

LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Smart Camera Login</title></head>
<body>
<h1>{vendor} {model} - Login</h1>
<form method="post" action="/login">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def login_page():
    return LOGIN_PAGE_TEMPLATE.format(vendor=settings.device_vendor, model=settings.device_model)


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == settings.admin_user and password == settings.admin_pass:
        return {"status": "ok", "message": "Login successful"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/device/info")
def device_info():
    return {
        "device_id": settings.device_id,
        "vendor": settings.device_vendor,
        "model": settings.device_model,
        "mac": settings.device_mac,
        "device_type": settings.device_type,
        "firmware_version": settings.firmware_version,
    }


@app.get("/api/config")
def get_config():
    config = {
        "cred_mode": settings.cred_mode,
        "mqtt_host": settings.mqtt_host,
        "mqtt_tls": settings.mqtt_tls,
        "logging_mode": settings.logging_mode,
    }
    if settings.expose_api_key:
        # Intentional leak on the insecure profile only (EXPOSE_API_KEY=false elsewhere).
        config["api_key"] = settings.api_key
    return config


@app.post("/api/config")
def update_config(payload: dict):
    return {"status": "accepted", "received": payload}


@app.get("/api/firmware/version")
def firmware_version():
    return {"version": settings.firmware_version}


@app.get("/api/admin/reset")
def admin_reset(authorization: str = Header(default=None)):
    if settings.require_admin_auth:
        expected = f"Bearer {settings.admin_user}:{settings.admin_pass}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="Unauthorized")
    return {"status": "reset-triggered"}


@app.get("/privacy", response_class=PlainTextResponse)
def privacy_doc():
    try:
        with open(settings.privacy_doc_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "No privacy document configured."


@app.get("/health")
def health():
    return {"status": "healthy"}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/test_main.py -v
```

Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/devices/smart-camera/app/main.py lab/devices/smart-camera/tests/test_main.py
git commit -m "feat(smart-camera): add FastAPI endpoints for login/info/config/firmware/admin/privacy"
```

---

### Task 6: `smart-camera` MQTT publisher (TDD) + wiring into app startup

**Files:**
- Create: `lab/devices/smart-camera/app/mqtt_publisher.py`
- Modify: `lab/devices/smart-camera/app/main.py` (add startup hook)
- Test: `lab/devices/smart-camera/tests/test_mqtt_publisher.py`

**Interfaces:**
- Consumes: `app.config.settings`.
- Produces: `build_client(settings) -> paho.mqtt.client.Client` (unconnected, configured client — connection happens in a background thread via `start_mqtt_publisher()`), `start_mqtt_publisher() -> None`.

- [ ] **Step 1: Write the failing test first**

Create `lab/devices/smart-camera/tests/test_mqtt_publisher.py`:

```python
from app.config import Settings
from app.mqtt_publisher import build_client


def test_build_client_uses_device_id_as_client_id():
    settings = Settings(device_id="device-partial")
    client = build_client(settings)
    assert client._client_id.decode() == "device-partial"


def test_build_client_enables_tls_when_configured(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_cert.write_text("dummy")
    settings = Settings(mqtt_tls=True, mqtt_ca_cert=str(ca_cert))
    client = build_client(settings)
    # paho stores the SSL context once tls_set() succeeds
    assert client._ssl_context is not None


def test_build_client_no_tls_by_default():
    settings = Settings(mqtt_tls=False)
    client = build_client(settings)
    assert client._ssl_context is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/test_mqtt_publisher.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.mqtt_publisher'`.

- [ ] **Step 3: Write `lab/devices/smart-camera/app/mqtt_publisher.py`**

```python
import json
import threading
import time

import paho.mqtt.client as mqtt

from app.config import Settings, settings as default_settings


def build_client(settings: Settings) -> mqtt.Client:
    client = mqtt.Client(client_id=settings.device_id)
    if settings.mqtt_tls:
        client.tls_set(ca_certs=settings.mqtt_ca_cert or None)
    return client


def _publish_loop(settings: Settings) -> None:
    client = build_client(settings)
    while True:
        try:
            client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=30)
            client.loop_start()
            break
        except OSError:
            time.sleep(2)

    topic = f"devices/{settings.device_id}/telemetry"
    while True:
        payload = json.dumps({"device_id": settings.device_id, "status": "ok", "ts": time.time()})
        client.publish(topic, payload)
        time.sleep(10)


def start_mqtt_publisher(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_publish_loop, args=(settings,), daemon=True)
    thread.start()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/test_mqtt_publisher.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Wire the publisher into app startup**

Modify `lab/devices/smart-camera/app/main.py` — add near the top (after the `app = FastAPI(...)` line):

```python
from app.mqtt_publisher import start_mqtt_publisher


@app.on_event("startup")
def _on_startup():
    start_mqtt_publisher()
```

- [ ] **Step 6: Re-run the full smart-camera test suite to confirm nothing broke**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project/lab/devices/smart-camera"
".venv/Scripts/pytest" tests/ -v
```

Expected: all 15 tests (2 + 10 + 3) pass. `test_main.py`'s `TestClient(app)` triggers the startup event, spawning the background MQTT thread; since no broker is reachable in the unit-test environment, `_publish_loop` just retries silently in its daemon thread — this doesn't fail the test run because the thread is daemonized and detached.

- [ ] **Step 7: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/devices/smart-camera/app/mqtt_publisher.py lab/devices/smart-camera/app/main.py lab/devices/smart-camera/tests/test_mqtt_publisher.py
git commit -m "feat(smart-camera): add MQTT telemetry publisher and startup hook"
```

---

### Task 7: `smart-camera` Dockerfile, entrypoint, insecure profile env, privacy docs

**Files:**
- Create: `lab/devices/smart-camera/Dockerfile`
- Create: `lab/devices/smart-camera/entrypoint.sh`
- Create: `lab/devices/smart-camera/profiles/insecure.env`
- Create: `lab/devices/smart-camera/docs/privacy_insecure.md`

**Interfaces:**
- Consumes: `app/` package from Tasks 4-6.
- Produces: a buildable Docker image tagged `smart-camera:local`, driven entirely by env vars — consumed by Task 11's compose service definition.

- [ ] **Step 1: Write `lab/devices/smart-camera/entrypoint.sh`**

```bash
#!/bin/sh
set -e

if [ "$TRANSPORT" = "https" ]; then
  exec uvicorn app.main:app --host 0.0.0.0 --port 443 \
    --ssl-keyfile "$TLS_KEYFILE" --ssl-certfile "$TLS_CERTFILE"
else
  exec uvicorn app.main:app --host 0.0.0.0 --port 80
fi
```

- [ ] **Step 2: Write `lab/devices/smart-camera/Dockerfile`**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY docs ./docs
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 80 443

HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD python -c "\
import os, ssl, urllib.request; \
ctx = ssl.create_default_context(); \
ctx.check_hostname = False; \
ctx.verify_mode = ssl.CERT_NONE; \
scheme = 'https' if os.environ.get('TRANSPORT') == 'https' else 'http'; \
port = 443 if scheme == 'https' else 80; \
urllib.request.urlopen(f'{scheme}://localhost:{port}/health', context=ctx if scheme == 'https' else None, timeout=2)"

ENTRYPOINT ["./entrypoint.sh"]
```

- [ ] **Step 3: Write `lab/devices/smart-camera/profiles/insecure.env`**

```dotenv
DEVICE_ID=device-insecure
DEVICE_VENDOR=AcmeCam
DEVICE_MODEL=AC-100
DEVICE_MAC=AA:BB:CC:00:11:22
FIRMWARE_VERSION=1.0.0-old
TRANSPORT=http
TLS_PROFILE=none
CRED_MODE=default
ADMIN_USER=admin
ADMIN_PASS=admin
EXPOSE_API_KEY=true
API_KEY=sk-insecure-hardcoded-key-000111222
REQUIRE_ADMIN_AUTH=false
LOGGING_MODE=off
MQTT_HOST=mqtt-broker-insecure
MQTT_PORT=1883
MQTT_TLS=false
PRIVACY_DOC_PATH=docs/privacy_insecure.md
```

- [ ] **Step 4: Write `lab/devices/smart-camera/docs/privacy_insecure.md`**

```markdown
# Privacy Notice — AcmeCam AC-100 (Insecure Reference Configuration)

This document intentionally **omits** data retention and deletion terms
to model a non-compliant vendor privacy disclosure (CGIoT-1:2024 gap).

- Data collected: video telemetry heartbeat (simulated), device metadata.
- Retention period: **not specified**.
- Deletion process: **not specified**.
- Data sharing: **not specified**.
```

- [ ] **Step 5: Build the image locally to confirm the Dockerfile is valid (PC via ssh-mcp)**

Push, then on the PC:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab\devices\smart-camera; docker build -t smart-camera:local .
```

Expected: `Successfully tagged smart-camera:local` (or Docker's newer "naming to docker.io/library/smart-camera:local" success line).

- [ ] **Step 6: Smoke-test the built image standalone (PC via ssh-mcp)**

```
docker run --rm -d --name smart-camera-smoketest -e TRANSPORT=http -p 18080:80 smart-camera:local; Start-Sleep -Seconds 3; Invoke-WebRequest -UseBasicParsing http://localhost:18080/health; docker logs smart-camera-smoketest; docker rm -f smart-camera-smoketest
```

Expected: the `Invoke-WebRequest` call prints `StatusCode 200` and body `{"status":"healthy"}`.

- [ ] **Step 7: Commit (laptop, after confirming the PC smoke test passed)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/devices/smart-camera/Dockerfile lab/devices/smart-camera/entrypoint.sh lab/devices/smart-camera/profiles/insecure.env lab/devices/smart-camera/docs/privacy_insecure.md
git commit -m "feat(smart-camera): add Dockerfile, entrypoint, insecure profile"
git push
```

---

### Task 8: `telnet-sim` banner listener

**Files:**
- Create: `lab/telnet-sim/banner_server.py`
- Create: `lab/telnet-sim/Dockerfile`

**Interfaces:**
- Produces: a container listening on TCP 23 that sends a login-style banner on connect — enough for `nmap -sV` service detection and manual banner-grab evidence in Task 26. Consumed by Task 11's compose service definition.

- [ ] **Step 1: Write `lab/telnet-sim/banner_server.py`**

```python
import socket

BANNER = b"AcmeCam Telnet Management Console\r\nlogin: "


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 23))
    server.listen(5)
    while True:
        conn, _ = server.accept()
        try:
            conn.sendall(BANNER)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write `lab/telnet-sim/Dockerfile`**

```dockerfile
FROM python:3.12-alpine
WORKDIR /app
COPY banner_server.py .
EXPOSE 23
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD nc -z 127.0.0.1 23 || exit 1
CMD ["python", "banner_server.py"]
```

> **Errata (2026-07-08):** originally used `nc -z localhost 23`. BusyBox `nc` resolves `localhost` and
> tries `::1` (IPv6) first; `banner_server.py` binds only `0.0.0.0` (IPv4), so the healthcheck failed
> even though the server was reachable. Fixed by using `127.0.0.1` directly, skipping DNS resolution
> entirely. See `docs/errors/005-busybox-nc-localhost-ipv6-healthcheck.md`. (Mosquitto's healthchecks
> elsewhere in this plan are unaffected — the broker listens on both IPv4 and IPv6 by default.)

- [ ] **Step 3: Build and smoke-test (PC via ssh-mcp)**

Push, then on the PC:

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab\telnet-sim; docker build -t telnet-sim:local .; docker run --rm -d --name telnet-smoketest -p 2323:23 telnet-sim:local; Start-Sleep -Seconds 2; (New-Object System.Net.Sockets.TcpClient('localhost', 2323)) | Out-Null; docker logs telnet-smoketest; docker rm -f telnet-smoketest
```

Expected: no connection error (a `TcpClient` construction that doesn't throw means the port accepted the connection).

- [ ] **Step 4: Commit (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/telnet-sim
git commit -m "feat: add telnet banner simulator for device-insecure"
git push
```

---

### Task 9: Mosquitto insecure broker config

**Files:**
- Create: `lab/mqtt/insecure/mosquitto.conf`

**Interfaces:**
- Produces: a plaintext, anonymous-access Mosquitto config on port 1883. Consumed by Task 11's compose service definition (using the stock `eclipse-mosquitto:2` image with this file mounted).

- [ ] **Step 1: Write `lab/mqtt/insecure/mosquitto.conf`**

```
listener 1883
allow_anonymous true
persistence false
log_dest stdout
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/mqtt/insecure/mosquitto.conf
git commit -m "feat: add insecure (plaintext, anonymous) MQTT broker config"
```

(Verified end-to-end once wired into compose in Task 11.)

---

### Task 10: `.gitignore` entry for lab-generated artifacts

**Files:**
- Modify: `.gitignore`

**Interfaces:** none (housekeeping).

- [ ] **Step 1: Append generated-artifact ignores**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
cat >> .gitignore <<'EOF'

# Lab-generated artifacts (regenerable, keep repo lean)
lab/certs/*.key
lab/certs/*.crt
lab/certs/*.csr
lab/certs/*.srl
lab/mqtt/secure/passwd
auditor/worker/firmware/output/
EOF
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore generated certs, mqtt passwd file, firmware build output"
```

---

### Task 11: Wire `device-insecure` + `telnet-sim` + `mqtt-broker-insecure` into compose; Day-1 acceptance check

**Files:**
- Modify: `lab/docker-compose.yml` (add three services under the existing `services:` key, replacing the `services: {}` placeholder)

**Interfaces:**
- Consumes: images from Tasks 7-9.
- Produces: a running lab reachable per Day-1 acceptance criteria. Consumed by Task 12+ (profiles/TLS extend this same file) and Task 22 (auditor-worker joins this network).

- [ ] **Step 1: Replace the `services: {}` placeholder in `lab/docker-compose.yml`**

```yaml
services:
  device-insecure:
    build: ./devices/smart-camera
    env_file: ./devices/smart-camera/profiles/insecure.env
    networks:
      - audit-network
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost/health', timeout=2)"]
      interval: 10s
      timeout: 3s
      retries: 3

  telnet-sim:
    build: ./telnet-sim
    networks:
      - audit-network
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "23"]
      interval: 10s
      timeout: 3s
      retries: 3

  mqtt-broker-insecure:
    image: eclipse-mosquitto:2
    volumes:
      - ./mqtt/insecure/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
    networks:
      - audit-network
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 1883 || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3
```

- [ ] **Step 2: Push, pull, bring the lab up (PC via ssh-mcp)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/docker-compose.yml
git commit -m "feat: wire device-insecure, telnet-sim, mqtt-broker-insecure into compose"
git push
```

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab; docker compose up -d --build
```

Expected: three containers created and started.

- [ ] **Step 3: Verify health (PC via ssh-mcp)**

```
docker compose ps
```

Expected: all three services show `healthy` within ~30 seconds (poll with `docker compose ps` again if `starting`).

- [ ] **Step 4: Day-1 acceptance — reach the web UI, connect to MQTT, port-scan, view metadata, all from inside the lab network (PC via ssh-mcp)**

Use a throwaway `nicolaka/netshoot` container attached to `audit-network` (this stands in for the not-yet-built `auditor-worker`, which is built properly in Task 22):

```
docker run --rm --network kaust-iot-lab_audit-network nicolaka/netshoot sh -c "curl -s http://device-insecure/ | head -5; echo '---'; curl -s http://device-insecure/api/device/info; echo '---'; nmap -sV -p 22,23,80,443,1883 device-insecure telnet-sim mqtt-broker-insecure; echo '---'; timeout 2 mosquitto_sub -h mqtt-broker-insecure -t 'devices/#' -C 1"
```

Expected:
- The `curl http://device-insecure/` output contains `Login`.
- `curl .../api/device/info` returns the device JSON with `"device_type":"smart-camera"`.
- `nmap` reports port 80 open on `device-insecure`, port 23 open on `telnet-sim`, port 1883 open on `mqtt-broker-insecure` — **≥3 open ports detected**, satisfying Day-1 acceptance.
- `mosquitto_sub` receives at least one telemetry message within a couple of publish cycles (device publishes every 10s) — confirms MQTT connectivity.

- [ ] **Step 5: Confirm host isolation (devices are NOT reachable from the host)**

```
Test-NetConnection -ComputerName localhost -Port 80 -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded
```

Expected: `False` — `device-insecure` port 80 is not published to the host, matching the brief ("reachable only inside the lab").

- [ ] **Step 6: Tear down and commit is already done in Step 2; just stop the stack for now to free PC resources**

```
docker compose down
```

---

### Task 12: Certificate generation (containerized, no host OpenSSL)

**Files:**
- Create: `lab/certs/Dockerfile`
- Create: `lab/certs/generate.sh`

**Interfaces:**
- Produces (at runtime, into a mounted volume, not committed): `ca.crt`, `ca.key`, `weak.key`/`weak.crt` (device-partial), `strong.key`/`strong.crt` (device-hardened), `mqtt-server.key`/`mqtt-server.crt` (secure broker). Consumed by Tasks 14, 15, 16.

- [ ] **Step 1: Write `lab/certs/generate.sh`**

```sh
#!/bin/sh
set -e
OUT=/out
mkdir -p "$OUT"

# CA
openssl genrsa -out "$OUT/ca.key" 4096
openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 \
  -subj "/CN=KAUST-IoT-Lab-CA" -out "$OUT/ca.crt"

# Weak cert for device-partial: 1024-bit RSA + SHA-1 signature (intentionally weak, lab-only)
openssl genrsa -out "$OUT/weak.key" 1024
openssl req -new -key "$OUT/weak.key" -subj "/CN=device-partial" -out "$OUT/weak.csr"
openssl x509 -req -in "$OUT/weak.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -sha1 -out "$OUT/weak.crt"

# Strong cert for device-hardened: 2048-bit RSA + SHA-256
openssl genrsa -out "$OUT/strong.key" 2048
openssl req -new -key "$OUT/strong.key" -subj "/CN=device-hardened" -out "$OUT/strong.csr"
openssl x509 -req -in "$OUT/strong.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -sha256 -out "$OUT/strong.crt"

# Secure MQTT broker cert: 2048-bit RSA + SHA-256
openssl genrsa -out "$OUT/mqtt-server.key" 2048
openssl req -new -key "$OUT/mqtt-server.key" -subj "/CN=mqtt-broker-secure" -out "$OUT/mqtt-server.csr"
openssl x509 -req -in "$OUT/mqtt-server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 365 -sha256 -out "$OUT/mqtt-server.crt"

rm -f "$OUT"/*.csr "$OUT"/*.srl
echo "Certificates generated in $OUT"
```

- [ ] **Step 2: Write `lab/certs/Dockerfile`**

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache openssl
WORKDIR /certs
COPY generate.sh .
RUN chmod +x generate.sh
ENTRYPOINT ["./generate.sh"]
```

- [ ] **Step 3: Add a one-shot `cert-init` service to `lab/docker-compose.yml`** (append under `services:`)

```yaml
  cert-init:
    build: ./certs
    volumes:
      - ./certs:/out
    profiles: ["init"]
```

- [ ] **Step 4: Push, pull, run the one-shot cert generator (PC via ssh-mcp)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/certs lab/docker-compose.yml
git commit -m "feat: add containerized cert-init service (CA + weak + strong + mqtt certs)"
git push
```

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab; docker compose --profile init run --rm cert-init
```

Expected: `Certificates generated in /out`; then confirm files landed:

```
Get-ChildItem certs
```

Expected: lists `ca.crt`, `ca.key`, `weak.key`, `weak.crt`, `strong.key`, `strong.crt`, `mqtt-server.key`, `mqtt-server.crt`.

- [ ] **Step 5: Verify weak cert is actually weak, strong cert is actually strong (PC via ssh-mcp)**

```
docker run --rm -v "${PWD}/certs:/certs" alpine/openssl x509 -in /certs/weak.crt -noout -text | Select-String "Public-Key|Signature Algorithm"
docker run --rm -v "${PWD}/certs:/certs" alpine/openssl x509 -in /certs/strong.crt -noout -text | Select-String "Public-Key|Signature Algorithm"
```

Expected: weak cert shows `Public-Key: (1024 bit)` and `sha1WithRSAEncryption`; strong cert shows `Public-Key: (2048 bit)` and `sha256WithRSAEncryption`.

(No separate commit needed here — generated cert files are gitignored per Task 10; only the scripts are tracked.)

---

### Task 13: Mosquitto secure broker config + password file

**Files:**
- Create: `lab/mqtt/secure/mosquitto.conf`

**Interfaces:**
- Produces: a TLS + authenticated Mosquitto config on port 8883. Consumes cert files from Task 12 (mounted at runtime). Consumed by Task 16's compose service.

- [ ] **Step 1: Write `lab/mqtt/secure/mosquitto.conf`**

```
listener 8883
allow_anonymous false
password_file /mosquitto/config/passwd
cafile /mosquitto/certs/ca.crt
certfile /mosquitto/certs/mqtt-server.crt
keyfile /mosquitto/certs/mqtt-server.key
require_certificate false
persistence false
log_dest stdout
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/mqtt/secure/mosquitto.conf
git commit -m "feat: add secure (TLS, authenticated) MQTT broker config"
```

(Password file generation happens in Task 16, right before the broker first starts, since it needs the running Mosquitto image's `mosquitto_passwd` helper.)

---

### Task 14: `device-partial` profile (env + docs)

**Files:**
- Create: `lab/devices/smart-camera/profiles/partial.env`
- Create: `lab/devices/smart-camera/docs/privacy_partial.md`

**Interfaces:** none new — reuses the Task 5-7 image with a different env file.

- [ ] **Step 1: Write `lab/devices/smart-camera/profiles/partial.env`**

```dotenv
DEVICE_ID=device-partial
DEVICE_VENDOR=AcmeCam
DEVICE_MODEL=AC-200
DEVICE_MAC=AA:BB:CC:00:11:33
FIRMWARE_VERSION=1.5.0-mid
TRANSPORT=https
TLS_PROFILE=weak
TLS_KEYFILE=/certs/weak.key
TLS_CERTFILE=/certs/weak.crt
CRED_MODE=strong
ADMIN_USER=admin
ADMIN_PASS=Ch4ng3d-Bu7-W3ak
EXPOSE_API_KEY=false
API_KEY=
REQUIRE_ADMIN_AUTH=false
LOGGING_MODE=basic
MQTT_HOST=mqtt-broker-insecure
MQTT_PORT=1883
MQTT_TLS=false
PRIVACY_DOC_PATH=docs/privacy_partial.md
```

- [ ] **Step 2: Write `lab/devices/smart-camera/docs/privacy_partial.md`**

```markdown
# Privacy Notice — AcmeCam AC-200 (Partially Hardened Reference Configuration)

- Data collected: video telemetry heartbeat (simulated), device metadata.
- Retention period: 90 days (undocumented deletion mechanics).
- Deletion process: **incomplete** — no user-triggered deletion path documented.
- Data sharing: not shared with third parties.
```

- [ ] **Step 3: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/devices/smart-camera/profiles/partial.env lab/devices/smart-camera/docs/privacy_partial.md
git commit -m "feat(smart-camera): add device-partial profile (weak TLS, changed-but-weak creds)"
```

---

### Task 15: `device-hardened` profile (env + docs)

**Files:**
- Create: `lab/devices/smart-camera/profiles/hardened.env`
- Create: `lab/devices/smart-camera/docs/privacy_hardened.md`

**Interfaces:** none new.

- [ ] **Step 1: Write `lab/devices/smart-camera/profiles/hardened.env`**

```dotenv
DEVICE_ID=device-hardened
DEVICE_VENDOR=AcmeCam
DEVICE_MODEL=AC-300
DEVICE_MAC=AA:BB:CC:00:11:44
FIRMWARE_VERSION=2.0.0-current
TRANSPORT=https
TLS_PROFILE=strong
TLS_KEYFILE=/certs/strong.key
TLS_CERTFILE=/certs/strong.crt
CRED_MODE=strong
ADMIN_USER=admin
ADMIN_PASS=Un1qu3-P3r-D3v1c3-9f2a
EXPOSE_API_KEY=false
API_KEY=
REQUIRE_ADMIN_AUTH=true
LOGGING_MODE=security
MQTT_HOST=mqtt-broker-secure
MQTT_PORT=8883
MQTT_TLS=true
MQTT_CA_CERT=/certs/ca.crt
PRIVACY_DOC_PATH=docs/privacy_hardened.md
```

- [ ] **Step 2: Write `lab/devices/smart-camera/docs/privacy_hardened.md`**

```markdown
# Privacy Notice — AcmeCam AC-300 (Hardened Reference Configuration)

- Data collected: video telemetry heartbeat (simulated), device metadata.
- Retention period: 30 days, automatically purged.
- Deletion process: user can request deletion via `/api/admin/reset` (authenticated); confirmed by
  audit log entry (security logging enabled).
- Data sharing: not shared with third parties.
```

- [ ] **Step 3: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/devices/smart-camera/profiles/hardened.env lab/devices/smart-camera/docs/privacy_hardened.md
git commit -m "feat(smart-camera): add device-hardened profile (strong TLS, unique creds, signed-only posture)"
```

---

### Task 16: Wire `device-partial`, `device-hardened`, `mqtt-broker-secure` into compose; verify all three profiles

**Files:**
- Modify: `lab/docker-compose.yml` (append three services)

**Interfaces:**
- Consumes: Tasks 12-15.
- Produces: the full 6-device-profile lab (3 cameras + 2 brokers + telnet-sim) needed by Phase 3's diagrams and Phase 4's manual assessment.

- [ ] **Step 1: Append to `lab/docker-compose.yml` under `services:`**

```yaml
  device-partial:
    build: ./devices/smart-camera
    env_file: ./devices/smart-camera/profiles/partial.env
    volumes:
      - ./certs:/certs:ro
    networks:
      - audit-network
    healthcheck:
      test: ["CMD", "python", "-c", "import ssl, urllib.request; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; urllib.request.urlopen('https://localhost/health', context=ctx, timeout=2)"]
      interval: 10s
      timeout: 3s
      retries: 3

  device-hardened:
    build: ./devices/smart-camera
    env_file: ./devices/smart-camera/profiles/hardened.env
    volumes:
      - ./certs:/certs:ro
    networks:
      - audit-network
    healthcheck:
      test: ["CMD", "python", "-c", "import ssl, urllib.request; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; urllib.request.urlopen('https://localhost/health', context=ctx, timeout=2)"]
      interval: 10s
      timeout: 3s
      retries: 3

  mqtt-broker-secure:
    image: eclipse-mosquitto:2
    volumes:
      - ./mqtt/secure/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - ./certs:/mosquitto/certs:ro
      - mqtt-secure-passwd:/mosquitto/config
    networks:
      - audit-network
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 8883 || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3

volumes:
  mqtt-secure-passwd:
```

Note: the password file lives on a named volume (`mqtt-secure-passwd`) rather than a bind mount so Task 2's generation step can write into it via a one-shot container without needing the file to pre-exist on the host.

- [ ] **Step 2: Push, pull, generate the MQTT password file, bring the full lab up (PC via ssh-mcp)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/docker-compose.yml
git commit -m "feat: wire device-partial, device-hardened, mqtt-broker-secure into compose"
git push
```

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab
docker compose --profile init run --rm cert-init
docker run --rm -v kaust-iot-lab_mqtt-secure-passwd:/mosquitto/config eclipse-mosquitto:2 mosquitto_passwd -c -b /mosquitto/config/passwd labworker "LabWork3r-Secr3t!"
docker compose up -d --build
docker compose ps
```

Expected: all six services (`device-insecure`, `device-partial`, `device-hardened`, `telnet-sim`, `mqtt-broker-insecure`, `mqtt-broker-secure`) show `healthy`.

- [ ] **Step 3: Verify each device profile matches its intended posture (PC via ssh-mcp)**

```
docker run --rm --network kaust-iot-lab_audit-network nicolaka/netshoot sh -c "\
echo '--- insecure ---'; curl -s http://device-insecure/api/config; \
echo '--- partial (weak TLS, no api_key) ---'; curl -sk https://device-partial/api/config; \
echo '--- hardened (strong TLS, no api_key, admin/reset requires auth) ---'; curl -sk https://device-hardened/api/config; curl -sk -o /dev/null -w '%{http_code}\n' https://device-hardened/api/admin/reset; \
echo '--- secure MQTT rejects anonymous ---'; timeout 2 mosquitto_pub -h mqtt-broker-secure -p 8883 --cafile /dev/null -t test -m x 2>&1 | head -3"
```

Expected: insecure `/api/config` includes `api_key`; partial/hardened do not; hardened `/api/admin/reset` returns `401` (no `Authorization` header sent); the anonymous MQTT publish to the secure broker fails (auth/TLS error), confirming `allow_anonymous false` + TLS are enforced.

- [ ] **Step 4: Tear down to free PC resources until Phase 3/4 work resumes**

```
docker compose down
```

(Commit already done in Step 2.)

---

### Task 17: Architecture Mermaid diagram (Day-1 artifact)

**Files:**
- Create: `docs/architecture/architecture-diagram.md`

- [ ] **Step 1: Write the diagram**

```markdown
# Lab Architecture — Phases 0-5

​```mermaid
flowchart TB
    subgraph HOST["HOST (32GB PC) — only auditor-web published"]
    end

    subgraph INTERNAL["internal-network 172.31.0.0/24 (TRUSTED, internal: true)"]
        WORKER[auditor-worker<br/>dual-homed bridge]
    end

    subgraph AUDIT["audit-network 172.30.0.0/24 (UNTRUSTED simulated IoT LAN)"]
        DI[device-insecure<br/>HTTP:80]
        DP[device-partial<br/>HTTPS weak:443]
        DH[device-hardened<br/>HTTPS strong:443]
        TS[telnet-sim<br/>TCP:23]
        MI[mqtt-broker-insecure<br/>1883 plaintext]
        MS[mqtt-broker-secure<br/>8883 TLS]
    end

    WORKER -->|pulls evidence| DI
    WORKER -->|pulls evidence| DP
    WORKER -->|pulls evidence| DH
    WORKER -->|pulls evidence| TS
    WORKER -->|pulls evidence| MI
    WORKER -->|pulls evidence| MS
    DI -->|plaintext telemetry| MI
    DP -->|plaintext telemetry| MI
    DH -->|TLS telemetry| MS
​```

## Containers (Phases 0-5 scope)

| Container | Network(s) | Port | Host-exposed? |
|---|---|---|---|
| device-insecure | audit-network | 80 (HTTP) | no |
| device-partial | audit-network | 443 (weak TLS) | no |
| device-hardened | audit-network | 443 (strong TLS) | no |
| telnet-sim | audit-network | 23 | no |
| mqtt-broker-insecure | audit-network | 1883 | no |
| mqtt-broker-secure | audit-network | 8883 | no |
| auditor-worker | audit-network + internal-network | n/a (toolbox) | no |

`auditor-api`/`auditor-database`/`document-store`(as a service)/`auditor-web` are added in the
Phase 6-8 follow-up plan; `document-store` is a plain filesystem directory for Phases 0-5.
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add docs/architecture/architecture-diagram.md
git commit -m "docs: add Phase 0-5 architecture diagram"
```

---

### Task 18: Trust-boundary Mermaid diagram (Day-1 artifact)

**Files:**
- Create: `docs/architecture/trust-boundary-diagram.md`

- [ ] **Step 1: Write the diagram**

```markdown
# Trust Boundaries — Phases 0-5

​```mermaid
flowchart LR
    subgraph Untrusted["UNTRUSTED: audit-network"]
        D[3 device profiles + telnet-sim + 2 MQTT brokers]
    end
    subgraph Bridge["ONE-WAY BRIDGE"]
        W[auditor-worker<br/>the only dual-homed container]
    end
    subgraph Trusted["TRUSTED: internal-network (internal: true, no default route)"]
        S[document-store<br/>filesystem, Phases 0-5]
    end

    D -.->|worker PULLS evidence, never pushed inbound| W
    W -->|worker WRITES evidence.json / verdict.json| S
    S -.->|devices have NO route here| D
​```

## Rules enforced

1. Devices cannot reach `internal-network` at all — it is a Docker `internal: true` network with no
   gateway to anything devices are attached to.
2. `auditor-worker` never accepts inbound connections from devices; it only initiates outbound
   probes (nmap/curl/mosquitto_sub/openssl) against them.
3. Only `auditor-worker`'s own filesystem writes reach `document-store` — devices cannot write
   evidence, only be evidence *about*.
4. No device port is published to the PC host — the only host-facing service in the full platform
   (Phase 6-8) is `auditor-web`.
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add docs/architecture/trust-boundary-diagram.md
git commit -m "docs: add trust-boundary diagram"
```

---

### Task 19: STRIDE threat model (Day-1 artifact)

**Files:**
- Create: `docs/architecture/threat-model-stride.md`

- [ ] **Step 1: Write the doc** (transcribing spec §8, tied to what's actually built in Phases 0-5)

```markdown
# STRIDE Threat Model — Smart Camera Devices

| STRIDE | Threat (against the device) | Demonstrated by | Mitigation on device-hardened |
|---|---|---|---|
| Spoofing | Anonymous MQTT publish; admin/admin login | `mqtt-broker-insecure` (allow_anonymous true), device-insecure default creds | `mqtt-broker-secure` requires TLS + password auth; unique strong admin credential |
| Tampering | Plaintext MITM on HTTP/MQTT; unsigned firmware accepted by update.sh | device-insecure HTTP transport, insecure firmware's `update.sh` (no checksum) | HTTPS-only strong TLS; `update.sh` verifies an OpenSSL signature before applying |
| Repudiation | Missing/weak logging of admin actions | device-insecure `LOGGING_MODE=off` | device-hardened `LOGGING_MODE=security` |
| Information Disclosure | Hard-coded API key/private key; `/api/config` leak; Telnet plaintext banner | `TEST-FW-SECRETS` YARA findings, device-insecure `/api/config` response, telnet-sim banner | No secrets baked into hardened firmware; API key never exposed (`EXPOSE_API_KEY=false`); Telnet removed entirely |
| Denial of Service | Unnecessary open services (Telnet) increase attack surface | `telnet-sim` reachable from device-insecure's network segment | Telnet container simply isn't part of the hardened device's exposed surface (services minimized) |
| Elevation of Privilege | Unauthenticated admin endpoint | `TEST-ADMIN-UNAUTH` — device-insecure's `/api/admin/reset` requires no auth | device-hardened sets `REQUIRE_ADMIN_AUTH=true`, enforced in `app/main.py`'s `admin_reset()` |

The platform's own defense against a compromised device is the trust-boundary design in
`trust-boundary-diagram.md`: even a fully compromised `device-insecure` cannot reach
`internal-network` or write to `document-store` directly — only `auditor-worker` can.
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add docs/architecture/threat-model-stride.md
git commit -m "docs: add STRIDE threat model"
```

---

### Task 20: Device inventory (Day-1 artifact)

**Files:**
- Create: `docs/architecture/device-inventory.md`

- [ ] **Step 1: Write the inventory, derived from the three profile `.env` files**

```markdown
# Device Inventory

| device_id | vendor | model | mac | firmware | transport | mqtt target |
|---|---|---|---|---|---|---|
| device-insecure | AcmeCam | AC-100 | AA:BB:CC:00:11:22 | 1.0.0-old | HTTP | mqtt-broker-insecure (plaintext) |
| device-partial | AcmeCam | AC-200 | AA:BB:CC:00:11:33 | 1.5.0-mid | HTTPS (weak cert) | mqtt-broker-insecure (plaintext) |
| device-hardened | AcmeCam | AC-300 | AA:BB:CC:00:11:44 | 2.0.0-current | HTTPS (strong cert) | mqtt-broker-secure (TLS) |

Source of truth: `lab/devices/smart-camera/profiles/{insecure,partial,hardened}.env`.
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add docs/architecture/device-inventory.md
git commit -m "docs: add device inventory"
```

---

### Task 21: Lab README (Day-1 output)

**Files:**
- Create: `lab/README.md`

- [ ] **Step 1: Write the README**

```markdown
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
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` if you want `device-insecure`
  and `mqtt-broker-insecure` exposed to `localhost` for manual poking around.
- To probe the lab from the audit network without a published port, run a throwaway container
  attached to it, e.g.:
  `docker run --rm --network kaust-iot-lab_audit-network nicolaka/netshoot nmap -sV device-insecure`
- All "insecure" behavior (default creds, hardcoded API key, plaintext MQTT, unsigned firmware) is
  an intentional training fixture inside this sandboxed, non-internet-facing lab.
```

- [ ] **Step 2: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/README.md
git commit -m "docs: add lab start/stop README"
```

---

### Task 22: `auditor-worker` toolbox image, dual-homed compose service

**Files:**
- Create: `lab/auditor/worker/Dockerfile`
- Create: `lab/auditor/worker/requirements.txt`
- Modify: `lab/docker-compose.yml` (append `auditor-worker` service, attach to both networks)

**Interfaces:**
- Produces: a long-running container with `nmap`, `openssl`, `mosquitto-clients`, `yara`, `syft`, `grype`, plus this repo's `policies/` and `auditor/worker/` Python code mounted in, on both networks — the execution environment for Task 23-27's manual test catalog.

- [ ] **Step 1: Write `lab/auditor/worker/requirements.txt`**

```
pyyaml==6.0.2
jsonschema==4.23.0
yara-python==4.5.1
```

- [ ] **Step 2: Write `lab/auditor/worker/Dockerfile`**

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    openssl \
    mosquitto-clients \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Syft + Grype (SBOM + vuln scan) — official install scripts, pinned versions
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v1.14.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.82.0

WORKDIR /work
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["sleep", "infinity"]
```

- [ ] **Step 3: Append the `auditor-worker` service to `lab/docker-compose.yml`**

```yaml
  auditor-worker:
    build: ./auditor/worker
    volumes:
      - ../policies:/work/policies:ro
      - ./auditor/worker:/work/auditor/worker
      - ../document-store:/work/document-store
    networks:
      - audit-network
      - internal-network
```

Note the relative paths: `../policies` and `../document-store` climb out of `lab/` to the repo root, matching the top-level layout from the File Structure section.

- [ ] **Step 4: Push, pull, build, verify dual-homed connectivity (PC via ssh-mcp)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/auditor/worker/Dockerfile lab/auditor/worker/requirements.txt lab/docker-compose.yml
git commit -m "feat: add auditor-worker toolbox image, dual-homed on both networks"
git push
```

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab; docker compose up -d --build
docker compose exec auditor-worker sh -c "nmap --version | head -1; openssl version; python --version; ls /work/policies; ls /work/document-store"
```

Expected: version strings print for each tool; `/work/policies` lists `schema/ engine/ controls/`; `/work/document-store` lists `evidence/ raw/ verdicts/ firmware/`.

- [ ] **Step 5: Confirm the worker can reach both a device (audit-network) and would be able to reach a future backend (internal-network) — internal-network has no other member yet, so just confirm the interface exists**

```
docker compose exec auditor-worker sh -c "curl -s http://device-insecure/api/device/info; echo; ip addr show | grep -A2 eth1"
```

Expected: device info JSON prints; a second network interface (`eth1` or similar, on the 172.31.0.0/24 range) is listed.

---

### Task 23: Evidence recorder CLI (TDD)

**Files:**
- Create: `lab/auditor/worker/tests/record_evidence.py`
- Test: `lab/auditor/worker/tests/test_record_evidence.py`

**Interfaces:**
- Consumes: `policies.schema.validate.validate_evidence` (Task 2).
- Produces: `record_evidence(device_id, test_id, tool, tool_version, command, finding, raw_file, confidence, observations, document_store=DOCUMENT_STORE) -> dict`, and a `main()` CLI entry point. Used manually for every evidence entry in Task 26.

- [ ] **Step 1: Write the failing test first**

Create `lab/auditor/worker/tests/test_record_evidence.py`:

```python
import json
from pathlib import Path

from auditor.worker.tests.record_evidence import record_evidence


def test_record_evidence_writes_valid_json(tmp_path):
    raw_file = tmp_path / "raw_nmap_output.txt"
    raw_file.write_text("23/tcp open telnet\n80/tcp open http\n1883/tcp open mqtt\n")

    record = record_evidence(
        device_id="device-insecure",
        test_id="TEST-NET-PORTSCAN",
        tool="nmap",
        tool_version="7.94",
        command="nmap -sV -p- device-insecure",
        finding="Telnet (23/tcp) open; plaintext management exposed",
        raw_file=str(raw_file),
        confidence="high",
        observations={"open_ports": [23, 80, 1883], "telnet_open": True},
        document_store=tmp_path / "document-store",
    )

    assert record["evidence_id"].startswith("EV-")
    assert record["device_id"] == "device-insecure"
    assert len(record["sha256"]) == 64

    out_file = tmp_path / "document-store" / "evidence" / f"{record['evidence_id']}.json"
    assert out_file.exists()
    saved = json.loads(out_file.read_text())
    assert saved == record


def test_record_evidence_copies_raw_output(tmp_path):
    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("raw tool output")

    record = record_evidence(
        device_id="device-insecure",
        test_id="TEST-HTTP-HEADERS",
        tool="curl",
        tool_version="8.9.1",
        command="curl -I http://device-insecure/",
        finding="Missing security headers",
        raw_file=str(raw_file),
        confidence="high",
        observations={"missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]},
        document_store=tmp_path / "document-store",
    )

    copied = tmp_path / "document-store" / "raw" / f"{record['evidence_id']}.txt"
    assert copied.read_text() == "raw tool output"


def test_sequence_increments_within_same_day(tmp_path):
    raw_file = tmp_path / "raw.txt"
    raw_file.write_text("x")
    store = tmp_path / "document-store"

    first = record_evidence(
        device_id="d1", test_id="T1", tool="t", tool_version="1", command="c",
        finding="f", raw_file=str(raw_file), confidence="high", observations={},
        document_store=store,
    )
    second = record_evidence(
        device_id="d1", test_id="T2", tool="t", tool_version="1", command="c",
        finding="f", raw_file=str(raw_file), confidence="high", observations={},
        document_store=store,
    )
    assert first["evidence_id"] != second["evidence_id"]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" lab/auditor/worker/tests/test_record_evidence.py -v
```

Expected: `ModuleNotFoundError`. Create the needed `__init__.py` package markers so the import path resolves:

```bash
touch lab/__init__.py lab/auditor/__init__.py lab/auditor/worker/__init__.py lab/auditor/worker/tests/__init__.py
```

- [ ] **Step 3: Write `lab/auditor/worker/tests/record_evidence.py`**

```python
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from policies.schema.validate import validate_evidence

DOCUMENT_STORE = Path(__file__).resolve().parents[3] / "document-store"


def _next_sequence(evidence_dir: Path, date_str: str) -> int:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    existing = list(evidence_dir.glob(f"EV-{date_str}-*.json"))
    return len(existing) + 1


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def record_evidence(
    device_id: str,
    test_id: str,
    tool: str,
    tool_version: str,
    command: str,
    finding: str,
    raw_file: str,
    confidence: str,
    observations: dict,
    document_store: Path = DOCUMENT_STORE,
) -> dict:
    evidence_dir = document_store / "evidence"
    raw_dir = document_store / "raw"

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    seq = _next_sequence(evidence_dir, date_str)
    evidence_id = f"EV-{date_str}-{seq:04d}"

    raw_path = Path(raw_file)
    sha256 = _sha256_file(raw_path)

    raw_dir.mkdir(parents=True, exist_ok=True)
    stored_raw_path = raw_dir / f"{evidence_id}.txt"
    stored_raw_path.write_bytes(raw_path.read_bytes())

    record = {
        "evidence_id": evidence_id,
        "device_id": device_id,
        "test_id": test_id,
        "tool": tool,
        "tool_version": tool_version,
        "command": command,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finding": finding,
        "observations": observations,
        "raw_output_path": f"document-store/raw/{evidence_id}.txt",
        "confidence": confidence,
        "sha256": sha256,
    }
    validate_evidence(record)

    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / f"{evidence_id}.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Record a manual evidence entry")
    parser.add_argument("--device", required=True)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--raw-file", required=True)
    parser.add_argument("--confidence", required=True, choices=["high", "medium", "low"])
    parser.add_argument("--observations", required=True, help="JSON string")
    args = parser.parse_args()

    record = record_evidence(
        device_id=args.device,
        test_id=args.test_id,
        tool=args.tool,
        tool_version=args.tool_version,
        command=args.command,
        finding=args.finding,
        raw_file=args.raw_file,
        confidence=args.confidence,
        observations=json.loads(args.observations),
    )
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" lab/auditor/worker/tests/test_record_evidence.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add lab/__init__.py lab/auditor lab/auditor/worker/tests/record_evidence.py lab/auditor/worker/tests/test_record_evidence.py
git commit -m "feat(worker): add evidence recorder CLI with schema validation"
```

---

### Task 24: Firmware generator (TDD, deterministic/reproducible)

**Files:**
- Create: `lab/auditor/worker/firmware/generate_firmware.py`
- Test: `lab/auditor/worker/firmware/test_generate_firmware.py`

**Interfaces:**
- Produces: `build_variant(device_id: str, signing_key: Path | None = None, output_dir: Path = OUTPUT_DIR) -> Path`, `sha256_of(path: Path) -> str`. Consumed by Task 25's YARA scan and Task 26's manual firmware-analysis evidence entries.

- [ ] **Step 1: Write the failing test first**

Create `lab/auditor/worker/firmware/test_generate_firmware.py`:

```python
import tarfile

from auditor.worker.firmware.generate_firmware import build_variant, sha256_of


def test_firmware_build_is_byte_reproducible(tmp_path):
    path1 = build_variant("device-insecure", output_dir=tmp_path)
    hash1 = sha256_of(path1)
    path2 = build_variant("device-insecure", output_dir=tmp_path)
    hash2 = sha256_of(path2)
    assert hash1 == hash2


def test_insecure_firmware_contains_hardcoded_password(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    with tarfile.open(path, "r:gz") as tar:
        content = tar.extractfile("etc/config.ini").read().decode()
    assert "admin_pass=admin" in content


def test_hardened_firmware_has_no_hardcoded_password(tmp_path):
    path = build_variant("device-hardened", output_dir=tmp_path)
    with tarfile.open(path, "r:gz") as tar:
        content = tar.extractfile("etc/config.ini").read().decode()
    assert "admin_pass=admin" not in content
    assert "admin_pass=Ch4ng3d-Bu7-W3ak" not in content


def test_all_three_variants_have_distinct_manifests(tmp_path):
    packages_by_variant = {}
    for device_id in ("device-insecure", "device-partial", "device-hardened"):
        path = build_variant(device_id, output_dir=tmp_path)
        with tarfile.open(path, "r:gz") as tar:
            import json
            manifest = json.loads(tar.extractfile("manifest.json").read())
        packages_by_variant[device_id] = manifest["packages"]
    assert packages_by_variant["device-insecure"] != packages_by_variant["device-hardened"]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
touch lab/auditor/worker/firmware/__init__.py
".venv/Scripts/pytest" lab/auditor/worker/firmware/test_generate_firmware.py -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Write `lab/auditor/worker/firmware/generate_firmware.py`**

```python
import gzip
import io
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Optional

OUTPUT_DIR = Path(__file__).resolve().parent / "output"

VARIANTS = {
    "device-insecure": {
        "version": "1.0.0-old",
        # Intentional training fixture (sandboxed lab, never a live credential).
        "config_ini": (
            "[device]\n"
            "admin_user=admin\n"
            "admin_pass=admin\n"
            "api_key=sk-insecure-hardcoded-key-000111222\n"
        ),
        "manifest": {"packages": [
            {"name": "openssl", "version": "1.0.1e"},
            {"name": "busybox", "version": "1.19.4"},
        ]},
        "update_script": (
            "#!/bin/sh\n"
            "curl -o /tmp/fw.bin http://updates.example.local/latest.bin\n"
            "cp /tmp/fw.bin /firmware/current.bin\n"
        ),
        "signed": False,
    },
    "device-partial": {
        "version": "1.5.0-mid",
        "config_ini": (
            "[device]\n"
            "admin_user=admin\n"
            "admin_pass=Ch4ng3d-Bu7-W3ak\n"
        ),
        "manifest": {"packages": [
            {"name": "openssl", "version": "1.1.1k"},
            {"name": "busybox", "version": "1.34.1"},
        ]},
        "update_script": (
            "#!/bin/sh\n"
            "curl -o /tmp/fw.bin https://updates.example.local/latest.bin\n"
            "cp /tmp/fw.bin /firmware/current.bin\n"
        ),
        "signed": False,
    },
    "device-hardened": {
        "version": "2.0.0-current",
        "config_ini": "[device]\nadmin_user=admin\nadmin_pass=<unique-per-device-set-at-provisioning>\n",
        "manifest": {"packages": [
            {"name": "openssl", "version": "3.0.11"},
            {"name": "busybox", "version": "1.36.1"},
        ]},
        "update_script": (
            "#!/bin/sh\n"
            "curl -o /tmp/fw.bin https://updates.example.local/latest.bin\n"
            "openssl dgst -sha256 -verify /keys/vendor_pub.pem -signature /tmp/fw.sig /tmp/fw.bin || exit 1\n"
            "cp /tmp/fw.bin /firmware/current.bin\n"
        ),
        "signed": True,
    },
}


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def build_variant(device_id: str, signing_key: Optional[Path] = None, output_dir: Path = OUTPUT_DIR) -> Path:
    spec = VARIANTS[device_id]
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"camera-fw-{spec['version']}-{device_id}.tar.gz"

    with gzip.GzipFile(archive_path, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            _add_bytes(tar, "VERSION", spec["version"].encode() + b"\n")
            _add_bytes(tar, "etc/config.ini", spec["config_ini"].encode())
            _add_bytes(tar, "manifest.json", json.dumps(spec["manifest"], indent=2, sort_keys=True).encode())
            _add_bytes(tar, "update.sh", spec["update_script"].encode(), mode=0o755)

    if spec["signed"] and signing_key is not None:
        sig_path = archive_path.with_suffix(".sig")
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(signing_key), "-out", str(sig_path), str(archive_path)],
            check=True,
        )

    return archive_path


def sha256_of(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    for device_id in VARIANTS:
        path = build_variant(device_id)
        print(f"{device_id}: {path.name} sha256={sha256_of(path)}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pip" install pyyaml==6.0.2 jsonschema==4.23.0
".venv/Scripts/pytest" lab/auditor/worker/firmware/test_generate_firmware.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add lab/auditor/worker/firmware/__init__.py lab/auditor/worker/firmware/generate_firmware.py lab/auditor/worker/firmware/test_generate_firmware.py
git commit -m "feat(firmware): add deterministic 3-variant firmware generator"
```

---

### Task 25: YARA secret-scan rules + scanner (TDD)

**Files:**
- Create: `lab/auditor/worker/firmware/rules/iot_secrets.yar`
- Create: `lab/auditor/worker/firmware/scan_firmware.py`
- Test: `lab/auditor/worker/firmware/test_scan_firmware.py`

**Interfaces:**
- Consumes: `build_variant` (Task 24).
- Produces: `scan_archive(archive_path: Path) -> list[dict]` (each dict: `{member, rule, severity}`). Feeds `TEST-FW-SECRETS` evidence in Task 26.

- [ ] **Step 1: Write the failing test first**

Create `lab/auditor/worker/firmware/test_scan_firmware.py`:

```python
from auditor.worker.firmware.generate_firmware import build_variant
from auditor.worker.firmware.scan_firmware import scan_archive


def test_insecure_firmware_flags_hardcoded_password_and_api_key(tmp_path):
    path = build_variant("device-insecure", output_dir=tmp_path)
    findings = scan_archive(path)
    rules_hit = {f["rule"] for f in findings}
    assert "HardcodedPassword" in rules_hit
    assert "EmbeddedAPIKey" in rules_hit


def test_partial_firmware_flags_weak_hardcoded_password(tmp_path):
    path = build_variant("device-partial", output_dir=tmp_path)
    findings = scan_archive(path)
    rules_hit = {f["rule"] for f in findings}
    assert "HardcodedPassword" in rules_hit
    assert "EmbeddedAPIKey" not in rules_hit


def test_hardened_firmware_has_no_secret_findings(tmp_path):
    path = build_variant("device-hardened", output_dir=tmp_path)
    findings = scan_archive(path)
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pip" install yara-python==4.5.1
".venv/Scripts/pytest" lab/auditor/worker/firmware/test_scan_firmware.py -v
```

Expected: `ModuleNotFoundError: No module named 'auditor.worker.firmware.scan_firmware'`.

- [ ] **Step 3: Write `lab/auditor/worker/firmware/rules/iot_secrets.yar`**

```yara
rule HardcodedPassword
{
    meta:
        description = "Detects a hardcoded admin password value baked into firmware config"
        severity = "high"
    strings:
        $default_pass = "admin_pass=admin"
        $weak_pass = "admin_pass=Ch4ng3d-Bu7-W3ak"
    condition:
        any of them
}

rule EmbeddedAPIKey
{
    meta:
        description = "Detects an embedded API key string in firmware config"
        severity = "high"
    strings:
        $key = /api_key=sk-[A-Za-z0-9\-]+/ ascii
    condition:
        $key
}

rule PrivateKeyFile
{
    meta:
        description = "Detects an embedded PEM private key inside firmware"
        severity = "critical"
    strings:
        $pem = "-----BEGIN PRIVATE KEY-----"
        $pem_rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $pem_ec = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}
```

- [ ] **Step 4: Write `lab/auditor/worker/firmware/scan_firmware.py`**

```python
import sys
import tarfile
from pathlib import Path

import yara

RULES_PATH = Path(__file__).parent / "rules" / "iot_secrets.yar"


def scan_archive(archive_path: Path) -> list:
    rules = yara.compile(filepath=str(RULES_PATH))
    findings = []
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            data = tar.extractfile(member).read()
            for match in rules.match(data=data):
                findings.append({
                    "member": member.name,
                    "rule": match.rule,
                    "severity": match.meta.get("severity", "unknown"),
                })
    return findings


def main() -> None:
    target = Path(sys.argv[1])
    for finding in scan_archive(target):
        print(finding)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" lab/auditor/worker/firmware/test_scan_firmware.py -v
```

Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add lab/auditor/worker/firmware/rules lab/auditor/worker/firmware/scan_firmware.py lab/auditor/worker/firmware/test_scan_firmware.py
git commit -m "feat(firmware): add YARA secret-scan rules and scanner"
```

---

### Task 26: Run the manual test catalog against all three devices; record ≥8 evidence entries (Day-2 output)

**Files:**
- Create: `lab/auditor/worker/tests/run_catalog.md` (runbook documenting exact commands run)
- Create (generated by running the runbook): `document-store/evidence/EV-*.json` (≥8 files), `document-store/raw/EV-*.txt`

**Interfaces:**
- Consumes: Task 22 (`auditor-worker` container), Task 23 (`record_evidence` CLI), Tasks 24-25 (firmware generator + YARA scanner).
- Produces: the evidence corpus Task 5 policy-as-code (Phase 5, Tasks 28-30) verdicts against.

- [ ] **Step 1: Write `lab/auditor/worker/tests/run_catalog.md`** documenting every command to run inside `auditor-worker`, one per `test_id` from spec §6, against whichever device(s) are relevant:

```markdown
# Day-2 Manual Test Catalog Runbook

Run every command below **inside** the `auditor-worker` container:

​```
docker compose exec auditor-worker sh
​```

Then from that shell (`/work` is the container's workdir; evidence files land in
`/work/document-store`, which is the same `document-store/` at the repo root via bind mount):

## TEST-NET-PORTSCAN (against device-insecure)

​```sh
nmap -sV -p- device-insecure > /tmp/portscan.txt
cat /tmp/portscan.txt
python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-NET-PORTSCAN \
  --tool nmap --tool-version "$(nmap --version | head -1 | awk '{print $3}')" \
  --command "nmap -sV -p- device-insecure" \
  --finding "Port 80 (HTTP) open; no unnecessary Telnet on this device's own container" \
  --raw-file /tmp/portscan.txt --confidence high \
  --observations '{"open_ports": [80], "telnet_open": false}'
​```

## TEST-NET-PORTSCAN (against telnet-sim, representing device-insecure's exposed Telnet service)

​```sh
nmap -sV -p 23 telnet-sim > /tmp/portscan_telnet.txt
python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-NET-PORTSCAN \
  --tool nmap --tool-version "$(nmap --version | head -1 | awk '{print $3}')" \
  --command "nmap -sV -p 23 telnet-sim" \
  --finding "Telnet (23/tcp) open; plaintext management console exposed" \
  --raw-file /tmp/portscan_telnet.txt --confidence high \
  --observations '{"open_ports": [23], "telnet_open": true}'
​```

## TEST-AUTH-DEFAULT-CREDS (device-insecure)

​```sh
curl -s -X POST http://device-insecure/login -d "username=admin&password=admin" > /tmp/login.txt
cat /tmp/login.txt
python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-AUTH-DEFAULT-CREDS \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl -X POST http://device-insecure/login -d username=admin&password=admin" \
  --finding "Default credentials admin/admin accepted" \
  --raw-file /tmp/login.txt --confidence high \
  --observations '{"default_creds": true}'
​```

## TEST-AUTH-DEFAULT-CREDS (device-hardened, expect rejection)

​```sh
curl -sk -X POST https://device-hardened/login -d "username=admin&password=admin" -o /tmp/login_hardened.txt -w "%{http_code}" > /tmp/login_hardened_code.txt
cat /tmp/login_hardened_code.txt
python auditor/worker/tests/record_evidence.py \
  --device device-hardened --test-id TEST-AUTH-DEFAULT-CREDS \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl -X POST https://device-hardened/login -d username=admin&password=admin" \
  --finding "Default credentials rejected (401); device requires its unique provisioned password" \
  --raw-file /tmp/login_hardened_code.txt --confidence high \
  --observations '{"default_creds": false}'
​```

## TEST-ADMIN-UNAUTH (device-insecure)

​```sh
curl -s -o /tmp/admin_reset.txt -w "%{http_code}" http://device-insecure/api/admin/reset > /tmp/admin_reset_code.txt
python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-ADMIN-UNAUTH \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl http://device-insecure/api/admin/reset" \
  --finding "Admin reset endpoint reachable with no authentication" \
  --raw-file /tmp/admin_reset_code.txt --confidence high \
  --observations '{"admin_unauthenticated": true}'
​```

## TEST-HTTP-HEADERS (device-insecure)

​```sh
curl -sI http://device-insecure/ > /tmp/headers.txt
cat /tmp/headers.txt
python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-HTTP-HEADERS \
  --tool curl --tool-version "$(curl --version | head -1 | awk '{print $2}')" \
  --command "curl -I http://device-insecure/" \
  --finding "Missing security headers (X-Frame-Options, Content-Security-Policy)" \
  --raw-file /tmp/headers.txt --confidence medium \
  --observations '{"missing_security_headers": ["X-Frame-Options", "Content-Security-Policy"]}'
​```

## TEST-TLS-CONFIG (device-partial, weak cert)

​```sh
openssl s_client -connect device-partial:443 -brief < /dev/null > /tmp/tls_partial.txt 2>&1
cat /tmp/tls_partial.txt
python auditor/worker/tests/record_evidence.py \
  --device device-partial --test-id TEST-TLS-CONFIG \
  --tool openssl --tool-version "$(openssl version | awk '{print $2}')" \
  --command "openssl s_client -connect device-partial:443 -brief" \
  --finding "1024-bit RSA certificate with SHA-1 signature (weak)" \
  --raw-file /tmp/tls_partial.txt --confidence high \
  --observations '{"tls_version": "TLSv1.2", "weak_cipher": true, "cert_bits": 1024}'
​```

## TEST-TLS-CONFIG (device-hardened, strong cert)

​```sh
openssl s_client -connect device-hardened:443 -brief < /dev/null > /tmp/tls_hardened.txt 2>&1
python auditor/worker/tests/record_evidence.py \
  --device device-hardened --test-id TEST-TLS-CONFIG \
  --tool openssl --tool-version "$(openssl version | awk '{print $2}')" \
  --command "openssl s_client -connect device-hardened:443 -brief" \
  --finding "2048-bit RSA certificate with SHA-256 signature (strong)" \
  --raw-file /tmp/tls_hardened.txt --confidence high \
  --observations '{"tls_version": "TLSv1.3", "weak_cipher": false, "cert_bits": 2048}'
​```

## TEST-MQTT-OPEN (mqtt-broker-insecure)

​```sh
timeout 3 mosquitto_sub -h mqtt-broker-insecure -t 'devices/#' -C 1 -v > /tmp/mqtt_insecure.txt 2>&1
cat /tmp/mqtt_insecure.txt
python auditor/worker/tests/record_evidence.py \
  --device mqtt-broker-insecure --test-id TEST-MQTT-OPEN \
  --tool mosquitto_sub --tool-version "$(mosquitto_sub --help 2>&1 | head -1)" \
  --command "mosquitto_sub -h mqtt-broker-insecure -t devices/# -C 1" \
  --finding "Anonymous plaintext subscription succeeded; no auth or TLS required" \
  --raw-file /tmp/mqtt_insecure.txt --confidence high \
  --observations '{"mqtt_anonymous": true, "mqtt_tls": false}'
​```

## TEST-MQTT-OPEN (mqtt-broker-secure, expect rejection)

​```sh
timeout 3 mosquitto_sub -h mqtt-broker-secure -p 8883 -t 'devices/#' -C 1 > /tmp/mqtt_secure.txt 2>&1
cat /tmp/mqtt_secure.txt
python auditor/worker/tests/record_evidence.py \
  --device mqtt-broker-secure --test-id TEST-MQTT-OPEN \
  --tool mosquitto_sub --tool-version "$(mosquitto_sub --help 2>&1 | head -1)" \
  --command "mosquitto_sub -h mqtt-broker-secure -p 8883 -t devices/# -C 1" \
  --finding "Anonymous connection rejected; TLS + password auth required" \
  --raw-file /tmp/mqtt_secure.txt --confidence high \
  --observations '{"mqtt_anonymous": false, "mqtt_tls": true}'
​```

## TEST-FW-SECRETS + TEST-FW-SBOM (firmware analysis, all 3 variants)

​```sh
python auditor/worker/firmware/generate_firmware.py
file auditor/worker/firmware/output/*.tar.gz > /tmp/fw_file.txt

python -c "
from pathlib import Path
from auditor.worker.firmware.scan_firmware import scan_archive
p = Path('auditor/worker/firmware/output/camera-fw-1.0.0-old-device-insecure.tar.gz')
for f in scan_archive(p):
    print(f)
" > /tmp/fw_scan_insecure.txt
cat /tmp/fw_scan_insecure.txt

python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-FW-SECRETS \
  --tool yara --tool-version "4.5.1" \
  --command "scan_firmware.py camera-fw-1.0.0-old-device-insecure.tar.gz" \
  --finding "Hardcoded admin password and embedded API key found in firmware config" \
  --raw-file /tmp/fw_scan_insecure.txt --confidence high \
  --observations '{"hardcoded_secret": true, "api_key_found": true, "private_key_present": false}'

syft auditor/worker/firmware/output/camera-fw-1.0.0-old-device-insecure.tar.gz -o json > /tmp/fw_sbom_insecure.json
grype sbom:/tmp/fw_sbom_insecure.json > /tmp/fw_vulns_insecure.txt
cat /tmp/fw_vulns_insecure.txt

python auditor/worker/tests/record_evidence.py \
  --device device-insecure --test-id TEST-FW-SBOM \
  --tool grype --tool-version "$(grype version 2>&1 | head -1)" \
  --command "syft ... | grype sbom:-" \
  --finding "Outdated openssl 1.0.1e and busybox 1.19.4 flagged with known CVEs" \
  --raw-file /tmp/fw_vulns_insecure.txt --confidence high \
  --observations '{"outdated_packages": ["openssl-1.0.1e", "busybox-1.19.4"]}'
​```

This yields **10 evidence entries** total (well above the required ≥8), covering: network/port
scan (2), default credentials (2), unauthenticated admin (1), missing headers (1), TLS config (2),
MQTT posture (2), firmware secrets (1), firmware SBOM/CVE (1) — every category the brief requires
(default creds, exposed insecure service, unencrypted protocol, hard-coded secret, outdated
package, weak/missing TLS, missing logging note captured in the STRIDE doc, missing privacy
evidence captured in `docs/privacy_insecure.md`).
```

- [ ] **Step 2: Push, pull, actually execute the runbook (PC via ssh-mcp)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add lab/auditor/worker/tests/run_catalog.md
git commit -m "docs: add Day-2 manual test catalog runbook"
git push
```

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git pull; cd lab; docker compose up -d --build
docker compose exec auditor-worker sh -c "cd /work && <paste each command block from run_catalog.md in order>"
```

Expected: each `record_evidence.py` invocation prints the JSON record it just wrote; no `ValidationError` tracebacks.

- [ ] **Step 3: Confirm ≥8 evidence files landed and all validate (PC via ssh-mcp)**

```
docker compose exec auditor-worker sh -c "ls /work/document-store/evidence | wc -l; python -c \"
import json, glob
from policies.schema.validate import validate_evidence
for f in glob.glob('/work/document-store/evidence/*.json'):
    validate_evidence(json.load(open(f)))
print('all evidence files valid')
\""
```

Expected: a count ≥ 8, and `all evidence files valid` with no exception.

- [ ] **Step 4: Pull the generated evidence back to the laptop and commit it (laptop)**

The evidence files were written on the PC into the bind-mounted `document-store/` — since Workflow B pushes from laptop→PC, and the PC wrote new files locally, `git status` on the **PC** will show them as untracked. Commit from the PC side (still following the plan's "the PC is a build target," but committing generated evidence artifacts is a one-time exception since they were generated there):

```
cd C:\Users\osama\Projects\kaust-iot-security-lab; git add document-store/evidence document-store/raw; git commit -m "test: add Day-2 manual assessment evidence (10 entries across 3 devices)"; git push
```

Then on the laptop:

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git pull
```

Expected: the 20 new files (10 evidence JSON + 10 raw .txt) appear locally.

---

### Task 27: Evidence summary doc (Day-2 output)

**Files:**
- Create: `docs/architecture/evidence-summary.md`

- [ ] **Step 1: Write a table summarizing the evidence corpus from Task 26**

```markdown
# Day-2 Evidence Summary

| evidence_id | device | test_id | finding |
|---|---|---|---|
| (fill exact IDs after Task 26 run) | device-insecure | TEST-NET-PORTSCAN | Port 80 open |
| ... | device-insecure | TEST-NET-PORTSCAN | Telnet (23) open |
| ... | device-insecure | TEST-AUTH-DEFAULT-CREDS | admin/admin accepted |
| ... | device-hardened | TEST-AUTH-DEFAULT-CREDS | admin/admin rejected |
| ... | device-insecure | TEST-ADMIN-UNAUTH | unauthenticated admin reset |
| ... | device-insecure | TEST-HTTP-HEADERS | missing security headers |
| ... | device-partial | TEST-TLS-CONFIG | weak 1024-bit/SHA-1 cert |
| ... | device-hardened | TEST-TLS-CONFIG | strong 2048-bit/SHA-256 cert |
| ... | mqtt-broker-insecure | TEST-MQTT-OPEN | anonymous plaintext MQTT |
| ... | mqtt-broker-secure | TEST-MQTT-OPEN | TLS+auth required |
| ... | device-insecure | TEST-FW-SECRETS | hardcoded password + API key |
| ... | device-insecure | TEST-FW-SBOM | outdated openssl/busybox with CVEs |

Each row's full record (raw output → structured evidence → sha256) lives in
`document-store/evidence/<evidence_id>.json` and `document-store/raw/<evidence_id>.txt`.
```

- [ ] **Step 2: Fill in the real `evidence_id`s from the files generated in Task 26 (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
ls document-store/evidence
```

Edit `docs/architecture/evidence-summary.md` replacing each `(fill exact IDs after Task 26 run)`-style placeholder with the real IDs listed.

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/evidence-summary.md
git commit -m "docs: add Day-2 evidence summary table"
```

---

### Task 28: Policy engine core (TDD) — structured condition evaluator

**Files:**
- Create: `policies/engine/__init__.py`
- Create: `policies/engine/policy_engine.py`
- Test: `policies/engine/test_policy_engine.py`

**Interfaces:**
- Produces: `_get_field(record: dict, dotted_path: str) -> Any`, `load_control(path: str) -> dict`, `load_evidence(path: str) -> dict`, `evaluate(control: dict, evidence: dict, verdict_id: Optional[str] = None) -> dict`. Consumed by Task 30's verdict-generation CLI.

- [ ] **Step 1: Write the failing test first**

Create `policies/engine/test_policy_engine.py`:

```python
from policies.engine.policy_engine import evaluate, _get_field

CONTROL = {
    "control_id": "SA-IOT-002",
    "title": "No default or hard-coded credentials",
    "saudi_source": [{"framework": "CGIoT-1:2024", "reference": "2-2-2"}],
    "severity": "high",
    "conditions": {
        "fail": {"field": "observations.default_creds", "op": "equals", "value": True},
        "partial": None,
        "pass": {"field": "observations.default_creds", "op": "equals", "value": False},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    },
    "remediation": "Force a unique strong password on first boot.",
}


def _evidence(default_creds):
    return {
        "evidence_id": "EV-2026-07-08-0007",
        "device_id": "device-insecure",
        "timestamp": "2026-07-08T10:15:32Z",
        "observations": {"default_creds": default_creds},
    }


def test_get_field_resolves_dotted_path():
    assert _get_field({"observations": {"default_creds": True}}, "observations.default_creds") is True


def test_get_field_missing_path_returns_none():
    assert _get_field({"observations": {}}, "observations.missing") is None


def test_fail_condition_matches_when_default_creds_true():
    verdict = evaluate(CONTROL, _evidence(True))
    assert verdict["status"] == "FAIL"
    assert verdict["matched"] == "fail"


def test_pass_condition_matches_when_default_creds_false():
    verdict = evaluate(CONTROL, _evidence(False))
    assert verdict["status"] == "PASS"
    assert verdict["matched"] == "pass"


def test_saudi_source_formatted_correctly():
    verdict = evaluate(CONTROL, _evidence(True))
    assert verdict["saudi_source"] == "CGIoT-1:2024 §2-2-2"


def test_fail_checked_before_pass_when_both_would_match_a_permissive_control():
    permissive = dict(CONTROL)
    permissive["conditions"] = {
        "fail": {"field": "observations.default_creds", "op": "in", "value": [True, False]},
        "partial": None,
        "pass": {"field": "observations.default_creds", "op": "equals", "value": False},
        "inconclusive": None,
    }
    verdict = evaluate(permissive, _evidence(False))
    assert verdict["matched"] == "fail"  # fail is checked first, per spec ordering


def test_inconclusive_when_nothing_matches():
    no_match_control = dict(CONTROL)
    no_match_control["conditions"] = {
        "fail": {"field": "observations.nonexistent", "op": "equals", "value": True},
        "partial": None,
        "pass": {"field": "observations.nonexistent", "op": "equals", "value": False},
        "inconclusive": {"when": "evidence_missing_or_low_confidence"},
    }
    verdict = evaluate(no_match_control, _evidence(True))
    assert verdict["status"] == "INCONCLUSIVE"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
touch policies/engine/__init__.py
".venv/Scripts/pytest" policies/engine/test_policy_engine.py -v
```

Expected: `ModuleNotFoundError: No module named 'policies.engine.policy_engine'`.

- [ ] **Step 3: Write `policies/engine/policy_engine.py`**

```python
import json
import operator
from typing import Any, Optional

import yaml

OPS = {
    "equals": operator.eq,
    "not_equals": operator.ne,
    "in": lambda a, b: a in b if b is not None else False,
    "not_in": lambda a, b: a not in b if b is not None else True,
    "greater_than": lambda a, b: a is not None and a > b,
    "less_than": lambda a, b: a is not None and a < b,
    "contains": lambda a, b: b in a if a is not None else False,
}

STATUS_MAP = {"fail": "FAIL", "partial": "PARTIAL", "pass": "PASS", "inconclusive": "INCONCLUSIVE"}


def _get_field(record: dict, dotted_path: str) -> Any:
    value: Any = record
    for part in dotted_path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def _condition_matches(evidence: dict, condition: Optional[dict]) -> bool:
    if not condition or "when" in condition:
        return False
    field = condition["field"]
    op = condition["op"]
    expected = condition["value"]
    actual = _get_field(evidence, field)
    return OPS[op](actual, expected)


def load_control(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_evidence(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate(control: dict, evidence: dict, verdict_id: Optional[str] = None) -> dict:
    conditions = control["conditions"]
    matched = "inconclusive"
    reason = "no condition matched; evidence insufficient"

    for status in ("fail", "partial", "pass"):
        condition = conditions.get(status)
        if _condition_matches(evidence, condition):
            matched = status
            reason = f"{condition['field']} {condition['op']} {condition['value']}"
            break

    saudi = control["saudi_source"][0]
    result = {
        "control_id": control["control_id"],
        "device_id": evidence["device_id"],
        "status": STATUS_MAP[matched],
        "severity": control["severity"],
        "evidence_ids": [evidence["evidence_id"]],
        "matched": matched,
        "reason": reason,
        "saudi_source": f"{saudi['framework']} §{saudi['reference']}",
        "remediation": control["remediation"],
        "timestamp": evidence["timestamp"],
    }
    if verdict_id:
        result = {"verdict_id": verdict_id, **result}
    return result
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/engine/test_policy_engine.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add policies/engine/__init__.py policies/engine/policy_engine.py policies/engine/test_policy_engine.py
git commit -m "feat(policy-engine): add structured-condition verdict evaluator"
```

---

### Task 29: The 5 Day-3 YAML controls (SA-IOT-001..005)

**Files:**
- Create: `policies/controls/SA-IOT-001.yaml`
- Create: `policies/controls/SA-IOT-002.yaml`
- Create: `policies/controls/SA-IOT-003.yaml`
- Create: `policies/controls/SA-IOT-004.yaml`
- Create: `policies/controls/SA-IOT-005.yaml`
- Test: `policies/controls/test_controls_are_valid.py`

**Interfaces:**
- Consumes: `policies.schema.validate.validate_control` (Task 2), `policies.engine.policy_engine.load_control` (Task 28).
- Produces: 5 loadable, schema-valid control definitions. Consumed by Task 30.

- [ ] **Step 1: Write `policies/controls/SA-IOT-001.yaml`** (device identification)

```yaml
control_id: SA-IOT-001
title: Device identification and asset inventory
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-1-1"
    clause: "Maintain an accurate inventory of connected IoT devices, including vendor, model, and identifiers."
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-DEVICE-ID
automated_test_ids: [TEST-DEVICE-ID]
severity: medium
conditions:
  pass: { field: "observations.device_identified", op: "equals", value: true }
  fail: { field: "observations.device_identified", op: "equals", value: false }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Expose vendor, model, MAC, and firmware version via an unauthenticated read-only device-info endpoint for asset inventory tooling."
```

- [ ] **Step 2: Write `policies/controls/SA-IOT-002.yaml`** (default credentials — from spec §5 verbatim)

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
  pass: { field: "observations.default_creds", op: "equals", value: false }
  fail: { field: "observations.default_creds", op: "equals", value: true }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Force a unique strong password on first boot; remove all vendor defaults."
```

- [ ] **Step 3: Write `policies/controls/SA-IOT-003.yaml`** (unnecessary services)

```yaml
control_id: SA-IOT-003
title: Disable unnecessary network services
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-15-2"
    clause: "Disable all unnecessary network services and interfaces on the device."
  - framework: CGIoT-1:2024
    reference: "Appendix A #3"
    clause: "Minimize the device's exposed attack surface."
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-NET-PORTSCAN
automated_test_ids: [TEST-NET-PORTSCAN]
severity: high
conditions:
  pass: { field: "observations.telnet_open", op: "equals", value: false }
  fail: { field: "observations.telnet_open", op: "equals", value: true }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Remove Telnet and any other non-essential listening service from the device image."
```

- [ ] **Step 4: Write `policies/controls/SA-IOT-004.yaml`** (insecure protocols)

```yaml
control_id: SA-IOT-004
title: No insecure/unencrypted communication protocols
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-4-3"
    clause: "Use encrypted protocols for all device-to-backend communication."
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-MQTT-OPEN
automated_test_ids: [TEST-MQTT-OPEN]
severity: high
conditions:
  pass: { field: "observations.mqtt_tls", op: "equals", value: true }
  fail: { field: "observations.mqtt_tls", op: "equals", value: false }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Route all MQTT telemetry through the TLS-secured, authenticated broker; retire the plaintext broker."
```

- [ ] **Step 5: Write `policies/controls/SA-IOT-005.yaml`** (TLS / secure comms)

```yaml
control_id: SA-IOT-005
title: Strong TLS configuration for device communications
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-7-2"
    clause: "Use strong, up-to-date cryptographic algorithms and key lengths for TLS."
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-TLS-CONFIG
automated_test_ids: [TEST-TLS-CONFIG]
severity: high
conditions:
  pass: { field: "observations.weak_cipher", op: "equals", value: false }
  fail: { field: "observations.weak_cipher", op: "equals", value: true }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Reissue the device certificate at 2048-bit RSA (or better) with SHA-256, disable TLS 1.0/1.1."
```

- [ ] **Step 6: Write a schema-validity test for all 5 controls**

Create `policies/controls/test_controls_are_valid.py`:

```python
import glob

from policies.engine.policy_engine import load_control
from policies.schema.validate import validate_control


def test_all_five_controls_are_schema_valid():
    control_files = sorted(glob.glob("policies/controls/SA-IOT-*.yaml"))
    assert len(control_files) == 5
    for path in control_files:
        control = load_control(path)
        validate_control(control)  # should not raise


def test_control_ids_match_filenames():
    control_files = sorted(glob.glob("policies/controls/SA-IOT-*.yaml"))
    for path in control_files:
        control = load_control(path)
        expected_id = path.split("/")[-1].replace(".yaml", "").replace("\\", "/").split("/")[-1]
        assert control["control_id"] == expected_id
```

- [ ] **Step 7: Run the tests (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/controls/test_controls_are_valid.py -v
```

Expected: 2 passed.

- [ ] **Step 8: Commit**

```bash
git add policies/controls
git commit -m "feat(policy): add 5 Day-3 NCA controls (SA-IOT-001..005)"
```

---

### Task 30: Verdict-generation CLI; run across Phase-4 evidence; verify Day-3 acceptance

**Files:**
- Create: `policies/engine/generate_verdicts.py`
- Test: `policies/engine/test_generate_verdicts.py`

**Interfaces:**
- Consumes: `evaluate`, `load_control`, `load_evidence` (Task 28), the 5 controls (Task 29), evidence corpus (Task 26).
- Produces: `generate_verdicts(evidence_dir, controls_dir, output_dir) -> list[dict]` — matches each evidence record's `test_id` against every control whose `required_evidence[*].test_id` includes it, writes one verdict JSON per match.

- [ ] **Step 1: Write the failing test first**

Create `policies/engine/test_generate_verdicts.py`:

```python
import json

from policies.engine.generate_verdicts import generate_verdicts


def _write_evidence(path, evidence_id, test_id, device_id, observations):
    record = {
        "evidence_id": evidence_id,
        "device_id": device_id,
        "test_id": test_id,
        "tool": "curl",
        "tool_version": "8.9.1",
        "command": "curl ...",
        "timestamp": "2026-07-08T10:15:32Z",
        "finding": "test finding",
        "observations": observations,
        "raw_output_path": "document-store/raw/x.txt",
        "confidence": "high",
        "sha256": "a" * 64,
    }
    path.write_text(json.dumps(record))
    return record


def _write_control(path, contents):
    path.write_text(contents)


CONTROL_YAML = """
control_id: SA-IOT-002
title: No default or hard-coded credentials
saudi_source:
  - framework: CGIoT-1:2024
    reference: "2-2-2"
applicability:
  device_type: [smart-camera]
required_evidence:
  - test_id: TEST-AUTH-DEFAULT-CREDS
automated_test_ids: [TEST-AUTH-DEFAULT-CREDS]
severity: high
conditions:
  pass: { field: "observations.default_creds", op: "equals", value: false }
  fail: { field: "observations.default_creds", op: "equals", value: true }
  partial: null
  inconclusive: { when: "evidence_missing_or_low_confidence" }
remediation: "Force a unique strong password on first boot."
"""


def test_generate_verdicts_produces_fail_and_pass_across_devices(tmp_path):
    evidence_dir = tmp_path / "evidence"
    controls_dir = tmp_path / "controls"
    output_dir = tmp_path / "verdicts"
    evidence_dir.mkdir()
    controls_dir.mkdir()

    _write_control(controls_dir / "SA-IOT-002.yaml", CONTROL_YAML)
    _write_evidence(evidence_dir / "EV-1.json", "EV-1", "TEST-AUTH-DEFAULT-CREDS", "device-insecure", {"default_creds": True})
    _write_evidence(evidence_dir / "EV-2.json", "EV-2", "TEST-AUTH-DEFAULT-CREDS", "device-hardened", {"default_creds": False})

    verdicts = generate_verdicts(evidence_dir, controls_dir, output_dir)

    statuses_by_device = {v["device_id"]: v["status"] for v in verdicts}
    assert statuses_by_device["device-insecure"] == "FAIL"
    assert statuses_by_device["device-hardened"] == "PASS"
    assert len(list(output_dir.glob("VD-*.json"))) == 2
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/engine/test_generate_verdicts.py -v
```

Expected: `ModuleNotFoundError: No module named 'policies.engine.generate_verdicts'`.

- [ ] **Step 3: Write `policies/engine/generate_verdicts.py`**

```python
import json
from pathlib import Path
from typing import List

from policies.engine.policy_engine import evaluate, load_control, load_evidence
from policies.schema.validate import validate_verdict


def generate_verdicts(evidence_dir: Path, controls_dir: Path, output_dir: Path) -> List[dict]:
    output_dir.mkdir(parents=True, exist_ok=True)

    controls = [load_control(str(p)) for p in sorted(Path(controls_dir).glob("SA-IOT-*.yaml"))]
    evidence_records = [load_evidence(str(p)) for p in sorted(Path(evidence_dir).glob("*.json"))]

    verdicts = []
    seq = 0
    for evidence in evidence_records:
        for control in controls:
            required_test_ids = {req["test_id"] for req in control["required_evidence"]}
            if evidence["test_id"] not in required_test_ids:
                continue
            seq += 1
            date_str = evidence["timestamp"][:10]
            verdict_id = f"VD-{date_str}-{seq:04d}"
            verdict = evaluate(control, evidence, verdict_id=verdict_id)
            validate_verdict(verdict)
            out_path = Path(output_dir) / f"{verdict_id}.json"
            out_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
            verdicts.append(verdict)

    return verdicts


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    verdicts = generate_verdicts(
        evidence_dir=repo_root / "document-store" / "evidence",
        controls_dir=repo_root / "policies" / "controls",
        output_dir=repo_root / "document-store" / "verdicts",
    )
    for v in verdicts:
        print(f"{v['verdict_id']}: {v['control_id']} / {v['device_id']} -> {v['status']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/engine/test_generate_verdicts.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add policies/engine/generate_verdicts.py policies/engine/test_generate_verdicts.py
git commit -m "feat(policy-engine): add verdict-generation CLI across an evidence corpus"
```

- [ ] **Step 6: Run the real thing against the Task 26 evidence corpus and confirm Day-3 acceptance (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/python" -m policies.engine.generate_verdicts
```

Expected output: one line per (evidence, matching control) pair, e.g.:

```
VD-2026-07-08-0001: SA-IOT-003 / device-insecure -> FAIL
VD-2026-07-08-0002: SA-IOT-002 / device-insecure -> FAIL
VD-2026-07-08-0003: SA-IOT-002 / device-hardened -> PASS
VD-2026-07-08-0004: SA-IOT-004 / mqtt-broker-insecure -> FAIL
VD-2026-07-08-0005: SA-IOT-004 / mqtt-broker-secure -> PASS
VD-2026-07-08-0006: SA-IOT-005 / device-partial -> FAIL
VD-2026-07-08-0007: SA-IOT-005 / device-hardened -> PASS
```

This satisfies Day-3 acceptance: **at least 2 controls (here, SA-IOT-002, SA-IOT-004, and SA-IOT-005 — three) produce correct PASS and FAIL verdicts across different device configurations**, end-to-end from simulated device → network test → evidence JSON → YAML policy → verdict JSON.

- [ ] **Step 7: Commit the generated verdict JSON files as delivered evidence of the working demo**

```bash
git add document-store/verdicts
git commit -m "test: add generated Day-3 verdict corpus demonstrating pass/fail across device configs"
```

---

### Task 31: Phases 0-5 acceptance verification checklist

**Files:**
- Create: `docs/architecture/phases-0-5-acceptance.md`

- [ ] **Step 1: Write the checklist, filled in as each item is actually verified**

```markdown
# Phases 0-5 Acceptance Verification

## Day 1
- [x] Working compose env (`lab/docker-compose.yml`, 6 services + cert-init, 2 networks)
- [x] ≥1 device (3: device-insecure, device-partial, device-hardened)
- [x] ≥3 exposed services inside the lab (HTTP/HTTPS x3, Telnet, MQTT x2 = 6)
- [x] Network diagram (`docs/architecture/architecture-diagram.md`)
- [x] Threat model (`docs/architecture/threat-model-stride.md`)
- [x] Device inventory (`docs/architecture/device-inventory.md`)
- [x] README (`lab/README.md`)
- [x] Demonstrated: reach device web UI, connect to MQTT, detect ≥3 open ports, view metadata — all
      from inside the lab network (Task 11, Step 4)

## Day 2
- [x] ≥8 manual findings (Task 26 produced 10, across all required categories)
- [x] Each finding: raw output → structured evidence (schema-validated) → interpretation (`finding`
      field) → remediation (carried by the matching control in Day 3)
- [x] Evidence summary (`docs/architecture/evidence-summary.md`)

## Day 3
- [x] First 5 controls mapped to Saudi CGIoT-1:2024 sources (`policies/controls/SA-IOT-001..005.yaml`)
- [x] Minimal policy engine: load control → read evidence → apply verdict logic → output verdict
      JSON (`policies/engine/policy_engine.py` + `generate_verdicts.py`)
- [x] ≥2 controls produce correct Pass and Fail verdicts across different device configs (Task 30,
      Step 6 — SA-IOT-002, SA-IOT-004, SA-IOT-005 all show both a PASS and a FAIL)

## Determinism check
- [x] No `eval`/`exec` anywhere in `policies/engine/policy_engine.py` — verified by inspection
      (grep confirms zero matches)
```

- [ ] **Step 2: Run the grep check referenced in the doc (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
grep -n "eval(\|exec(" policies/engine/policy_engine.py || echo "clean: no eval/exec found"
```

Expected: `clean: no eval/exec found`.

- [ ] **Step 3: Run the full local test suite one final time (laptop)**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
".venv/Scripts/pytest" policies/ lab/auditor/worker -v
cd lab/devices/smart-camera && "../../../.venv/Scripts/python" -m pytest tests/ -v 2>/dev/null || .venv/Scripts/pytest tests/ -v
```

Expected: all tests pass (policy engine: 7+1+2, schema: 8, worker: 3+4+3, smart-camera: 15 — 36+ total).

- [ ] **Step 4: Commit**

```bash
cd "/c/Users/cours/Desktop/Kaust IoT Project"
git add docs/architecture/phases-0-5-acceptance.md
git commit -m "docs: record Phases 0-5 acceptance verification"
```

- [ ] **Step 5: Update CLAUDE.md §0/§8** to reflect Phases 0-5 complete, and note that Phases 6-8
      (auditor-api/database, Flutter auditor-web, full 11-container polish) are a separate
      follow-up plan not yet written.

---

## Self-Review Notes (for the plan author, not a task to execute)

- **Spec coverage:** §3 architecture/networks → Tasks 3, 22. §4 device profiles → Tasks 4-7, 14-16.
  §5 data contracts → Task 2. §6 test catalog → Task 26. §7 firmware → Tasks 24-25. §8 diagrams →
  Tasks 17-20. §9 repo layout → File Structure section + Task 1. §10 build order Phases 0-5 → Tasks
  1-3 (Phase 0), 4-11 (Phase 1), 12-16 (Phase 2), 17-21 (Phase 3), 22-27 (Phase 4), 28-30 (Phase 5).
  §11 acceptance → Task 31. All covered; Phases 6-8 explicitly deferred to a follow-up plan.
- **Type consistency:** `record_evidence()` signature (device_id, test_id, tool, tool_version,
  command, finding, raw_file, confidence, observations, document_store) is identical between Task
  23's implementation and Task 26's runbook CLI usage. `evaluate(control, evidence, verdict_id)`
  matches between Task 28's definition and Task 30's caller. `_get_field`/`_condition_matches`
  names match between Task 28's tests and implementation.
