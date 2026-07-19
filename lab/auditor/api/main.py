import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from db import get_connection
from device_validation import (
    TIERS,
    ValidationError,
    validate_device_id,
    validate_host,
    validate_port,
    validate_service_type,
)
from policies.catalog.scan_tests import SCAN_CATALOG, is_applicable


def _document_store_dir() -> Path:
    # Read lazily (not as a module-level constant) so it reflects the
    # current environment at request time, not just whatever it was when
    # this module was first imported.
    return Path(os.environ.get("DOCUMENT_STORE_DIR", "/work/document-store"))

app = FastAPI(title="auditor-api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ValidationError)
async def validation_error_handler(request, exc: ValidationError):
    return JSONResponse(
        status_code=400, content={"field": exc.field, "detail": exc.message}
    )

SCHEMA_PATH = Path("/work/policies/schema/evidence.schema.json")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _load_evidence_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _insert_evidence(conn, evidence: dict) -> None:
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


@app.post("/evidence", status_code=201)
def post_evidence(evidence: dict):
    schema = _load_evidence_schema()
    try:
        jsonschema.validate(evidence, schema)
    except jsonschema.ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc.message))

    conn = get_connection()
    try:
        _insert_evidence(conn, evidence)
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


SCAN_JOB_COLUMNS = (
    "id, device_id, test_id, status, tool, tool_version, command, "
    "raw_output, observations, error, evidence_id, created_at, updated_at"
)


def _row_to_scan_job(row: tuple) -> dict:
    (job_id, device_id, test_id, status, tool, tool_version, command,
     raw_output, observations, error, evidence_id, created_at, updated_at) = row
    return {
        "id": job_id, "device_id": device_id, "test_id": test_id, "status": status,
        "tool": tool, "tool_version": tool_version, "command": command,
        "raw_output": raw_output, "observations": observations, "error": error,
        "evidence_id": evidence_id,
        "created_at": created_at.isoformat(), "updated_at": updated_at.isoformat(),
    }


@app.get("/scan-tests")
def get_scan_tests():
    return [
        {
            "test_id": test_id,
            "label": spec["label"],
            "applicable_service_types": list(spec["applicable_service_types"]),
        }
        for test_id, spec in SCAN_CATALOG.items()
    ]


@app.post("/scan-jobs", status_code=201)
def post_scan_job(payload: dict):
    device_id = payload.get("device_id")
    test_id = payload.get("test_id")
    if not device_id or not test_id:
        raise HTTPException(status_code=422, detail="device_id and test_id are required")

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

    conn = get_connection()
    try:
        row = conn.execute(
            f"INSERT INTO scan_jobs (device_id, test_id) VALUES (%s, %s) RETURNING {SCAN_JOB_COLUMNS}",
            (device_id, test_id),
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    return _row_to_scan_job(row)


@app.get("/scan-jobs")
def get_scan_jobs(status: str | None = None):
    # The worker resolves each job's target (host/service_type/port) from the
    # current device state via this LEFT JOIN, rather than from columns on
    # scan_jobs itself - scan_jobs stays a pure audit row (device_id, test_id
    # only), and a deregistered device yields NULLs that resolve_target must
    # reject rather than a KeyError that would crash the poll loop.
    conn = get_connection()
    try:
        query = """
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
            WHERE 1=1
        """
        params: list = []
        if status is not None:
            query += " AND j.status = %s"
            params.append(status)
        query += " ORDER BY j.created_at"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    jobs = []
    for row in rows:
        job = _row_to_scan_job(row[:13])
        job["host"] = row[13]
        job["service_type"] = row[14]
        job["port"] = row[15]
        jobs.append(job)
    return jobs


@app.get("/scan-jobs/{job_id}")
def get_scan_job(job_id: int):
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE id = %s", (job_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="scan job not found")
    return _row_to_scan_job(row)


SCAN_JOB_PATCHABLE_FIELDS = {
    "status", "tool", "tool_version", "command", "raw_output", "observations", "error",
}


@app.patch("/scan-jobs/{job_id}")
def patch_scan_job(job_id: int, payload: dict):
    fields = {k: v for k, v in payload.items() if k in SCAN_JOB_PATCHABLE_FIELDS}
    if not fields:
        raise HTTPException(status_code=422, detail="no valid fields to update")

    set_clauses = []
    values: list = []
    for key, value in fields.items():
        set_clauses.append(f"{key} = %s")
        values.append(json.dumps(value) if key == "observations" else value)
    values.append(job_id)

    conn = get_connection()
    try:
        row = conn.execute(
            f"UPDATE scan_jobs SET {', '.join(set_clauses)}, updated_at = now() "
            f"WHERE id = %s RETURNING {SCAN_JOB_COLUMNS}",
            values,
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="scan job not found")
    return _row_to_scan_job(row)


@app.post("/scan-jobs/{job_id}/record", status_code=201)
def record_scan_job_evidence(job_id: int, payload: dict):
    finding = payload.get("finding")
    confidence = payload.get("confidence")
    if not finding or confidence not in ("high", "medium", "low"):
        raise HTTPException(status_code=422, detail="finding and a valid confidence are required")

    conn = get_connection()
    try:
        job_row = conn.execute(
            f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE id = %s", (job_id,)
        ).fetchone()
        if job_row is None:
            raise HTTPException(status_code=404, detail="scan job not found")
        job = _row_to_scan_job(job_row)
        if job["status"] != "awaiting_finding":
            raise HTTPException(
                status_code=409,
                detail=f"scan job status is '{job['status']}', expected 'awaiting_finding'",
            )

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        prefix = f"EV-{date_str}-"
        existing = conn.execute(
            "SELECT evidence_id FROM evidence WHERE evidence_id LIKE %s", (f"{prefix}%",)
        ).fetchall()
        evidence_id = f"{prefix}{len(existing) + 1:04d}"

        raw_dir = _document_store_dir() / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_path = raw_dir / f"{evidence_id}.txt"
        raw_path.write_text(job["raw_output"] or "")
        sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()

        evidence = {
            "evidence_id": evidence_id,
            "device_id": job["device_id"],
            "test_id": job["test_id"],
            "tool": job["tool"],
            "tool_version": job["tool_version"],
            "command": job["command"],
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finding": finding,
            "observations": job["observations"] or {},
            "raw_output_path": f"document-store/raw/{evidence_id}.txt",
            "confidence": confidence,
            "sha256": sha256,
        }
        schema = _load_evidence_schema()
        jsonschema.validate(evidence, schema)

        _insert_evidence(conn, evidence)
        conn.execute(
            "UPDATE scan_jobs SET status = 'recorded', evidence_id = %s, updated_at = now() WHERE id = %s",
            (evidence_id, job_id),
        )
        conn.commit()
    finally:
        conn.close()
    return evidence


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


@app.post("/verdicts/recompute")
def recompute_verdicts():
    """Re-evaluate every control against every evidence record and insert any
    verdicts that don't already exist yet. Idempotent by design (checked via
    the evidence_id already present in an existing verdict's evidence_ids) so
    clicking this repeatedly is always safe, never a duplicate-key failure."""
    from policies.engine.policy_engine import evaluate

    conn = get_connection()
    try:
        evidence_rows = conn.execute(
            "SELECT evidence_id, device_id, test_id, tool, tool_version, command, "
            "timestamp, finding, observations, raw_output_path, confidence, sha256 "
            "FROM evidence ORDER BY evidence_id"
        ).fetchall()
        evidence_records = [_row_to_evidence(row) for row in evidence_rows]
        controls = _load_all_controls()

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        existing_count = conn.execute(
            "SELECT COUNT(*) FROM verdicts WHERE verdict_id LIKE %s", (f"VD-{date_str}-%",)
        ).fetchone()[0]
        seq = existing_count

        created = []
        for evidence in evidence_records:
            for control in controls:
                required_test_ids = {req["test_id"] for req in control["required_evidence"]}
                if evidence["test_id"] not in required_test_ids:
                    continue
                already_exists = conn.execute(
                    "SELECT 1 FROM verdicts WHERE control_id = %s AND evidence_ids ? %s",
                    (control["control_id"], evidence["evidence_id"]),
                ).fetchone()
                if already_exists:
                    continue
                seq += 1
                verdict_id = f"VD-{date_str}-{seq:04d}"
                verdict = evaluate(control, evidence, verdict_id=verdict_id)
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
                created.append(verdict)
        conn.commit()
    finally:
        conn.close()
    return {"created": len(created), "verdicts": created}


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


CONTROLS_DIR = Path(os.environ.get("CONTROLS_DIR", "/work/policies/controls"))

VERDICT_STATUSES = ("PASS", "FAIL", "PARTIAL", "INCONCLUSIVE")


def _load_all_controls() -> list[dict]:
    controls = []
    for path in sorted(CONTROLS_DIR.glob("*.yaml")):
        controls.append(yaml.safe_load(path.read_text()))
    return controls


@app.get("/controls")
def get_controls():
    return _load_all_controls()


@app.get("/controls/{control_id:path}/verdicts")
def get_control_verdicts(control_id: str) -> dict:
    # Reject any control_id that doesn't match the allowed pattern (alphanumeric and hyphen only)
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


@app.get("/controls/{control_id}")
def get_control_by_id(control_id: str):
    if not re.match(r"^[A-Za-z0-9\-]+$", control_id):
        raise HTTPException(status_code=400, detail="invalid control_id format")
    path = CONTROLS_DIR / f"{control_id}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail="control not found")
    return yaml.safe_load(path.read_text())


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
        return JSONResponse(
            status_code=400, content={"field": "body", "detail": "no updatable fields supplied"}
        )

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
