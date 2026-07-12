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
from policies.catalog.scan_tests import SCAN_CATALOG, is_allowed


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
        {"test_id": test_id, "label": spec["label"], "allowed_devices": spec["allowed_devices"]}
        for test_id, spec in SCAN_CATALOG.items()
    ]


@app.post("/scan-jobs", status_code=201)
def post_scan_job(payload: dict):
    device_id = payload.get("device_id")
    test_id = payload.get("test_id")
    if not device_id or not test_id:
        raise HTTPException(status_code=422, detail="device_id and test_id are required")
    if not is_allowed(device_id, test_id):
        raise HTTPException(status_code=422, detail="unknown or disallowed device_id/test_id combination")

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
    conn = get_connection()
    try:
        query = f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE 1=1"
        params: list = []
        if status is not None:
            query += " AND status = %s"
            params.append(status)
        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_scan_job(row) for row in rows]


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
    if not re.match(r"^[A-Za-z0-9\-]+$", control_id):
        raise HTTPException(status_code=400, detail="invalid control_id format")
    path = CONTROLS_DIR / f"{control_id}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail="control not found")
    return yaml.safe_load(path.read_text())


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
