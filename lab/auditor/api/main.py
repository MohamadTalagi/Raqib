import hashlib
import json
import os
import re
import tarfile
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import jsonschema
import yaml
from fastapi import Body, FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

from db import get_connection
from device_validation import (
    TIERS,
    ValidationError,
    validate_device_id,
    validate_host,
    validate_port,
    validate_service_type,
)
from nca_routes import router as nca_router
from vuln_routes import router as vuln_router
from policies.catalog.scan_tests import (
    SCAN_CATALOG,
    is_applicable,
    is_firmware_test,
    is_network_discovery_test,
)
from report import build_report_model, render_report_html, render_report_pdf
from upload_utils import read_capped


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

app.include_router(nca_router)
app.include_router(vuln_router)


@app.exception_handler(ValidationError)
async def validation_error_handler(request, exc: ValidationError):
    return JSONResponse(
        status_code=400, content={"field": exc.field, "detail": exc.message}
    )

SCHEMA_PATH = Path("/work/policies/schema/evidence.schema.json")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/document-store/{subpath:path}")
def get_document_store_file(subpath: str):
    """Serves raw evidence artefacts for the dashboard's "view raw artefact"
    link (evidence.raw_output_path values look like
    "document-store/raw/EV-....txt"). Path-traversal-safe: refuses any
    resolved path that escapes the document-store root."""
    base = _document_store_dir().resolve()
    target = (base / subpath).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid path")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(target, media_type="text/plain")


def _load_evidence_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _insert_evidence(conn, evidence: dict) -> None:
    conn.execute(
        """
        INSERT INTO evidence (
            evidence_id, device_id, test_id, tool, tool_version, command,
            timestamp, finding, observations, raw_output_path, confidence, sha256,
            assessment_id, source_type, confidence_reason, error_state
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            evidence["evidence_id"], evidence["device_id"], evidence["test_id"],
            evidence["tool"], evidence["tool_version"], evidence["command"],
            evidence["timestamp"], evidence["finding"],
            json.dumps(evidence["observations"]), evidence["raw_output_path"],
            evidence["confidence"], evidence["sha256"],
            evidence.get("assessment_id"), evidence.get("source_type", "automated"),
            evidence.get("confidence_reason"), evidence.get("error_state"),
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


EVIDENCE_COLUMNS = (
    "evidence_id, device_id, test_id, tool, tool_version, command, timestamp, "
    "finding, observations, raw_output_path, confidence, sha256, "
    "assessment_id, source_type, confidence_reason, error_state"
)


def _row_to_evidence(row: tuple) -> dict:
    (evidence_id, device_id, test_id, tool, tool_version, command,
     timestamp, finding, observations, raw_output_path, confidence, sha256,
     assessment_id, source_type, confidence_reason, error_state) = row
    return {
        "evidence_id": evidence_id, "device_id": device_id, "test_id": test_id,
        "tool": tool, "tool_version": tool_version, "command": command,
        "timestamp": timestamp.isoformat(), "finding": finding,
        "observations": observations, "raw_output_path": raw_output_path,
        "confidence": confidence, "sha256": sha256,
        "assessment_id": assessment_id, "source_type": source_type,
        "confidence_reason": confidence_reason, "error_state": error_state,
    }


@app.get("/evidence")
def get_evidence(device_id: str | None = None, test_id: str | None = None):
    conn = get_connection()
    try:
        query = f"SELECT {EVIDENCE_COLUMNS} FROM evidence WHERE 1=1"
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
            f"SELECT {EVIDENCE_COLUMNS} FROM evidence WHERE evidence_id = %s",
            (evidence_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return _row_to_evidence(row)


SCAN_JOB_COLUMNS = (
    "id, device_id, test_id, status, tool, tool_version, command, "
    "raw_output, observations, error, evidence_id, assessment_id, created_at, updated_at"
)


def _row_to_scan_job(row: tuple) -> dict:
    (job_id, device_id, test_id, status, tool, tool_version, command,
     raw_output, observations, error, evidence_id, assessment_id, created_at, updated_at) = row
    return {
        "id": job_id, "device_id": device_id, "test_id": test_id, "status": status,
        "tool": tool, "tool_version": tool_version, "command": command,
        "raw_output": raw_output, "observations": observations, "error": error,
        "evidence_id": evidence_id, "assessment_id": assessment_id,
        "created_at": created_at.isoformat(), "updated_at": updated_at.isoformat(),
    }


@app.get("/scan-tests")
def get_scan_tests():
    return [
        {
            "test_id": test_id,
            "label": spec["label"],
            "category": spec["category"],
            "applicable_service_types": list(spec["applicable_service_types"]),
        }
        for test_id, spec in SCAN_CATALOG.items()
    ]


def _create_scan_job(conn, device_id: str, test_id: str, assessment_id: str | None = None) -> dict:
    """Validates device/test applicability and inserts one scan_jobs row.
    Shared by the standalone POST /scan-jobs endpoint (assessment_id=None,
    an ad-hoc single-test run) and POST /assessments (assessment_id set,
    tagging every job in the batch under one assessment)."""
    # Firmware tests inspect an uploaded archive keyed only by device_id, not
    # a live host:port - a device can have zero enabled services and still
    # have firmware uploaded, so this must short-circuit before the
    # device_services query below (which 400s on "no enabled service").
    if is_firmware_test(test_id):
        row = conn.execute(
            "SELECT firmware_sha256 FROM devices WHERE device_id = %s", (device_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=400, detail="device is not registered")
        if row[0] is None:
            raise HTTPException(status_code=400, detail="device has no firmware uploaded")
        insert_row = conn.execute(
            f"INSERT INTO scan_jobs (device_id, test_id, assessment_id) VALUES (%s, %s, %s) RETURNING {SCAN_JOB_COLUMNS}",
            (device_id, test_id, assessment_id),
        ).fetchone()
        return _row_to_scan_job(insert_row)

    # Network-discovery tests sweep the whole audit-network subnet rather
    # than one device's registered service, so they need only confirm the
    # device itself is registered (for the job's own audit trail) - no
    # enabled-service check, exactly like the firmware branch above.
    if is_network_discovery_test(test_id):
        row = conn.execute("SELECT 1 FROM devices WHERE device_id = %s", (device_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=400, detail="device is not registered")
        insert_row = conn.execute(
            f"INSERT INTO scan_jobs (device_id, test_id, assessment_id) VALUES (%s, %s, %s) RETURNING {SCAN_JOB_COLUMNS}",
            (device_id, test_id, assessment_id),
        ).fetchone()
        return _row_to_scan_job(insert_row)

    services = conn.execute(
        """
        SELECT d.host, s.service_type, s.port
        FROM devices d
        JOIN device_services s ON s.device_id = d.device_id
        WHERE d.device_id = %s AND s.enabled = true
        ORDER BY s.id
        """,
        (device_id,),
    ).fetchall()

    if not services:
        raise HTTPException(
            status_code=400, detail="device is not registered or has no enabled service"
        )

    # A device can carry several enabled services of different types (e.g.
    # mqtt + http); pick whichever enabled service the chosen test actually
    # applies to, rather than blindly taking the first row by insertion order.
    target = None
    for host, service_type, port in services:
        candidate = {
            "device_id": device_id, "host": host,
            "service_type": service_type, "port": port,
        }
        if is_applicable(candidate, test_id):
            target = candidate
            break

    if target is None:
        raise HTTPException(
            status_code=400, detail="test does not apply to this device's services"
        )

    row = conn.execute(
        f"INSERT INTO scan_jobs (device_id, test_id, assessment_id) VALUES (%s, %s, %s) RETURNING {SCAN_JOB_COLUMNS}",
        (device_id, test_id, assessment_id),
    ).fetchone()
    return _row_to_scan_job(row)


@app.post("/scan-jobs", status_code=201)
def post_scan_job(payload: dict):
    device_id = payload.get("device_id")
    test_id = payload.get("test_id")
    if not device_id or not test_id:
        raise HTTPException(status_code=422, detail="device_id and test_id are required")

    conn = get_connection()
    try:
        job = _create_scan_job(conn, device_id, test_id)
        conn.commit()
    finally:
        conn.close()
    return job


ASSESSMENT_COLUMNS = "id, device_id, status, policy_version, started_at, completed_at, error, created_at"


def _row_to_assessment(row: tuple) -> dict:
    id_, device_id, status, policy_version, started_at, completed_at, error, created_at = row
    return {
        "id": id_, "device_id": device_id, "status": status, "policy_version": policy_version,
        "started_at": started_at.isoformat() if started_at else None,
        "completed_at": completed_at.isoformat() if completed_at else None,
        "error": error, "created_at": created_at.isoformat(),
    }


def _next_assessment_id(conn) -> str:
    now = datetime.now(timezone.utc)
    prefix = f"ASMT-{now:%Y-%m-%d}-"
    existing = conn.execute("SELECT id FROM assessments WHERE id LIKE %s", (f"{prefix}%",)).fetchall()
    return f"{prefix}{len(existing) + 1:04d}"


@app.post("/assessments", status_code=201)
def create_assessment(payload: dict):
    """Groups a batch of scan_jobs (e.g. Run Scan's "Run selected") under one
    Assessment id with an aggregate status, per the brief's "Select device ->
    create assessment -> run collectors -> ..." workflow. Individual
    ad-hoc single-test runs still go through POST /scan-jobs directly and
    stay ungrouped (assessment_id NULL) - this endpoint is additive."""
    device_id = payload.get("device_id")
    test_ids = payload.get("test_ids")
    if not device_id or not isinstance(test_ids, list) or not test_ids:
        raise HTTPException(status_code=422, detail="device_id and a non-empty test_ids list are required")

    conn = get_connection()
    try:
        controls = _load_all_controls()
        relevant_versions = {
            control.get("version") for control in controls
            if any(req["test_id"] in test_ids for req in control["required_evidence"])
        }
        policy_version = sorted(v for v in relevant_versions if v)[-1] if relevant_versions else None

        assessment_id = _next_assessment_id(conn)
        conn.execute(
            "INSERT INTO assessments (id, device_id, policy_version) VALUES (%s, %s, %s)",
            (assessment_id, device_id, policy_version),
        )

        jobs = []
        errors = {}
        for test_id in test_ids:
            try:
                jobs.append(_create_scan_job(conn, device_id, test_id, assessment_id))
            except HTTPException as exc:
                errors[test_id] = exc.detail

        assessment_row = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
        conn.commit()
    finally:
        conn.close()

    assessment = _row_to_assessment(assessment_row)
    assessment["jobs"] = jobs
    assessment["errors"] = errors
    return assessment


@app.get("/assessments")
def list_assessments(device_id: str | None = None):
    conn = get_connection()
    try:
        query = f"SELECT {ASSESSMENT_COLUMNS} FROM assessments WHERE 1=1"
        params: list = []
        if device_id is not None:
            query += " AND device_id = %s"
            params.append(device_id)
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_assessment(row) for row in rows]


@app.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="assessment not found")
        job_rows = conn.execute(
            f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE assessment_id = %s ORDER BY id", (assessment_id,)
        ).fetchall()
    finally:
        conn.close()
    assessment = _row_to_assessment(row)
    assessment["jobs"] = [_row_to_scan_job(r) for r in job_rows]
    return assessment


@app.post("/assessments/{assessment_id}/cancel")
def cancel_assessment(assessment_id: str):
    """Only jobs still pending (not yet dispatched to the worker) are
    actually cancelled; a job already running is left to finish rather than
    killed mid-execution, since this worker has no process-group tracking to
    do that safely - see docs/known-limitations.md. Cancelled is terminal:
    _refresh_assessment_status() never recomputes it back to anything else."""
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="assessment not found")

        conn.execute(
            "UPDATE scan_jobs SET status = 'failed', error = 'cancelled before it started', updated_at = now() "
            "WHERE assessment_id = %s AND status = 'pending'",
            (assessment_id,),
        )
        conn.execute(
            "UPDATE assessments SET status = 'cancelled', completed_at = now() WHERE id = %s",
            (assessment_id,),
        )
        conn.commit()
        updated_row = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
    finally:
        conn.close()
    return _row_to_assessment(updated_row)


@app.get("/scan-jobs")
def get_scan_jobs(status: str | None = None):
    # The worker resolves each job's target (host/service_type/port) from the
    # current device state, rather than from columns on scan_jobs itself -
    # scan_jobs stays a pure audit row (device_id, test_id only), and a
    # deregistered device (or a device with no service the job's test
    # applies to) yields NULLs that resolve_target must reject rather than a
    # KeyError that would crash the poll loop.
    #
    # Service resolution must be test-aware: a device can carry several
    # enabled services of different types (e.g. mqtt + http), so we fetch
    # every enabled service per device and let is_applicable() - the same
    # rule post_scan_job uses - pick the one that matches each job's test_id.
    # This can't be expressed as a single correlated SQL join because
    # applicability is a Python-side rule (SCAN_CATALOG), not a DB column, so
    # the join is finished here instead of duplicating that rule in SQL.
    conn = get_connection()
    try:
        query = """
            SELECT j.id, j.device_id, j.test_id, j.status, j.tool, j.tool_version,
                   j.command, j.raw_output, j.observations, j.error, j.evidence_id,
                   j.assessment_id, j.created_at, j.updated_at,
                   d.host
            FROM scan_jobs j
            LEFT JOIN devices d ON d.device_id = j.device_id
            WHERE 1=1
        """
        params: list = []
        if status is not None:
            query += " AND j.status = %s"
            params.append(status)
        query += " ORDER BY j.created_at"
        job_rows = conn.execute(query, params).fetchall()

        device_ids = {row[1] for row in job_rows}
        services_by_device: dict[str, list[tuple[str, int]]] = {}
        if device_ids:
            service_rows = conn.execute(
                """
                SELECT device_id, service_type, port FROM device_services
                WHERE device_id = ANY(%s) AND enabled = true
                ORDER BY device_id, id
                """,
                (list(device_ids),),
            ).fetchall()
            for device_id, service_type, port in service_rows:
                services_by_device.setdefault(device_id, []).append((service_type, port))
    finally:
        conn.close()

    jobs = []
    for row in job_rows:
        job = _row_to_scan_job(row[:14])
        host = row[14]
        device_id, test_id = job["device_id"], job["test_id"]

        target = None
        if host is not None:
            for service_type, port in services_by_device.get(device_id, []):
                candidate = {
                    "device_id": device_id, "host": host,
                    "service_type": service_type, "port": port,
                }
                if is_applicable(candidate, test_id):
                    target = candidate
                    break

        job["host"] = target["host"] if target else None
        job["service_type"] = target["service_type"] if target else None
        job["port"] = target["port"] if target else None
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


def _refresh_assessment_status(conn, assessment_id: str | None) -> None:
    """Recomputes and persists one assessment's aggregate status from its
    current child scan_jobs, via the single pure function that owns this
    logic. Called every time a scan_job's status changes. A cancelled
    assessment is terminal and never recomputed back to anything else."""
    if assessment_id is None:
        return
    from policies.engine.assessment_status import compute_assessment_status

    current = conn.execute("SELECT status FROM assessments WHERE id = %s", (assessment_id,)).fetchone()
    if current is None or current[0] == "cancelled":
        return

    job_statuses = [
        row[0] for row in conn.execute(
            "SELECT status FROM scan_jobs WHERE assessment_id = %s", (assessment_id,)
        ).fetchall()
    ]
    new_status = compute_assessment_status(job_statuses)
    now = datetime.now(timezone.utc)
    completed_at = now if new_status in ("completed", "failed", "partially_completed") else None
    started_at = now if new_status != "queued" else None
    conn.execute(
        "UPDATE assessments SET status = %s, "
        "started_at = COALESCE(started_at, %s), completed_at = %s WHERE id = %s",
        (new_status, started_at, completed_at, assessment_id),
    )


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
        if row is not None:
            _refresh_assessment_status(conn, row[11])  # scan_jobs.assessment_id
        conn.commit()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="scan job not found")
    return _row_to_scan_job(row)


NETWORK_SCAN_COLUMNS = (
    "id, status, tool, tool_version, command, raw_output, observations, error, created_at, updated_at"
)


def _row_to_network_scan(row: tuple) -> dict:
    (scan_id, status, tool, tool_version, command, raw_output, observations, error, created_at, updated_at) = row
    return {
        "id": scan_id, "status": status, "tool": tool, "tool_version": tool_version,
        "command": command, "raw_output": raw_output, "observations": observations, "error": error,
        "created_at": created_at.isoformat(), "updated_at": updated_at.isoformat(),
    }


@app.post("/network-scans", status_code=201)
def create_network_scan():
    """Kicks off a subnet-wide discovery scan, independent of any registered
    device - the discovery-first onboarding path (scan the audit-network
    subnet, then decide which hosts are worth registering) rather than
    typing every device's host/services in by hand. auditor-api still never
    executes anything itself: this only inserts a pending row, and
    auditor-worker's poll_network_scans() (job_runner.py) is the sole
    executor, reusing TEST-NET-DISCOVERY's own command/parser from
    policies/catalog/scan_tests.py."""
    conn = get_connection()
    try:
        row = conn.execute(
            f"INSERT INTO network_scans DEFAULT VALUES RETURNING {NETWORK_SCAN_COLUMNS}"
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    return _row_to_network_scan(row)


@app.get("/network-scans")
def list_network_scans(status: str | None = None):
    conn = get_connection()
    try:
        query = f"SELECT {NETWORK_SCAN_COLUMNS} FROM network_scans WHERE 1=1"
        params: list = []
        if status is not None:
            query += " AND status = %s"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT 20"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_network_scan(row) for row in rows]


@app.get("/network-scans/{scan_id}")
def get_network_scan(scan_id: int):
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {NETWORK_SCAN_COLUMNS} FROM network_scans WHERE id = %s", (scan_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="network scan not found")
    return _row_to_network_scan(row)


NETWORK_SCAN_PATCHABLE_FIELDS = {"status", "tool", "tool_version", "command", "raw_output", "observations", "error"}


@app.patch("/network-scans/{scan_id}")
def patch_network_scan(scan_id: int, payload: dict):
    fields = {k: v for k, v in payload.items() if k in NETWORK_SCAN_PATCHABLE_FIELDS}
    if not fields:
        raise HTTPException(status_code=422, detail="no valid fields to update")

    set_clauses = []
    values: list = []
    for key, value in fields.items():
        set_clauses.append(f"{key} = %s")
        values.append(json.dumps(value) if key == "observations" else value)
    values.append(scan_id)

    conn = get_connection()
    try:
        row = conn.execute(
            f"UPDATE network_scans SET {', '.join(set_clauses)}, updated_at = now() "
            f"WHERE id = %s RETURNING {NETWORK_SCAN_COLUMNS}",
            values,
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="network scan not found")
    return _row_to_network_scan(row)


def _next_evidence_id(conn, now: datetime) -> str:
    date_str = now.strftime("%Y-%m-%d")
    prefix = f"EV-{date_str}-"
    existing = conn.execute(
        "SELECT evidence_id FROM evidence WHERE evidence_id LIKE %s", (f"{prefix}%",)
    ).fetchall()
    return f"{prefix}{len(existing) + 1:04d}"


def _write_raw_output(evidence_id: str, raw_output: str) -> tuple[str, str]:
    """Returns (raw_output_path, sha256)."""
    raw_dir = _document_store_dir() / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{evidence_id}.txt"
    raw_path.write_text(raw_output or "")
    sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    return f"document-store/raw/{evidence_id}.txt", sha256


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
        evidence_id = _next_evidence_id(conn, now)
        raw_output_path, sha256 = _write_raw_output(evidence_id, job["raw_output"])

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
            "raw_output_path": raw_output_path,
            "confidence": confidence,
            "sha256": sha256,
            "assessment_id": job["assessment_id"],
            "source_type": "automated",
        }
        schema = _load_evidence_schema()
        jsonschema.validate(evidence, schema)

        _insert_evidence(conn, evidence)
        conn.execute(
            "UPDATE scan_jobs SET status = 'recorded', evidence_id = %s, updated_at = now() WHERE id = %s",
            (evidence_id, job_id),
        )
        _refresh_assessment_status(conn, job["assessment_id"])
        conn.commit()
    finally:
        conn.close()
    return evidence


@app.post("/scan-jobs/{job_id}/record-failure", status_code=201)
def record_scan_job_failure(job_id: int, payload: dict):
    """Called by job_runner.py itself (no human input) the instant a
    collector fails to run at all - timeout, invalid target, or an execution
    exception. A failed collector must never produce silence: this
    deterministically records evidence flagged observations.collector_error,
    which policy_engine.evaluate() checks first and always scores as
    INCONCLUSIVE, never FAIL and never left unassessed."""
    error_detail = payload.get("error_detail")
    if not error_detail:
        raise HTTPException(status_code=422, detail="error_detail is required")

    conn = get_connection()
    try:
        job_row = conn.execute(
            f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE id = %s", (job_id,)
        ).fetchone()
        if job_row is None:
            raise HTTPException(status_code=404, detail="scan job not found")
        job = _row_to_scan_job(job_row)

        now = datetime.now(timezone.utc)
        evidence_id = _next_evidence_id(conn, now)
        raw_output_path, sha256 = _write_raw_output(evidence_id, job["raw_output"] or error_detail)

        evidence = {
            "evidence_id": evidence_id,
            "device_id": job["device_id"],
            "test_id": job["test_id"],
            "tool": job["tool"] or "unknown",
            "tool_version": job["tool_version"] or "unknown",
            "command": job["command"] or "",
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finding": f"Collector execution failed: {error_detail}",
            "observations": {"collector_error": True, "error_detail": error_detail},
            "raw_output_path": raw_output_path,
            "confidence": "low",
            "sha256": sha256,
            "assessment_id": job["assessment_id"],
            "source_type": "automated",
            "error_state": error_detail,
        }
        schema = _load_evidence_schema()
        jsonschema.validate(evidence, schema)

        _insert_evidence(conn, evidence)
        conn.execute(
            "UPDATE scan_jobs SET status = 'failed', error = %s, evidence_id = %s, updated_at = now() WHERE id = %s",
            (error_detail, evidence_id, job_id),
        )
        _refresh_assessment_status(conn, job["assessment_id"])
        conn.commit()
    finally:
        conn.close()
    return evidence


VERDICT_SCHEMA_PATH = Path("/work/policies/schema/verdict.schema.json")


def _load_verdict_schema() -> dict:
    return json.loads(VERDICT_SCHEMA_PATH.read_text())


VERDICT_COLUMNS = (
    "verdict_id, control_id, device_id, status, severity, evidence_ids, matched, "
    "reason, saudi_source, remediation, timestamp, assessment_id, policy_version, "
    "conflict_detected, conflict_reason"
)


def _insert_verdict_row(conn, verdict: dict) -> None:
    conn.execute(
        """
        INSERT INTO verdicts (
            verdict_id, control_id, device_id, status, severity,
            evidence_ids, matched, reason, saudi_source, remediation, timestamp,
            assessment_id, policy_version, conflict_detected, conflict_reason
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            verdict["verdict_id"], verdict["control_id"], verdict["device_id"],
            verdict["status"], verdict["severity"],
            json.dumps(verdict["evidence_ids"]), json.dumps(verdict.get("matched")),
            verdict["reason"], json.dumps(verdict["saudi_source"]),
            verdict["remediation"], verdict["timestamp"],
            verdict.get("assessment_id"), verdict.get("policy_version"),
            verdict.get("conflict_detected", False), verdict.get("conflict_reason"),
        ),
    )


@app.post("/verdicts", status_code=201)
def post_verdict(verdict: dict):
    schema = _load_verdict_schema()
    try:
        jsonschema.validate(verdict, schema)
    except jsonschema.ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc.message))

    conn = get_connection()
    try:
        _insert_verdict_row(conn, verdict)
        conn.commit()
    finally:
        conn.close()
    return verdict


def _row_to_verdict(row: tuple) -> dict:
    (verdict_id, control_id, device_id, status, severity, evidence_ids, matched,
     reason, saudi_source, remediation, timestamp, assessment_id, policy_version,
     conflict_detected, conflict_reason) = row
    return {
        "verdict_id": verdict_id, "control_id": control_id, "device_id": device_id,
        "status": status, "severity": severity, "evidence_ids": evidence_ids,
        "matched": matched, "reason": reason, "saudi_source": saudi_source,
        "remediation": remediation, "timestamp": timestamp.isoformat(),
        "assessment_id": assessment_id, "policy_version": policy_version,
        "conflict_detected": conflict_detected, "conflict_reason": conflict_reason,
    }


@app.get("/verdicts")
def get_verdicts(control_id: str | None = None, device_id: str | None = None):
    conn = get_connection()
    try:
        query = f"SELECT {VERDICT_COLUMNS} FROM verdicts WHERE 1=1"
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
    """Re-evaluate every control against every device's evidence and insert
    any verdicts that don't already exist yet. Idempotent by design (skips a
    (control, device) pair once its latest verdict already covers every
    currently-known evidence id for it) so clicking this repeatedly is always
    safe, never a duplicate-key failure - but produces a new verdict the
    moment genuinely new evidence arrives for a pair that already has one.

    Evidence for the same (device, control) pair is evaluated together, not
    independently per record, so conflicting evidence (e.g. documentation
    says TLS, a packet capture says plaintext) is detected and resolved by
    policies/engine/conflict.py rather than producing two contradictory
    verdicts. A device with registered services but none applicable to a
    control, and no evidence for it yet, gets a NOT_APPLICABLE verdict
    instead of staying silently unassessed."""
    from policies.engine.conflict import detect_conflict
    from policies.engine.policy_engine import build_not_applicable_verdict, evaluate, is_control_applicable

    conn = get_connection()
    try:
        evidence_rows = conn.execute(
            f"SELECT {EVIDENCE_COLUMNS} FROM evidence ORDER BY evidence_id"
        ).fetchall()
        evidence_records = [_row_to_evidence(row) for row in evidence_rows]
        controls = _load_all_controls()

        by_device: dict[str, list[dict]] = {}
        for evidence in evidence_records:
            by_device.setdefault(evidence["device_id"], []).append(evidence)

        service_rows = conn.execute(
            "SELECT device_id, service_type FROM device_services WHERE enabled = true"
        ).fetchall()
        services_by_device: dict[str, list[dict]] = {}
        for device_id, service_type in service_rows:
            services_by_device.setdefault(device_id, []).append({"service_type": service_type})

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        existing_count = conn.execute(
            "SELECT COUNT(*) FROM verdicts WHERE verdict_id LIKE %s", (f"VD-{date_str}-%",)
        ).fetchone()[0]
        seq = existing_count

        created = []
        for control in controls:
            control_id = control["control_id"]
            required_test_ids = {req["test_id"] for req in control["required_evidence"]}
            policy_version = control.get("version")

            for device_id, device_evidence in by_device.items():
                relevant = [e for e in device_evidence if e["test_id"] in required_test_ids]
                if not relevant:
                    continue
                relevant_ids = sorted(e["evidence_id"] for e in relevant)

                latest = conn.execute(
                    "SELECT evidence_ids FROM verdicts WHERE control_id = %s AND device_id = %s "
                    "ORDER BY verdict_id DESC LIMIT 1",
                    (control_id, device_id),
                ).fetchone()
                if latest and set(latest[0]) >= set(relevant_ids):
                    continue  # nothing new since the last verdict for this pair

                chosen, conflict_detected, conflict_reason = detect_conflict(control, relevant)
                seq += 1
                verdict = evaluate(
                    control, chosen, verdict_id=f"VD-{date_str}-{seq:04d}",
                    conflict_detected=conflict_detected, conflict_reason=conflict_reason,
                    all_evidence_ids=relevant_ids,
                )
                verdict["policy_version"] = policy_version
                _insert_verdict_row(conn, verdict)
                created.append(verdict)

            # NOT_APPLICABLE: a registered device whose services never match
            # any of this control's required tests, and that has no evidence
            # or verdict for it yet at all.
            for device_id, services in services_by_device.items():
                if any(e["test_id"] in required_test_ids for e in by_device.get(device_id, [])):
                    continue  # has real evidence - handled above
                already_has_verdict = conn.execute(
                    "SELECT 1 FROM verdicts WHERE control_id = %s AND device_id = %s", (control_id, device_id)
                ).fetchone()
                if already_has_verdict or is_control_applicable(control, services):
                    continue
                seq += 1
                verdict = build_not_applicable_verdict(
                    control, device_id, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    verdict_id=f"VD-{date_str}-{seq:04d}",
                )
                verdict["policy_version"] = policy_version
                _insert_verdict_row(conn, verdict)
                created.append(verdict)

        conn.commit()
    finally:
        conn.close()
    return {"created": len(created), "verdicts": created}


@app.post("/devices/{device_id}/controls/{control_id}/assess", status_code=201)
def assess_control_verdict(device_id: str, control_id: str, payload: dict | None = Body(default=None)):
    """Assess (compute + record) a verdict for one control against one device,
    on demand, from that device's already-collected evidence. Unlike
    /verdicts/recompute (which sweeps every pair and skips any that already
    has a covering verdict), this always produces a fresh verdict for the
    chosen pair - the auditor explicitly asked to assess it. The verdict
    *status* is still computed deterministically by the policy engine from
    real evidence, never hand-set (the project's 'AI-assisted, not
    AI-decided' rule).

    The optional body `{"severity": ...}` lets the auditor set the finding's
    severity (low/medium/high/critical) instead of defaulting to the control's
    catalogued severity - severity is a risk judgement about this device's
    context, not a fact the evidence decides, so the auditor gets the choice.
    Omitting it keeps the control's default.

    Returns 400 (with the required test ids) when the device has no evidence
    for the control yet and the control still applies - there is nothing to
    assess until the required scan has run."""
    from policies.engine.conflict import detect_conflict
    from policies.engine.policy_engine import build_not_applicable_verdict, evaluate, is_control_applicable

    severity_override = (payload or {}).get("severity")
    if severity_override is not None and severity_override not in ("low", "medium", "high", "critical"):
        raise HTTPException(
            status_code=400,
            detail="severity must be one of low, medium, high, critical",
        )

    conn = get_connection()
    try:
        if _device_row(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="device not found")

        control = next((c for c in _load_all_controls() if c["control_id"] == control_id), None)
        if control is None:
            raise HTTPException(status_code=404, detail="control not found")

        required_test_ids = {req["test_id"] for req in control["required_evidence"]}
        policy_version = control.get("version")

        evidence_rows = conn.execute(
            f"SELECT {EVIDENCE_COLUMNS} FROM evidence WHERE device_id = %s ORDER BY evidence_id",
            (device_id,),
        ).fetchall()
        device_evidence = [_row_to_evidence(row) for row in evidence_rows]
        relevant = [e for e in device_evidence if e["test_id"] in required_test_ids]

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        seq = conn.execute(
            "SELECT COUNT(*) FROM verdicts WHERE verdict_id LIKE %s", (f"VD-{date_str}-%",)
        ).fetchone()[0] + 1
        verdict_id = f"VD-{date_str}-{seq:04d}"

        if relevant:
            relevant_ids = sorted(e["evidence_id"] for e in relevant)
            chosen, conflict_detected, conflict_reason = detect_conflict(control, relevant)
            verdict = evaluate(
                control, chosen, verdict_id=verdict_id,
                conflict_detected=conflict_detected, conflict_reason=conflict_reason,
                all_evidence_ids=relevant_ids,
            )
        else:
            services = [
                {"service_type": st}
                for (st,) in conn.execute(
                    "SELECT service_type FROM device_services WHERE device_id = %s AND enabled = true",
                    (device_id,),
                ).fetchall()
            ]
            if is_control_applicable(control, services):
                # Applicable but no evidence collected yet - nothing to assess.
                # Only some required tests have an automated collector (a
                # SCAN_CATALOG entry). If none do (e.g. SA-IOT-001's
                # TEST-DEVICE-ID), telling the user to "run" them is
                # misleading - the control is manual-assessment-only.
                runnable = sorted(t for t in required_test_ids if t in SCAN_CATALOG)
                if runnable:
                    detail = (
                        "No evidence collected for this control yet — run "
                        f"{', '.join(runnable)} on this device first (Run Scan or the Scan Console), then assess."
                    )
                else:
                    detail = "This control has no automated collector, so it cannot be assessed from a scan."
                raise HTTPException(status_code=400, detail=detail)
            verdict = build_not_applicable_verdict(
                control, device_id, now.strftime("%Y-%m-%dT%H:%M:%SZ"), verdict_id=verdict_id,
            )

        verdict["policy_version"] = policy_version
        if severity_override is not None:
            verdict["severity"] = severity_override
        _insert_verdict_row(conn, verdict)
        conn.commit()
    finally:
        conn.close()
    return verdict


@app.get("/verdicts/{verdict_id}")
def get_verdict_by_id(verdict_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {VERDICT_COLUMNS} FROM verdicts WHERE verdict_id = %s",
            (verdict_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="verdict not found")
    return _row_to_verdict(row)


CONTROLS_DIR = Path(os.environ.get("CONTROLS_DIR", "/work/policies/controls"))

VERDICT_STATUSES = ("PASS", "FAIL", "PARTIAL", "INCONCLUSIVE", "NOT_APPLICABLE")


def _load_all_controls() -> list[dict]:
    controls = []
    for path in sorted(CONTROLS_DIR.glob("*.yaml")):
        controls.append(yaml.safe_load(path.read_text()))
    return controls


NCA_FRAMEWORK = "CGIoT-1:2024"


def _compliance_from_verdict_rows(rows: list[tuple]) -> dict:
    """Percent compliance against the mapped NCA CGIoT-1:2024 controls.

    rows: iterable of (control_id, status, timestamp). A control can carry
    more than one verdict over time (re-tested with new evidence) - only the
    most recent verdict per control_id counts, so re-testing a control
    doesn't dilute or double-count its contribution.

    Denominator is controls that have actually been assessed (have at least
    one verdict), not the full mapped-control catalog - an unassessed
    control is reported as missing coverage, never assumed to fail or pass.
    NOT_APPLICABLE verdicts are excluded entirely from both passing and
    tested - a control that can never apply to this device shouldn't drag
    its compliance percentage down, any more than an unassessed one would.
    """
    latest: dict[str, tuple[str, object]] = {}
    for control_id, status, timestamp in rows:
        if status == "NOT_APPLICABLE":
            continue
        if control_id not in latest or timestamp > latest[control_id][1]:
            latest[control_id] = (status, timestamp)

    tested = len(latest)
    passing = sum(1 for status, _ in latest.values() if status == "PASS")
    percentage = round(passing / tested * 100) if tested else None
    return {
        "framework": NCA_FRAMEWORK,
        "tested_controls": tested,
        "passing_controls": passing,
        "percentage": percentage,
    }


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


def _validate_display_name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("display_name", "display_name is required")
    return value.strip()


def _validate_device_payload(payload: dict) -> dict:
    device_id = validate_device_id(payload.get("device_id", ""))
    host = validate_host(payload.get("host", ""))

    tier = payload.get("tier", "unknown")
    if tier not in TIERS:
        raise ValidationError("tier", f"tier must be one of {', '.join(TIERS)}")

    display_name = _validate_display_name(payload.get("display_name", ""))

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
        "display_name": display_name,
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

    return {
        **device, "source": "manual", "services": services, "registered": True,
        "firmware_filename": None, "firmware_sha256": None, "firmware_uploaded_at": None,
    }


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
                COALESCE(v.verdict_count, 0),
                d.firmware_filename, d.firmware_sha256, d.firmware_uploaded_at
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
                    "firmware_filename": r[14],
                    "firmware_sha256": r[15],
                    "firmware_uploaded_at": r[16].isoformat() if r[16] else None,
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
               location, owner, notes, source, created_at, updated_at,
               firmware_filename, firmware_sha256, firmware_uploaded_at
        FROM devices WHERE device_id = %s
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    keys = (
        "device_id", "display_name", "description", "tier", "host", "vendor",
        "model", "location", "owner", "notes", "source", "created_at", "updated_at",
        "firmware_filename", "firmware_sha256", "firmware_uploaded_at",
    )
    device = dict(zip(keys, row))
    device["created_at"] = device["created_at"].isoformat()
    device["updated_at"] = device["updated_at"].isoformat()
    if device["firmware_uploaded_at"] is not None:
        device["firmware_uploaded_at"] = device["firmware_uploaded_at"].isoformat()
    return device


@app.get("/devices/{device_id}/report.pdf")
def get_device_report(device_id: str):
    # validate_device_id raises ValidationError, which the global handler turns
    # into a 400 {field, detail}. device_id is constrained to
    # ^[a-z0-9][a-z0-9-]{0,62}$, so it cannot inject quotes, slashes or newlines
    # into the Content-Disposition header below.
    validate_device_id(device_id)

    conn = get_connection()
    try:
        model = build_report_model(conn, device_id)
    finally:
        conn.close()

    if model is None:
        raise HTTPException(status_code=404, detail="device not found")

    pdf = render_report_pdf(model)
    filename = f"iotguard-{device_id}-{datetime.now(timezone.utc):%Y-%m-%d}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/devices/{device_id}/report.html")
def get_device_report_html(device_id: str):
    validate_device_id(device_id)
    conn = get_connection()
    try:
        model = build_report_model(conn, device_id)
    finally:
        conn.close()
    if model is None:
        raise HTTPException(status_code=404, detail="device not found")
    return Response(content=render_report_html(model), media_type="text/html")


@app.get("/devices/{device_id}/report.json")
def get_device_report_json(device_id: str):
    validate_device_id(device_id)
    conn = get_connection()
    try:
        model = build_report_model(conn, device_id)
    finally:
        conn.close()
    if model is None:
        raise HTTPException(status_code=404, detail="device not found")
    return model


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
        "compliance": _compliance_from_verdict_rows([(r[1], r[2], r[5]) for r in verdicts]),
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
        if "display_name" in updates:
            updates["display_name"] = _validate_display_name(updates["display_name"])
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


MAX_FIRMWARE_UPLOAD_BYTES = 20 * 1024 * 1024


def _firmware_path(device_id: str) -> Path:
    # Format-neutral name: the upload may be a .tar.gz or a .zip, and the
    # worker detects which by magic bytes (see archive_reader.py). The
    # original filename is preserved separately in devices.firmware_filename
    # for display only.
    return _document_store_dir() / "firmware" / f"{device_id}.archive"


def _unsafe_member(name: str) -> bool:
    # Defense in depth: the worker's firmware analysis never extracts to disk
    # (it reads member bytes in memory only), so a traversal path can't be
    # exploited today, but a future maintainer might add an extract call
    # without knowing that assumption. Rejected the same way for tar and zip.
    return name.startswith("/") or ".." in name.replace("\\", "/").split("/")


def _validate_firmware_archive(data: bytes) -> None:
    if data[:2] == b"\x1f\x8b":  # gzip magic -> .tar.gz / .tgz
        try:
            with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as tar:
                names = [m.name for m in tar.getmembers()]
        except tarfile.TarError:
            raise HTTPException(status_code=400, detail="not a valid .tar.gz archive")
    elif data[:4] == b"PK\x03\x04":  # zip local-file-header magic -> .zip
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                names = zf.namelist()
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="not a valid .zip archive")
    else:
        raise HTTPException(
            status_code=400,
            detail="firmware must be a valid .tar.gz or .zip archive",
        )
    for name in names:
        if _unsafe_member(name):
            raise HTTPException(status_code=400, detail="archive contains an unsafe member path")


@app.post("/devices/{device_id}/firmware", status_code=201)
async def upload_device_firmware(device_id: str, firmware: UploadFile) -> dict:
    validate_device_id(device_id)
    if not firmware.filename or not firmware.filename.lower().endswith((".tar.gz", ".tgz", ".zip")):
        raise HTTPException(status_code=400, detail="firmware must be a .tar.gz, .tgz, or .zip archive")

    conn = get_connection()
    try:
        if _device_row(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="device not found")

        data = await read_capped(firmware, MAX_FIRMWARE_UPLOAD_BYTES)
        _validate_firmware_archive(data)

        path = _firmware_path(device_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        sha256 = hashlib.sha256(data).hexdigest()
        now = datetime.now(timezone.utc)

        conn.execute(
            """
            UPDATE devices
            SET firmware_filename = %s, firmware_sha256 = %s, firmware_uploaded_at = %s
            WHERE device_id = %s
            """,
            (firmware.filename, sha256, now, device_id),
        )
        conn.commit()
        device = _device_row(conn, device_id)
        device["services"] = _services_for(conn, device_id)
    finally:
        conn.close()
    return device


@app.delete("/devices/{device_id}/firmware", status_code=204)
def delete_device_firmware(device_id: str) -> None:
    validate_device_id(device_id)
    conn = get_connection()
    try:
        if _device_row(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="device not found")
        conn.execute(
            """
            UPDATE devices
            SET firmware_filename = NULL, firmware_sha256 = NULL, firmware_uploaded_at = NULL
            WHERE device_id = %s
            """,
            (device_id,),
        )
        conn.commit()
    finally:
        conn.close()

    path = _firmware_path(device_id)
    path.unlink(missing_ok=True)


@app.get("/summary")
def get_summary():
    conn = get_connection()
    try:
        total_evidence = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        total_verdicts = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        status_rows = conn.execute(
            "SELECT status, COUNT(*) FROM verdicts GROUP BY status"
        ).fetchall()
        verdict_rows = conn.execute(
            "SELECT device_id, control_id, status, timestamp FROM verdicts"
        ).fetchall()
    finally:
        conn.close()
    verdicts_by_status = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0, "NOT_APPLICABLE": 0}
    for status, count in status_rows:
        verdicts_by_status[status] = count

    by_device: dict[str, list[tuple]] = {}
    for device_id, control_id, status, timestamp in verdict_rows:
        by_device.setdefault(device_id, []).append((control_id, status, timestamp))
    device_compliance = [
        {"device_id": device_id, **_compliance_from_verdict_rows(rows)}
        for device_id, rows in sorted(by_device.items())
    ]

    return {
        "total_evidence": total_evidence,
        "total_verdicts": total_verdicts,
        "verdicts_by_status": verdicts_by_status,
        "device_compliance": device_compliance,
    }
