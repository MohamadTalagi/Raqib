""""Fully Automated Run" - a separate APIRouter (same pattern as
nca_routes.py/risk_routes.py/vuln_routes.py) mounted via app.include_router()
in main.py.

auditor-api never executes anything itself here either: this router only
ever inserts/reads/updates an automated_runs row. The real work - Discovery,
device registration, running every applicable scan test, recomputing
verdicts, auto-recording NCA assessments - is driven entirely by
auditor-worker's automated_run_runner.py, which is just another client of
this same API's existing endpoints (POST /network-scans, POST /scan-jobs,
POST /nca/assessments, ...) - the same security boundary every human click
already goes through, never bypassed.
"""

import json

from fastapi import APIRouter, HTTPException

from db import get_connection

router = APIRouter(prefix="/automation", tags=["automation"])

RUN_COLUMNS = "id, status, device_ids, current_stage, summary, error, created_at, started_at, completed_at"


def _row_to_run(row) -> dict:
    (id_, status, device_ids, current_stage, summary, error, created_at, started_at, completed_at) = row
    return {
        "id": id_,
        "status": status,
        "device_ids": device_ids,
        "current_stage": current_stage,
        "summary": summary,
        "error": error,
        "created_at": created_at.isoformat(),
        "started_at": started_at.isoformat() if started_at else None,
        "completed_at": completed_at.isoformat() if completed_at else None,
    }


@router.post("/runs", status_code=201)
def create_automated_run(payload: dict | None = None):
    """device_ids omitted or empty = the whole fleet, including a fresh
    Discovery sweep to find and register anything not yet known. Passing an
    explicit list scopes the run to those already-registered devices only
    (no Discovery step)."""
    device_ids = (payload or {}).get("device_ids") or None

    conn = get_connection()
    try:
        row = conn.execute(
            f"""
            INSERT INTO automated_runs (status, device_ids)
            VALUES ('pending', %s)
            RETURNING {RUN_COLUMNS}
            """,
            (json.dumps(device_ids) if device_ids else None,),
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    return _row_to_run(row)


@router.get("/runs")
def list_automated_runs(status: str | None = None):
    conn = get_connection()
    try:
        query = f"SELECT {RUN_COLUMNS} FROM automated_runs WHERE 1=1"
        params: list = []
        if status is not None:
            query += " AND status = %s"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT 20"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_run(r) for r in rows]


@router.get("/runs/{run_id}")
def get_automated_run(run_id: int):
    conn = get_connection()
    try:
        row = conn.execute(f"SELECT {RUN_COLUMNS} FROM automated_runs WHERE id = %s", (run_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="automated run not found")
    return _row_to_run(row)


RUN_PATCHABLE_FIELDS = {"status", "current_stage", "summary", "error"}


@router.patch("/runs/{run_id}")
def patch_automated_run(run_id: int, payload: dict):
    """Called only by automated_run_runner.py as it drives a run through its
    stages - never by the frontend directly (it only ever creates/reads/
    cancels). started_at/completed_at are set here, not by the caller, on
    the same first-running/first-terminal transitions job_runner.py's other
    poll loops already leave to the database layer."""
    fields = {k: v for k, v in payload.items() if k in RUN_PATCHABLE_FIELDS}
    if not fields:
        raise HTTPException(status_code=422, detail="no valid fields to update")

    conn = get_connection()
    try:
        current = conn.execute(
            "SELECT status, started_at FROM automated_runs WHERE id = %s", (run_id,)
        ).fetchone()
        if current is None:
            raise HTTPException(status_code=404, detail="automated run not found")
        current_status, started_at = current

        set_clauses = []
        values: list = []
        for key, value in fields.items():
            set_clauses.append(f"{key} = %s")
            values.append(json.dumps(value) if key == "summary" else value)

        if fields.get("status") == "running" and started_at is None:
            set_clauses.append("started_at = now()")
        if fields.get("status") in ("completed", "failed", "cancelled"):
            set_clauses.append("completed_at = now()")

        values.append(run_id)
        row = conn.execute(
            f"UPDATE automated_runs SET {', '.join(set_clauses)} WHERE id = %s RETURNING {RUN_COLUMNS}",
            values,
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    return _row_to_run(row)


@router.post("/runs/{run_id}/cancel")
def cancel_automated_run(run_id: int):
    """Only a run still pending/running can be cancelled - terminal states
    (completed/failed/cancelled) are left alone. The worker's own loop checks
    a run's status before starting each new step and stops if it's been
    cancelled - an already-dispatched scan job is left to finish rather than
    killed mid-execution, same documented limitation as
    POST /assessments/{id}/cancel."""
    conn = get_connection()
    try:
        row = conn.execute(f"SELECT {RUN_COLUMNS} FROM automated_runs WHERE id = %s", (run_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="automated run not found")
        current = _row_to_run(row)
        if current["status"] not in ("pending", "running"):
            raise HTTPException(
                status_code=409, detail=f"run status is '{current['status']}', can only cancel pending/running"
            )
        conn.execute(
            "UPDATE automated_runs SET status = 'cancelled', completed_at = now() WHERE id = %s",
            (run_id,),
        )
        conn.commit()
        updated = conn.execute(f"SELECT {RUN_COLUMNS} FROM automated_runs WHERE id = %s", (run_id,)).fetchone()
    finally:
        conn.close()
    return _row_to_run(updated)
