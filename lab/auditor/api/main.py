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
