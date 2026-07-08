import json
import os
from pathlib import Path

import jsonschema
import yaml
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
