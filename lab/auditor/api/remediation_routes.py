"""AI-Assisted Remediation (IoTGuard Stage 07) - a new APIRouter, same
pattern as nca_routes.py/risk_routes.py/vuln_routes.py.

This module owns everything database-facing: loading the real verdict or
NCA assessment row a finding refers to, assembling the normalized `finding`
dict remediation_engine.py's pure functions expect, and persisting the
generated blueprint (append-only, same supersede pattern
compliance_assessments already uses - a re-`generate` supersedes the prior
blueprint for that finding rather than overwriting it).

Never mutates verdicts.remediation or compliance_assessments.remediation -
both stay exactly as recorded; a generated blueprint is a separate,
additive artifact a human reviews before relying on it.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException

from db import get_connection
from remediation_engine import generate_remediation_blueprint

router = APIRouter(prefix="/remediation", tags=["remediation"])

CONTROLS_DIR = Path(os.environ.get("CONTROLS_DIR", "/work/policies/controls"))

BLUEPRINT_COLUMNS = (
    "id, finding_type, finding_id, device_id, control_id, model, root_cause, "
    "remediation_steps, priority, estimated_effort, caveats, generated_at, "
    "reviewed, reviewed_by, reviewed_at, superseded_by"
)

REMEDIABLE_SA_IOT_STATUSES = {"FAIL", "PARTIAL"}
REMEDIABLE_NCA_STATUSES = {"fail", "partial"}


def _row_to_blueprint(row) -> dict:
    (id_, finding_type, finding_id, device_id, control_id, model, root_cause,
     remediation_steps, priority, estimated_effort, caveats, generated_at,
     reviewed, reviewed_by, reviewed_at, superseded_by) = row
    return {
        "id": id_, "finding_type": finding_type, "finding_id": finding_id,
        "device_id": device_id, "control_id": control_id, "model": model,
        "root_cause": root_cause, "remediation_steps": remediation_steps,
        "priority": priority, "estimated_effort": estimated_effort, "caveats": caveats,
        "generated_at": generated_at.isoformat(),
        "reviewed": reviewed, "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at.isoformat() if reviewed_at else None,
        "superseded_by": superseded_by,
    }


def _next_id(conn) -> str:
    now = datetime.now(timezone.utc)
    prefix = f"RB-{now:%Y-%m-%d}-"
    existing = conn.execute(
        "SELECT id FROM remediation_blueprints WHERE id LIKE %s", (f"{prefix}%",)
    ).fetchall()
    return f"{prefix}{len(existing) + 1:04d}"


def _load_sa_iot_control(control_id: str) -> dict:
    path = CONTROLS_DIR / f"{control_id}.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def _device_label(conn, device_id: str | None) -> str | None:
    if device_id is None:
        return None
    row = conn.execute("SELECT display_name FROM devices WHERE device_id = %s", (device_id,)).fetchone()
    return f"{device_id} ({row[0]})" if row else device_id


def _sa_iot_finding(conn, verdict_id: str) -> dict | None:
    row = conn.execute(
        "SELECT verdict_id, control_id, device_id, status, severity, reason, remediation "
        "FROM verdicts WHERE verdict_id = %s",
        (verdict_id,),
    ).fetchone()
    if row is None:
        return None
    v_id, control_id, device_id, status, severity, reason, remediation = row
    control = _load_sa_iot_control(control_id)
    saudi = (control.get("saudi_source") or [{}])[0]
    return {
        "finding_type": "sa_iot_verdict",
        "finding_id": v_id,
        "device_id": device_id,
        "control_id": control_id,
        "control_title": control.get("title"),
        "requirement_text": saudi.get("clause"),
        "status": status,
        "severity": severity,
        "reason_or_finding": reason,
        "existing_remediation": remediation,
        "device_label": _device_label(conn, device_id),
    }


def _nca_finding(conn, assessment_id: str) -> dict | None:
    row = conn.execute(
        "SELECT id, control_id, device_id, status, severity, finding, remediation "
        "FROM compliance_assessments WHERE id = %s",
        (assessment_id,),
    ).fetchone()
    if row is None:
        return None
    a_id, control_id, device_id, status, severity, finding_text, remediation = row
    control_row = conn.execute(
        "SELECT canonical_requirement, implementation_summary FROM compliance_controls WHERE id = %s",
        (control_id,),
    ).fetchone()
    canonical_requirement, implementation_summary = control_row if control_row else (None, None)
    return {
        "finding_type": "nca_assessment",
        "finding_id": a_id,
        "device_id": device_id,
        "control_id": control_id,
        "control_title": implementation_summary,
        "requirement_text": canonical_requirement,
        "status": status,
        "severity": severity,
        "reason_or_finding": finding_text,
        "existing_remediation": remediation,
        "device_label": _device_label(conn, device_id),
    }


@router.post("/generate", status_code=201)
def generate_remediation(payload: dict):
    finding_type = payload.get("finding_type")
    finding_id = payload.get("finding_id")
    if finding_type not in ("sa_iot_verdict", "nca_assessment") or not finding_id:
        raise HTTPException(
            status_code=422,
            detail="finding_type ('sa_iot_verdict' or 'nca_assessment') and finding_id are required",
        )

    conn = get_connection()
    try:
        if finding_type == "sa_iot_verdict":
            finding = _sa_iot_finding(conn, finding_id)
            valid_statuses = REMEDIABLE_SA_IOT_STATUSES
        else:
            finding = _nca_finding(conn, finding_id)
            valid_statuses = REMEDIABLE_NCA_STATUSES

        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        if finding["status"] not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"finding status is '{finding['status']}' - remediation only applies "
                    "to a failing or partial finding"
                ),
            )

        blueprint = generate_remediation_blueprint(finding)
        if blueprint is None:
            raise HTTPException(
                status_code=502,
                detail="Gemini did not return a usable response - check GEMINI_API_KEY/quota and try again",
            )

        new_id = _next_id(conn)
        prior = conn.execute(
            "SELECT id FROM remediation_blueprints "
            "WHERE finding_type = %s AND finding_id = %s AND superseded_by IS NULL",
            (finding_type, finding_id),
        ).fetchone()

        row = conn.execute(
            f"""
            INSERT INTO remediation_blueprints (
                id, finding_type, finding_id, device_id, control_id, model,
                root_cause, remediation_steps, priority, estimated_effort, caveats
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {BLUEPRINT_COLUMNS}
            """,
            (
                new_id, finding_type, finding_id, finding["device_id"], finding["control_id"],
                os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
                blueprint["root_cause"], json.dumps(blueprint["remediation_steps"]),
                blueprint["priority"], blueprint["estimated_effort"], blueprint["caveats"],
            ),
        ).fetchone()

        if prior is not None:
            conn.execute(
                "UPDATE remediation_blueprints SET superseded_by = %s WHERE id = %s", (new_id, prior[0])
            )

        conn.commit()
    finally:
        conn.close()
    return _row_to_blueprint(row)


@router.get("/blueprints")
def list_blueprints(finding_type: str | None = None, finding_id: str | None = None, latest_only: bool = True):
    conn = get_connection()
    try:
        query = f"SELECT {BLUEPRINT_COLUMNS} FROM remediation_blueprints WHERE 1=1"
        params: list = []
        if finding_type is not None:
            query += " AND finding_type = %s"
            params.append(finding_type)
        if finding_id is not None:
            query += " AND finding_id = %s"
            params.append(finding_id)
        if latest_only:
            query += " AND superseded_by IS NULL"
        query += " ORDER BY generated_at DESC"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_blueprint(r) for r in rows]


@router.post("/blueprints/{blueprint_id}/review")
def review_blueprint(blueprint_id: str, payload: dict):
    reviewed_by = payload.get("reviewed_by")
    if not reviewed_by or not isinstance(reviewed_by, str) or not reviewed_by.strip():
        raise HTTPException(status_code=422, detail="reviewed_by (reviewer name) is required")

    conn = get_connection()
    try:
        row = conn.execute(
            f"""
            UPDATE remediation_blueprints SET reviewed = true, reviewed_by = %s, reviewed_at = now()
            WHERE id = %s RETURNING {BLUEPRINT_COLUMNS}
            """,
            (reviewed_by.strip(), blueprint_id),
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="remediation blueprint not found")
    return _row_to_blueprint(row)
