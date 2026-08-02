"""NCA CGIoT-1:2024 compliance module API - a separate APIRouter (not folded
into the already-1200-line main.py) mounted via app.include_router() in
main.py. Same conventions as the rest of the API: raw psycopg via
get_connection(), ValidationError -> 400 {field, detail} (handled by
main.py's global exception handler, which applies to every router mounted on
the same app), plain dict/list returns.

Every status/score/domain-count returned here comes from
policies/nca/evaluator.py's pure functions - this file only assembles rows
into the shape that module expects and never recomputes a status itself.

Reviewer-identity, not real authentication: this application has no login or
session concept anywhere. Every write that represents a judgment call
(creating or superseding an assessment, requesting or approving/rejecting an
exception) requires a free-text reviewer name recorded in the audit trail as
`assessed_by` / `requested_by` / `approved_by`. This is a deliberate, explicit
limitation - see docs/nca-compliance.md - not an oversight.
"""

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile
from fastapi.responses import Response

from db import get_connection
from device_validation import ValidationError
from nca_report import build_nca_executive_report_model, render_nca_executive_report_pdf
from policies.nca.compliance_text import (
    DISCLAIMER,
    METHODOLOGY_TEXT,
    PRODUCT_LABEL,
    READINESS_DEFINITIONS,
    STATUS_DEFINITIONS,
)
from policies.nca.evaluator import (
    device_overall_status,
    device_score,
    domain_summary,
    overall_classification,
)
from upload_utils import read_capped

router = APIRouter(prefix="/nca", tags=["nca"])

ORG_SCOPE_TYPES = ("organization", "mobile", "supplier", "cloud")
DEFAULT_ORG_SCOPE_ID = "default"  # single fixed organizational scope - see docs/nca-compliance.md

CONTROL_COLUMNS = (
    "id, framework, framework_version, domain_id, domain_name, subdomain_id, "
    "subdomain_name, guideline_id, canonical_requirement, implementation_summary, "
    "source_page, scope_type, assessment_type, required, severity, blocking, "
    "evidence_requirements, remediation_guidance, enabled"
)

ASSESSMENT_COLUMNS = (
    "id, control_id, device_id, organizational_scope_id, applicability, "
    "applicability_reason, status, severity, finding, test_method, test_identifier, "
    "raw_result_reference, evidence_ids, scanner_tool, scanner_tool_version, "
    "firmware_version_assessed, assessed_at, assessed_by, remediation, "
    "remediation_due_date, retest_status, retested_at, superseded_by, created_at, "
    "attested_role, attestation_confirmed, attestation_statement"
)

EXCEPTION_COLUMNS = (
    "id, control_id, device_id, organizational_scope_id, reason, compensating_control, "
    "requested_by, approved_by, approved_at, status, expires_at, created_at"
)

COMPLIANCE_EVIDENCE_COLUMNS = (
    "id, assessment_id, evidence_type, linked_evidence_id, original_filename, "
    "object_reference, sha256, collected_at, collected_by, source_system, "
    "retention_expires_at, access_control_note, created_at"
)


def _document_store_dir() -> Path:
    import os

    return Path(os.environ.get("DOCUMENT_STORE_DIR", "/work/document-store"))


def _row_to_control(row) -> dict:
    (id_, framework, framework_version, domain_id, domain_name, subdomain_id,
     subdomain_name, guideline_id, canonical_requirement, implementation_summary,
     source_page, scope_type, assessment_type, required, severity, blocking,
     evidence_requirements, remediation_guidance, enabled) = row
    return {
        "id": id_, "framework": framework, "framework_version": framework_version,
        "domain_id": domain_id, "domain_name": domain_name,
        "subdomain_id": subdomain_id, "subdomain_name": subdomain_name,
        "guideline_id": guideline_id, "canonical_requirement": canonical_requirement,
        "implementation_summary": implementation_summary, "source_page": source_page,
        "scope_type": scope_type, "assessment_type": assessment_type,
        "required": required, "severity": severity, "blocking": blocking,
        "evidence_requirements": evidence_requirements,
        "remediation_guidance": remediation_guidance, "enabled": enabled,
    }


def _row_to_assessment(row) -> dict:
    (id_, control_id, device_id, org_scope_id, applicability, applicability_reason,
     status, severity, finding, test_method, test_identifier, raw_result_reference,
     evidence_ids, scanner_tool, scanner_tool_version, firmware_version_assessed,
     assessed_at, assessed_by, remediation, remediation_due_date, retest_status,
     retested_at, superseded_by, created_at,
     attested_role, attestation_confirmed, attestation_statement) = row
    return {
        "id": id_, "control_id": control_id, "device_id": device_id,
        "organizational_scope_id": org_scope_id, "applicability": applicability,
        "applicability_reason": applicability_reason, "status": status,
        "severity": severity, "finding": finding, "test_method": test_method,
        "test_identifier": test_identifier, "raw_result_reference": raw_result_reference,
        "evidence_ids": evidence_ids, "scanner_tool": scanner_tool,
        "scanner_tool_version": scanner_tool_version,
        "firmware_version_assessed": firmware_version_assessed,
        "assessed_at": assessed_at.isoformat(), "assessed_by": assessed_by,
        "remediation": remediation,
        "remediation_due_date": remediation_due_date.isoformat() if remediation_due_date else None,
        "retest_status": retest_status,
        "retested_at": retested_at.isoformat() if retested_at else None,
        "superseded_by": superseded_by, "created_at": created_at.isoformat(),
        "attested_role": attested_role, "attestation_confirmed": attestation_confirmed,
        "attestation_statement": attestation_statement,
    }


def _row_to_exception(row) -> dict:
    (id_, control_id, device_id, org_scope_id, reason, compensating_control,
     requested_by, approved_by, approved_at, status, expires_at, created_at) = row
    return {
        "id": id_, "control_id": control_id, "device_id": device_id,
        "organizational_scope_id": org_scope_id, "reason": reason,
        "compensating_control": compensating_control, "requested_by": requested_by,
        "approved_by": approved_by,
        "approved_at": approved_at.isoformat() if approved_at else None,
        "status": status, "expires_at": expires_at.isoformat(),
        "created_at": created_at.isoformat(),
    }


def _row_to_compliance_evidence(row) -> dict:
    (id_, assessment_id, evidence_type, linked_evidence_id, original_filename,
     object_reference, sha256, collected_at, collected_by, source_system,
     retention_expires_at, access_control_note, created_at) = row
    return {
        "id": id_, "assessment_id": assessment_id, "evidence_type": evidence_type,
        "linked_evidence_id": linked_evidence_id, "original_filename": original_filename,
        "object_reference": object_reference, "sha256": sha256,
        "collected_at": collected_at.isoformat(), "collected_by": collected_by,
        "source_system": source_system,
        "retention_expires_at": retention_expires_at.isoformat() if retention_expires_at else None,
        "access_control_note": access_control_note, "created_at": created_at.isoformat(),
    }


def _next_id(conn, prefix: str, table: str, id_column: str) -> str:
    now = datetime.now(timezone.utc)
    full_prefix = f"{prefix}-{now:%Y-%m-%d}-"
    existing = conn.execute(
        f"SELECT {id_column} FROM {table} WHERE {id_column} LIKE %s", (f"{full_prefix}%",)
    ).fetchall()
    return f"{full_prefix}{len(existing) + 1:04d}"


def _expired_assessment_ids(conn, assessment_ids: list[str]) -> set[str]:
    if not assessment_ids:
        return set()
    rows = conn.execute(
        """
        SELECT DISTINCT assessment_id FROM compliance_evidence
        WHERE assessment_id = ANY(%s)
          AND retention_expires_at IS NOT NULL AND retention_expires_at < now()
        """,
        (assessment_ids,),
    ).fetchall()
    return {r[0] for r in rows}


def _active_exception_control_ids(conn, *, device_id: str | None, organizational_scope_id: str | None) -> set[str]:
    column = "device_id" if device_id else "organizational_scope_id"
    value = device_id or organizational_scope_id
    rows = conn.execute(
        f"""
        SELECT control_id FROM compliance_exceptions
        WHERE status = 'approved' AND expires_at > now() AND {column} = %s
        """,
        (value,),
    ).fetchall()
    return {r[0] for r in rows}


def _evaluator_rows_for_scope(conn, *, device_id: str | None = None, organizational_scope_id: str | None = None) -> list[dict]:
    """Assembles the per-control rows policies/nca/evaluator.py's pure
    functions expect, for one device or the organizational scope: the latest
    non-superseded assessment per enabled control (or a not_tested/applicable
    default when none exists yet), with evidence-expiry and active-exception
    already resolved."""
    scope_types = ("device",) if device_id else ORG_SCOPE_TYPES
    scope_column = "device_id" if device_id else "organizational_scope_id"
    scope_value = device_id or organizational_scope_id

    rows = conn.execute(
        f"""
        SELECT c.id, c.domain_id, c.required, c.severity, c.blocking, a.id, a.status, a.applicability
        FROM compliance_controls c
        LEFT JOIN LATERAL (
            SELECT id, status, applicability
            FROM compliance_assessments
            WHERE control_id = c.id AND superseded_by IS NULL AND {scope_column} = %s
            ORDER BY assessed_at DESC LIMIT 1
        ) a ON true
        WHERE c.enabled = true AND c.scope_type = ANY(%s)
        ORDER BY c.domain_id, c.subdomain_id, c.guideline_id
        """,
        (scope_value, list(scope_types)),
    ).fetchall()

    assessment_ids = [r[5] for r in rows if r[5] is not None]
    expired_ids = _expired_assessment_ids(conn, assessment_ids)
    exception_control_ids = _active_exception_control_ids(
        conn, device_id=device_id, organizational_scope_id=organizational_scope_id
    )

    return [
        {
            "control_id": control_id,
            "domain_id": domain_id,
            "required": required,
            "severity": severity,
            "blocking": blocking,
            "status": status or "not_tested",
            "applicability": applicability or "applicable",
            "evidence_expired": assessment_id in expired_ids,
            "exception_active": control_id in exception_control_ids,
        }
        for control_id, domain_id, required, severity, blocking, assessment_id, status, applicability in rows
    ]


# ---------------------------------------------------------------------------
# Summary / domains
# ---------------------------------------------------------------------------


@router.get("/summary")
def get_nca_summary():
    conn = get_connection()
    try:
        device_ids = [r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id").fetchall()]
        counts = {"pass": 0, "partial": 0, "fail": 0, "not_tested": 0}
        for device_id in device_ids:
            rows = _evaluator_rows_for_scope(conn, device_id=device_id)
            counts[device_overall_status(rows)] += 1

        last_assessment = conn.execute("SELECT MAX(assessed_at) FROM compliance_assessments").fetchone()[0]
        total_controls = conn.execute(
            "SELECT COUNT(*) FROM compliance_controls WHERE enabled = true"
        ).fetchone()[0]
    finally:
        conn.close()

    assessed = counts["pass"] + counts["partial"] + counts["fail"]
    overall_percentage = round(counts["pass"] / assessed * 100) if assessed else None

    return {
        "product_label": PRODUCT_LABEL,
        "framework": "NCA-CGIoT",
        "framework_version": "1:2024",
        "disclaimer": DISCLAIMER,
        "total_devices": len(device_ids),
        "device_counts": counts,
        "overall_pass_percentage": overall_percentage,
        "total_controls": total_controls,
        "last_assessment_at": last_assessment.isoformat() if last_assessment else None,
        "status_definitions": STATUS_DEFINITIONS,
        "readiness_definitions": READINESS_DEFINITIONS,
    }


@router.get("/domains")
def get_nca_domains():
    conn = get_connection()
    try:
        device_ids = [r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id").fetchall()]
        all_rows = []
        for device_id in device_ids:
            all_rows.extend(_evaluator_rows_for_scope(conn, device_id=device_id))
    finally:
        conn.close()
    return domain_summary(all_rows)


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@router.get("/controls")
def list_controls(
    domain_id: str | None = None,
    subdomain_id: str | None = None,
    scope_type: str | None = None,
    assessment_type: str | None = None,
    enabled: bool | None = None,
):
    conn = get_connection()
    try:
        query = f"SELECT {CONTROL_COLUMNS} FROM compliance_controls WHERE 1=1"
        params: list = []
        if domain_id is not None:
            query += " AND domain_id = %s"
            params.append(domain_id)
        if subdomain_id is not None:
            query += " AND subdomain_id = %s"
            params.append(subdomain_id)
        if scope_type is not None:
            query += " AND scope_type = %s"
            params.append(scope_type)
        if assessment_type is not None:
            query += " AND assessment_type = %s"
            params.append(assessment_type)
        if enabled is not None:
            query += " AND enabled = %s"
            params.append(enabled)
        query += " ORDER BY domain_id, subdomain_id, guideline_id"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_control(r) for r in rows]


@router.get("/controls/{control_id}")
def get_control(control_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            f"SELECT {CONTROL_COLUMNS} FROM compliance_controls WHERE id = %s", (control_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="control not found")
        control = _row_to_control(row)

        assessment_rows = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM compliance_assessments WHERE control_id = %s ORDER BY assessed_at DESC",
            (control_id,),
        ).fetchall()
        assessments = [_row_to_assessment(r) for r in assessment_rows]

        assessment_ids = [a["id"] for a in assessments]
        audit_events = []
        if assessment_ids:
            audit_rows = conn.execute(
                """
                SELECT id, event_type, entity_type, entity_id, before_value, after_value,
                       actor, reason, occurred_at
                FROM compliance_audit_events
                WHERE entity_type = 'compliance_assessment' AND entity_id = ANY(%s)
                ORDER BY occurred_at DESC
                """,
                (assessment_ids,),
            ).fetchall()
            audit_events = [
                {
                    "id": r[0], "event_type": r[1], "entity_type": r[2], "entity_id": r[3],
                    "before_value": r[4], "after_value": r[5], "actor": r[6],
                    "reason": r[7], "occurred_at": r[8].isoformat(),
                }
                for r in audit_rows
            ]
    finally:
        conn.close()
    return {"control": control, "assessments": assessments, "audit_events": audit_events}


@router.get("/controls/{control_id}/checklist")
def get_control_checklist(control_id: str):
    """The guided questions for this control, or 404 if it has none yet -
    a real, expected state for most of the 62 organizational guidelines
    until policies/nca/seed_checklists.py authors one. The frontend must
    treat 404 as "fall back to the plain assessment dialog", not an error."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT control_id, questions, suggestion_rule FROM compliance_control_checklists WHERE control_id = %s",
            (control_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="this control has no guided checklist yet")
    return {"control_id": row[0], "questions": row[1], "suggestion_rule": row[2]}


@router.post("/controls/{control_id}/checklist/evaluate")
def evaluate_control_checklist(control_id: str, payload: dict):
    """Read-only, like GET /nca/devices/{id}/suggestions - computes a
    suggested status from submitted answers but never writes anything.
    The frontend calls this live as the auditor fills in the checklist,
    then feeds the result into the same RecordAssessmentDialog a device
    suggestion already pre-fills."""
    from policies.nca.checklists import evaluate_checklist

    answers = payload.get("answers")
    if not isinstance(answers, dict):
        raise ValidationError("answers", "answers must be an object of question key -> answer value")

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT suggestion_rule FROM compliance_control_checklists WHERE control_id = %s",
            (control_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="this control has no guided checklist yet")

    suggested_status = evaluate_checklist(row[0], answers)
    return {"control_id": control_id, "suggested_status": suggested_status}


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@router.get("/devices")
def list_nca_devices(status: str | None = None):
    conn = get_connection()
    try:
        device_rows = conn.execute(
            "SELECT device_id, display_name, tier, vendor, model FROM devices ORDER BY device_id"
        ).fetchall()
        result = []
        for device_id, display_name, tier, vendor, model in device_rows:
            rows = _evaluator_rows_for_scope(conn, device_id=device_id)
            overall = device_overall_status(rows)
            if status is not None and overall != status:
                continue
            result.append(
                {
                    "device_id": device_id,
                    "display_name": display_name,
                    "tier": tier,
                    "vendor": vendor,
                    "model": model,
                    "overall_status": overall,
                    "score": device_score(rows),
                    "domain_summary": domain_summary(rows),
                    "readiness_classification": overall_classification(rows)["classification"],
                }
            )
    finally:
        conn.close()
    return result


@router.get("/devices/{device_id}")
def get_nca_device_detail(device_id: str):
    conn = get_connection()
    try:
        device_row = conn.execute(
            "SELECT device_id, display_name, tier FROM devices WHERE device_id = %s", (device_id,)
        ).fetchone()
        if device_row is None:
            raise HTTPException(status_code=404, detail="device not found")

        control_rows = conn.execute(
            f"""
            SELECT {CONTROL_COLUMNS} FROM compliance_controls
            WHERE enabled = true AND scope_type = 'device'
            ORDER BY domain_id, subdomain_id, guideline_id
            """
        ).fetchall()
        controls = [_row_to_control(r) for r in control_rows]

        assessment_rows = conn.execute(
            f"""
            SELECT DISTINCT ON (control_id) {ASSESSMENT_COLUMNS}
            FROM compliance_assessments
            WHERE device_id = %s AND superseded_by IS NULL
            ORDER BY control_id, assessed_at DESC
            """,
            (device_id,),
        ).fetchall()
        latest_by_control = {r[1]: _row_to_assessment(r) for r in assessment_rows}

        evaluator_rows = _evaluator_rows_for_scope(conn, device_id=device_id)

        exception_rows = conn.execute(
            f"SELECT {EXCEPTION_COLUMNS} FROM compliance_exceptions WHERE device_id = %s ORDER BY created_at DESC",
            (device_id,),
        ).fetchall()
        exceptions = [_row_to_exception(r) for r in exception_rows]
    finally:
        conn.close()

    return {
        "device_id": device_row[0],
        "display_name": device_row[1],
        "tier": device_row[2],
        "overall_status": device_overall_status(evaluator_rows),
        "score": device_score(evaluator_rows),
        "domain_summary": domain_summary(evaluator_rows),
        "readiness": overall_classification(evaluator_rows),
        "controls": [
            {"control": control, "assessment": latest_by_control.get(control["id"])}
            for control in controls
        ],
        "exceptions": exceptions,
    }


@router.get("/devices/{device_id}/suggestions")
def get_nca_device_suggestions(device_id: str):
    """Auto-verdict hints for the per-device assessment workspace: for each
    device-scope control that this device's automated scan evidence maps to,
    a suggested status the auditor confirms or overrides in one click.

    Only ever *suggests* - never records an assessment (that stays a human's
    call, "AI-assisted, not AI-decided"). A suggestion is emitted only when a
    finding mapping actually matches real evidence for this device; the
    absence of a matching mapping is never reported as a pass, because a test
    may simply not have been run. verdict_hint (from the mapping) decides
    fail vs review_required."""
    from policies.nca.finding_mappings import map_evidence_to_mappings

    conn = get_connection()
    try:
        device_row = conn.execute(
            "SELECT device_id FROM devices WHERE device_id = %s", (device_id,)
        ).fetchone()
        if device_row is None:
            raise HTTPException(status_code=404, detail="device not found")

        mapping_rows = conn.execute(
            "SELECT finding_key, description, control_id, match_rule, "
            "manufacturer_principle, enabled, verdict_hint FROM compliance_finding_mappings"
        ).fetchall()
        mappings = [
            {
                "finding_key": r[0], "description": r[1], "control_id": r[2],
                "match_rule": r[3], "manufacturer_principle": r[4],
                "enabled": r[5], "verdict_hint": r[6],
            }
            for r in mapping_rows
        ]

        evidence_rows = conn.execute(
            "SELECT evidence_id, test_id, observations FROM evidence "
            "WHERE device_id = %s ORDER BY evidence_id",
            (device_id,),
        ).fetchall()
    finally:
        conn.close()

    # Accumulate per control_id across every matching (evidence, mapping) pair.
    by_control: dict[str, dict] = {}
    for evidence_id, test_id, observations in evidence_rows:
        evidence = {"test_id": test_id, "observations": observations}
        for mapping in map_evidence_to_mappings(evidence, mappings):
            control_id = mapping["control_id"]
            acc = by_control.setdefault(
                control_id,
                {
                    "control_id": control_id,
                    "suggested_status": "review_required",
                    "evidence_ids": [],
                    "test_ids": [],
                    "reasons": [],
                },
            )
            # Any failing signal dominates a review-only one.
            if mapping["verdict_hint"] == "fail":
                acc["suggested_status"] = "fail"
            if evidence_id not in acc["evidence_ids"]:
                acc["evidence_ids"].append(evidence_id)
            if test_id and test_id not in acc["test_ids"]:
                acc["test_ids"].append(test_id)
            reason = f"{mapping['description']} (evidence {evidence_id})"
            if reason not in acc["reasons"]:
                acc["reasons"].append(reason)

    return {"device_id": device_id, "suggestions": by_control}


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


def _validate_assessment_payload(payload: dict) -> dict:
    control_id = payload.get("control_id")
    if not control_id or not isinstance(control_id, str):
        raise ValidationError("control_id", "control_id is required")

    device_id = payload.get("device_id")
    organizational_scope_id = payload.get("organizational_scope_id")
    if bool(device_id) == bool(organizational_scope_id):
        raise ValidationError(
            "device_id", "exactly one of device_id or organizational_scope_id is required"
        )

    applicability = payload.get("applicability", "applicable")
    if applicability not in ("applicable", "not_applicable"):
        raise ValidationError("applicability", "applicability must be 'applicable' or 'not_applicable'")
    applicability_reason = payload.get("applicability_reason")
    if applicability == "not_applicable" and not applicability_reason:
        raise ValidationError(
            "applicability_reason",
            "applicability_reason is required when applicability is not_applicable",
        )

    status = payload.get("status")
    if status not in ("pass", "partial", "fail", "not_tested", "review_required"):
        raise ValidationError(
            "status", "status must be one of pass, partial, fail, not_tested, review_required"
        )

    severity = payload.get("severity")
    if severity not in ("low", "medium", "high", "critical"):
        raise ValidationError("severity", "severity must be one of low, medium, high, critical")

    test_method = payload.get("test_method")
    if test_method not in ("automated", "manual", "hybrid"):
        raise ValidationError("test_method", "test_method must be one of automated, manual, hybrid")

    assessed_by = payload.get("assessed_by")
    if not assessed_by or not isinstance(assessed_by, str) or not assessed_by.strip():
        raise ValidationError("assessed_by", "assessed_by (reviewer name) is required")

    # Formal sign-off, required on every REAL verdict (compliance_assessments'
    # own attestation_confirmed CHECK constraint enforces this too - this is
    # the friendlier 400 a caller sees before ever reaching that constraint).
    # Never optional for pass/partial/fail/review_required: a human must
    # explicitly certify they reviewed the evidence/reasons before anything
    # is recorded, matching this project's "AI-assisted, not AI-decided"
    # rule at its strongest point yet. `not_tested` is the one exception -
    # it is the system's own "nothing has been asserted yet" placeholder
    # (see /assessments/recompute), not a human verdict, so there is
    # nothing to attest to.
    attestation_confirmed = payload.get("attestation_confirmed", False)
    attestation_statement = payload.get("attestation_statement")
    attested_role = payload.get("attested_role")
    if status != "not_tested":
        if attestation_confirmed is not True:
            raise ValidationError(
                "attestation_confirmed",
                "attestation_confirmed must be true - the recording auditor must certify "
                "they reviewed the evidence/reasons before this assessment can be saved",
            )
        if not attestation_statement or not isinstance(attestation_statement, str):
            raise ValidationError(
                "attestation_statement", "attestation_statement (the certify text shown at signing) is required"
            )
        if not attested_role or not isinstance(attested_role, str) or not attested_role.strip():
            raise ValidationError("attested_role", "attested_role is required")
        attested_role = attested_role.strip()

    return {
        "control_id": control_id,
        "device_id": device_id,
        "organizational_scope_id": organizational_scope_id,
        "applicability": applicability,
        "applicability_reason": applicability_reason,
        "status": status,
        "severity": severity,
        "finding": payload.get("finding"),
        "test_method": test_method,
        "test_identifier": payload.get("test_identifier"),
        "raw_result_reference": payload.get("raw_result_reference"),
        "evidence_ids": payload.get("evidence_ids") or [],
        "scanner_tool": payload.get("scanner_tool"),
        "scanner_tool_version": payload.get("scanner_tool_version"),
        "firmware_version_assessed": payload.get("firmware_version_assessed"),
        "assessed_by": assessed_by.strip(),
        "remediation": payload.get("remediation"),
        "remediation_due_date": payload.get("remediation_due_date"),
        "attested_role": attested_role,
        "attestation_confirmed": status != "not_tested",
        "attestation_statement": attestation_statement,
    }


def _insert_assessment(conn, data: dict, *, event_type: str, reason: str | None) -> dict:
    control_row = conn.execute("SELECT 1 FROM compliance_controls WHERE id = %s", (data["control_id"],)).fetchone()
    if control_row is None:
        raise HTTPException(status_code=404, detail="control not found")

    scope_column = "device_id" if data["device_id"] else "organizational_scope_id"
    scope_value = data["device_id"] or data["organizational_scope_id"]

    prior_row = conn.execute(
        f"""
        SELECT {ASSESSMENT_COLUMNS} FROM compliance_assessments
        WHERE control_id = %s AND {scope_column} = %s AND superseded_by IS NULL
        """,
        (data["control_id"], scope_value),
    ).fetchone()
    before_value = _row_to_assessment(prior_row) if prior_row is not None else None

    new_id = _next_id(conn, "ASM", "compliance_assessments", "id")
    row = conn.execute(
        f"""
        INSERT INTO compliance_assessments (
            id, control_id, device_id, organizational_scope_id, applicability,
            applicability_reason, status, severity, finding, test_method,
            test_identifier, raw_result_reference, evidence_ids, scanner_tool,
            scanner_tool_version, firmware_version_assessed, assessed_by,
            remediation, remediation_due_date, retest_status, retested_at,
            attested_role, attestation_confirmed, attestation_statement
        ) VALUES (
            %(id)s, %(control_id)s, %(device_id)s, %(organizational_scope_id)s,
            %(applicability)s, %(applicability_reason)s, %(status)s, %(severity)s,
            %(finding)s, %(test_method)s, %(test_identifier)s, %(raw_result_reference)s,
            %(evidence_ids)s, %(scanner_tool)s, %(scanner_tool_version)s,
            %(firmware_version_assessed)s, %(assessed_by)s, %(remediation)s,
            %(remediation_due_date)s, %(retest_status)s, %(retested_at)s,
            %(attested_role)s, %(attestation_confirmed)s, %(attestation_statement)s
        ) RETURNING {ASSESSMENT_COLUMNS}
        """,
        {
            **data,
            "id": new_id,
            "evidence_ids": json.dumps(data["evidence_ids"]),
            "retest_status": data.get("retest_status", "not_requested"),
            "retested_at": data.get("retested_at"),
        },
    ).fetchone()
    new_assessment = _row_to_assessment(row)

    if prior_row is not None:
        conn.execute(
            "UPDATE compliance_assessments SET superseded_by = %s WHERE id = %s",
            (new_id, prior_row[0]),
        )
        conn.execute(
            """
            INSERT INTO compliance_audit_events (event_type, entity_type, entity_id, before_value, after_value, actor, reason)
            VALUES (%s, 'compliance_assessment', %s, %s, %s, %s, %s)
            """,
            (event_type, new_id, json.dumps(before_value), json.dumps(new_assessment), data["assessed_by"], reason),
        )
    conn.commit()
    return new_assessment


@router.post("/assessments", status_code=201)
def create_assessment(payload: dict):
    data = _validate_assessment_payload(payload)
    conn = get_connection()
    try:
        return _insert_assessment(conn, data, event_type="assessment_superseded", reason=payload.get("reason"))
    finally:
        conn.close()


@router.post("/assessments/recompute")
def recompute_assessments():
    """Surfaces automated-evidence-to-control links as pending, not_tested
    placeholder assessments - never a verdict. Idempotent: skips any
    (control, device) pair that already has a non-superseded assessment, so a
    human's manual finding is never silently overwritten by a re-run. Mirrors
    /verdicts/recompute's insert-if-missing pattern."""
    from policies.nca.finding_mappings import map_evidence_to_controls

    conn = get_connection()
    try:
        mapping_rows = conn.execute(
            "SELECT finding_key, description, control_id, match_rule, manufacturer_principle, enabled "
            "FROM compliance_finding_mappings"
        ).fetchall()
        mappings = [
            {
                "finding_key": r[0], "description": r[1], "control_id": r[2],
                "match_rule": r[3], "manufacturer_principle": r[4], "enabled": r[5],
            }
            for r in mapping_rows
        ]

        evidence_rows = conn.execute(
            "SELECT evidence_id, device_id, test_id, tool, tool_version, raw_output_path, observations "
            "FROM evidence ORDER BY evidence_id"
        ).fetchall()

        created = []
        for evidence_id, device_id, test_id, tool, tool_version, raw_output_path, observations in evidence_rows:
            evidence = {"test_id": test_id, "observations": observations}
            for control_id in map_evidence_to_controls(evidence, mappings):
                existing = conn.execute(
                    """
                    SELECT 1 FROM compliance_assessments
                    WHERE control_id = %s AND device_id = %s AND superseded_by IS NULL
                    """,
                    (control_id, device_id),
                ).fetchone()
                if existing:
                    continue
                new_id = _next_id(conn, "ASM", "compliance_assessments", "id")
                finding = (
                    f"Automated mapping surfaced evidence {evidence_id} ({test_id}) as "
                    "relevant to this control; pending manual review."
                )
                conn.execute(
                    """
                    INSERT INTO compliance_assessments (
                        id, control_id, device_id, applicability, status, severity,
                        finding, test_method, test_identifier, raw_result_reference,
                        evidence_ids, scanner_tool, scanner_tool_version, assessed_by,
                        retest_status
                    ) VALUES (
                        %s, %s, %s, 'applicable', 'not_tested',
                        (SELECT severity FROM compliance_controls WHERE id = %s),
                        %s, 'automated', %s, %s, %s, %s, %s, 'system:recompute', 'not_requested'
                    )
                    """,
                    (
                        new_id, control_id, device_id, control_id,
                        finding, test_id, raw_output_path, json.dumps([]), tool, tool_version,
                    ),
                )
                created.append(new_id)
        conn.commit()
    finally:
        conn.close()
    return {"created": len(created), "assessment_ids": created}


@router.post("/assessments/{assessment_id}/retest", status_code=201)
def retest_assessment(assessment_id: str, payload: dict):
    conn = get_connection()
    try:
        prior_row = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM compliance_assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
        if prior_row is None:
            raise HTTPException(status_code=404, detail="assessment not found")
        prior = _row_to_assessment(prior_row)

        merged = {
            "control_id": prior["control_id"],
            "device_id": prior["device_id"],
            "organizational_scope_id": prior["organizational_scope_id"],
            "applicability": prior["applicability"],
            "applicability_reason": prior["applicability_reason"],
            "severity": prior["severity"],
            "test_method": prior["test_method"],
            **payload,
        }
        data = _validate_assessment_payload(merged)
        data["retest_status"] = "passed" if data["status"] == "pass" else "failed"
        data["retested_at"] = datetime.now(timezone.utc)
        return _insert_assessment(conn, data, event_type="assessment_retested", reason=payload.get("reason", "retest"))
    finally:
        conn.close()


@router.post("/assessments/{assessment_id}/override", status_code=201)
def override_assessment(assessment_id: str, payload: dict):
    """Lets an authorized auditor override a control's automated or
    previously-recorded result. Never overwrites history: this inserts a new
    assessment row (the same supersede-and-audit-trail mechanism
    _insert_assessment already uses for retest) with a mandatory written
    justification and reviewer identity, both also carried into the
    compliance_audit_events.reason field so the original automated/manual
    result and the override are both permanently visible in the audit trail
    - never a silent overwrite."""
    justification = payload.get("justification")
    if not justification or not isinstance(justification, str) or not justification.strip():
        raise ValidationError("justification", "justification is required to override an assessment result")
    overridden_by = payload.get("overridden_by")
    if not overridden_by or not isinstance(overridden_by, str) or not overridden_by.strip():
        raise ValidationError("overridden_by", "overridden_by (auditor identity) is required")
    new_status = payload.get("status")
    if new_status not in ("pass", "partial", "fail", "not_tested", "review_required"):
        raise ValidationError(
            "status", "status must be one of pass, partial, fail, not_tested, review_required"
        )

    conn = get_connection()
    try:
        prior_row = conn.execute(
            f"SELECT {ASSESSMENT_COLUMNS} FROM compliance_assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
        if prior_row is None:
            raise HTTPException(status_code=404, detail="assessment not found")
        prior = _row_to_assessment(prior_row)

        original_status = payload.get("original_status")
        if original_status is not None and original_status != prior["status"]:
            raise ValidationError(
                "original_status",
                f"original_status ({original_status}) no longer matches this assessment's current "
                f"status ({prior['status']}) - it may have changed since you loaded it; reload and retry",
            )

        merged = {
            "control_id": prior["control_id"],
            "device_id": prior["device_id"],
            "organizational_scope_id": prior["organizational_scope_id"],
            "applicability": prior["applicability"],
            "applicability_reason": prior["applicability_reason"],
            "severity": prior["severity"],
            "test_method": prior["test_method"],
            "finding": prior["finding"],
            "test_identifier": prior["test_identifier"],
            "evidence_ids": prior["evidence_ids"],
            "status": new_status,
            "remediation": payload.get("remediation", prior["remediation"]),
            "assessed_by": overridden_by,
            "attested_role": payload.get("attested_role"),
            "attestation_confirmed": payload.get("attestation_confirmed"),
            "attestation_statement": payload.get("attestation_statement"),
        }
        data = _validate_assessment_payload(merged)
        reason = f"Auditor override by {overridden_by.strip()}: {justification.strip()}"
        new_assessment = _insert_assessment(conn, data, event_type="assessment_overridden", reason=reason)
        return {
            **new_assessment,
            "original_status": prior["status"],
            "override_justification": justification.strip(),
        }
    finally:
        conn.close()


@router.post("/assessments/{assessment_id}/evidence", status_code=201)
def attach_assessment_evidence(assessment_id: str, payload: dict):
    linked_evidence_id = payload.get("linked_evidence_id")
    collected_by = payload.get("collected_by")
    if not collected_by or not isinstance(collected_by, str) or not collected_by.strip():
        raise ValidationError("collected_by", "collected_by (reviewer name) is required")
    if not linked_evidence_id:
        raise ValidationError(
            "linked_evidence_id",
            "linked_evidence_id is required (reuse an existing evidence record; "
            "use POST /nca/evidence/upload for a new organizational document)",
        )

    conn = get_connection()
    try:
        assessment_row = conn.execute(
            "SELECT id, evidence_ids FROM compliance_assessments WHERE id = %s", (assessment_id,)
        ).fetchone()
        if assessment_row is None:
            raise HTTPException(status_code=404, detail="assessment not found")

        evidence_row = conn.execute(
            "SELECT sha256, timestamp FROM evidence WHERE evidence_id = %s", (linked_evidence_id,)
        ).fetchone()
        if evidence_row is None:
            raise HTTPException(status_code=404, detail="linked evidence record not found")
        sha256, collected_at = evidence_row

        new_id = _next_id(conn, "CEV", "compliance_evidence", "id")
        row = conn.execute(
            f"""
            INSERT INTO compliance_evidence (
                id, assessment_id, evidence_type, linked_evidence_id, sha256,
                collected_at, collected_by, retention_expires_at
            ) VALUES (%s, %s, 'automated_scan', %s, %s, %s, %s, %s)
            RETURNING {COMPLIANCE_EVIDENCE_COLUMNS}
            """,
            (new_id, assessment_id, linked_evidence_id, sha256, collected_at,
             collected_by.strip(), payload.get("retention_expires_at")),
        ).fetchone()

        existing_ids = list(assessment_row[1] or [])
        existing_ids.append(new_id)
        conn.execute(
            "UPDATE compliance_assessments SET evidence_ids = %s WHERE id = %s",
            (json.dumps(existing_ids), assessment_id),
        )
        conn.commit()
    finally:
        conn.close()
    return _row_to_compliance_evidence(row)


MAX_COMPLIANCE_DOC_BYTES = 20 * 1024 * 1024
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


@router.post("/evidence/upload", status_code=201)
async def upload_compliance_document(
    file: UploadFile, collected_by: str, assessment_id: str | None = None,
    retention_expires_at: str | None = None,
):
    """For genuinely new organizational evidence (policy documents, training
    records, supplier contracts) - not for evidence a scan already produced,
    which should be linked via POST /assessments/{id}/evidence instead of
    re-uploaded. Stored under document-store/compliance/, referenced by path
    + SHA-256, never as a DB blob - same convention as firmware upload."""
    if not collected_by or not collected_by.strip():
        raise ValidationError("collected_by", "collected_by (reviewer name) is required")

    conn = get_connection()
    try:
        if assessment_id is not None:
            exists = conn.execute(
                "SELECT 1 FROM compliance_assessments WHERE id = %s", (assessment_id,)
            ).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="assessment not found")

        data = await read_capped(file, MAX_COMPLIANCE_DOC_BYTES)
        sha256 = hashlib.sha256(data).hexdigest()
        now = datetime.now(timezone.utc)

        new_id = _next_id(conn, "CEV", "compliance_evidence", "id")
        safe_name = _SAFE_FILENAME_RE.sub("_", file.filename or "document")
        stored_name = f"{new_id}-{safe_name}"
        path = _document_store_dir() / "compliance" / stored_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

        row = conn.execute(
            f"""
            INSERT INTO compliance_evidence (
                id, assessment_id, evidence_type, original_filename, object_reference,
                sha256, collected_at, collected_by, retention_expires_at
            ) VALUES (%s, %s, 'document', %s, %s, %s, %s, %s, %s)
            RETURNING {COMPLIANCE_EVIDENCE_COLUMNS}
            """,
            (new_id, assessment_id, file.filename, f"document-store/compliance/{stored_name}",
             sha256, now, collected_by.strip(), retention_expires_at),
        ).fetchone()

        if assessment_id is not None:
            current = conn.execute(
                "SELECT evidence_ids FROM compliance_assessments WHERE id = %s", (assessment_id,)
            ).fetchone()[0]
            ids = list(current or [])
            ids.append(new_id)
            conn.execute(
                "UPDATE compliance_assessments SET evidence_ids = %s WHERE id = %s",
                (json.dumps(ids), assessment_id),
            )
        conn.commit()
    finally:
        conn.close()
    return _row_to_compliance_evidence(row)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


def _validate_exception_payload(payload: dict) -> dict:
    control_id = payload.get("control_id")
    if not control_id:
        raise ValidationError("control_id", "control_id is required")
    device_id = payload.get("device_id")
    organizational_scope_id = payload.get("organizational_scope_id")
    if bool(device_id) == bool(organizational_scope_id):
        raise ValidationError(
            "device_id", "exactly one of device_id or organizational_scope_id is required"
        )
    reason = payload.get("reason")
    if not reason or not isinstance(reason, str) or not reason.strip():
        raise ValidationError("reason", "reason is required")
    requested_by = payload.get("requested_by")
    if not requested_by or not isinstance(requested_by, str) or not requested_by.strip():
        raise ValidationError("requested_by", "requested_by (reviewer name) is required")
    expires_at = payload.get("expires_at")
    if not expires_at:
        raise ValidationError("expires_at", "expires_at is required for every exception")
    return {
        "control_id": control_id,
        "device_id": device_id,
        "organizational_scope_id": organizational_scope_id,
        "reason": reason.strip(),
        "compensating_control": payload.get("compensating_control"),
        "requested_by": requested_by.strip(),
        "expires_at": expires_at,
    }


@router.get("/exceptions")
def list_exceptions(status: str | None = None, control_id: str | None = None, device_id: str | None = None):
    conn = get_connection()
    try:
        query = f"SELECT {EXCEPTION_COLUMNS} FROM compliance_exceptions WHERE 1=1"
        params: list = []
        if status is not None:
            query += " AND status = %s"
            params.append(status)
        if control_id is not None:
            query += " AND control_id = %s"
            params.append(control_id)
        if device_id is not None:
            query += " AND device_id = %s"
            params.append(device_id)
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_exception(r) for r in rows]


@router.post("/exceptions", status_code=201)
def create_exception(payload: dict):
    data = _validate_exception_payload(payload)
    conn = get_connection()
    try:
        control_row = conn.execute("SELECT 1 FROM compliance_controls WHERE id = %s", (data["control_id"],)).fetchone()
        if control_row is None:
            raise HTTPException(status_code=404, detail="control not found")
        new_id = _next_id(conn, "EXC", "compliance_exceptions", "id")
        row = conn.execute(
            f"""
            INSERT INTO compliance_exceptions (
                id, control_id, device_id, organizational_scope_id, reason,
                compensating_control, requested_by, expires_at
            ) VALUES (%(id)s, %(control_id)s, %(device_id)s, %(organizational_scope_id)s,
                      %(reason)s, %(compensating_control)s, %(requested_by)s, %(expires_at)s)
            RETURNING {EXCEPTION_COLUMNS}
            """,
            {**data, "id": new_id},
        ).fetchone()
        conn.commit()
    finally:
        conn.close()
    return _row_to_exception(row)


@router.post("/exceptions/{exception_id}/approve")
def approve_exception(exception_id: str, payload: dict):
    approved_by = payload.get("approved_by")
    if not approved_by or not isinstance(approved_by, str) or not approved_by.strip():
        raise HTTPException(status_code=422, detail="approved_by (reviewer name) is required")

    conn = get_connection()
    try:
        before_row = conn.execute(
            f"SELECT {EXCEPTION_COLUMNS} FROM compliance_exceptions WHERE id = %s", (exception_id,)
        ).fetchone()
        if before_row is None:
            raise HTTPException(status_code=404, detail="exception not found")
        before_value = _row_to_exception(before_row)

        row = conn.execute(
            f"""
            UPDATE compliance_exceptions SET status = 'approved', approved_by = %s, approved_at = now()
            WHERE id = %s RETURNING {EXCEPTION_COLUMNS}
            """,
            (approved_by.strip(), exception_id),
        ).fetchone()
        after_value = _row_to_exception(row)
        conn.execute(
            """
            INSERT INTO compliance_audit_events (event_type, entity_type, entity_id, before_value, after_value, actor, reason)
            VALUES ('exception_approved', 'compliance_exception', %s, %s, %s, %s, %s)
            """,
            (exception_id, json.dumps(before_value), json.dumps(after_value), approved_by.strip(), payload.get("reason")),
        )
        conn.commit()
    finally:
        conn.close()
    return after_value


@router.post("/exceptions/{exception_id}/reject")
def reject_exception(exception_id: str, payload: dict):
    rejected_by = payload.get("rejected_by")
    if not rejected_by or not isinstance(rejected_by, str) or not rejected_by.strip():
        raise HTTPException(status_code=422, detail="rejected_by (reviewer name) is required")

    conn = get_connection()
    try:
        before_row = conn.execute(
            f"SELECT {EXCEPTION_COLUMNS} FROM compliance_exceptions WHERE id = %s", (exception_id,)
        ).fetchone()
        if before_row is None:
            raise HTTPException(status_code=404, detail="exception not found")
        before_value = _row_to_exception(before_row)

        row = conn.execute(
            f"UPDATE compliance_exceptions SET status = 'rejected' WHERE id = %s RETURNING {EXCEPTION_COLUMNS}",
            (exception_id,),
        ).fetchone()
        after_value = _row_to_exception(row)
        conn.execute(
            """
            INSERT INTO compliance_audit_events (event_type, entity_type, entity_id, before_value, after_value, actor, reason)
            VALUES ('exception_rejected', 'compliance_exception', %s, %s, %s, %s, %s)
            """,
            (exception_id, json.dumps(before_value), json.dumps(after_value), rejected_by.strip(), payload.get("reason")),
        )
        conn.commit()
    finally:
        conn.close()
    return after_value


# ---------------------------------------------------------------------------
# Organizational compliance (single fixed scope: "default")
# ---------------------------------------------------------------------------


@router.get("/organization")
def get_organization_compliance():
    conn = get_connection()
    try:
        control_rows = conn.execute(
            f"""
            SELECT {CONTROL_COLUMNS} FROM compliance_controls
            WHERE enabled = true AND scope_type = ANY(%s)
            ORDER BY domain_id, subdomain_id, guideline_id
            """,
            (list(ORG_SCOPE_TYPES),),
        ).fetchall()
        controls = [_row_to_control(r) for r in control_rows]

        assessment_rows = conn.execute(
            f"""
            SELECT DISTINCT ON (control_id) {ASSESSMENT_COLUMNS}
            FROM compliance_assessments
            WHERE organizational_scope_id = %s AND superseded_by IS NULL
            ORDER BY control_id, assessed_at DESC
            """,
            (DEFAULT_ORG_SCOPE_ID,),
        ).fetchall()
        latest_by_control = {r[1]: _row_to_assessment(r) for r in assessment_rows}

        evaluator_rows = _evaluator_rows_for_scope(conn, organizational_scope_id=DEFAULT_ORG_SCOPE_ID)
    finally:
        conn.close()

    return {
        "organizational_scope_id": DEFAULT_ORG_SCOPE_ID,
        "overall_status": device_overall_status(evaluator_rows),
        "score": device_score(evaluator_rows),
        "domain_summary": domain_summary(evaluator_rows),
        "readiness": overall_classification(evaluator_rows),
        "controls": [
            {"control": control, "assessment": latest_by_control.get(control["id"])}
            for control in controls
        ],
    }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def _report_metadata_rows() -> list[list[str]]:
    return [
        ["# product", PRODUCT_LABEL],
        ["# framework", "NCA-CGIoT 1:2024"],
        ["# generated_at", datetime.now(timezone.utc).isoformat(timespec="seconds")],
        ["# disclaimer", DISCLAIMER],
    ]


@router.get("/reports/devices.csv")
def report_devices_csv():
    conn = get_connection()
    try:
        device_rows = conn.execute(
            "SELECT device_id, display_name, tier FROM devices ORDER BY device_id"
        ).fetchall()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        for row in _report_metadata_rows():
            writer.writerow(row)
        writer.writerow(["device_id", "display_name", "tier", "overall_status", "score"])
        for device_id, display_name, tier in device_rows:
            rows = _evaluator_rows_for_scope(conn, device_id=device_id)
            writer.writerow([device_id, display_name, tier, device_overall_status(rows), device_score(rows)])
    finally:
        conn.close()
    return Response(content=buffer.getvalue(), media_type="text/csv")


@router.get("/reports/controls.csv")
def report_controls_csv():
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT {CONTROL_COLUMNS} FROM compliance_controls ORDER BY domain_id, subdomain_id, guideline_id"
        ).fetchall()
    finally:
        conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in _report_metadata_rows():
        writer.writerow(row)
    writer.writerow([
        "id", "domain_id", "domain_name", "subdomain_id", "subdomain_name", "guideline_id",
        "scope_type", "assessment_type", "required", "severity", "enabled",
    ])
    for r in rows:
        control = _row_to_control(r)
        writer.writerow([
            control["id"], control["domain_id"], control["domain_name"], control["subdomain_id"],
            control["subdomain_name"], control["guideline_id"], control["scope_type"],
            control["assessment_type"], control["required"], control["severity"], control["enabled"],
        ])
    return Response(content=buffer.getvalue(), media_type="text/csv")


@router.get("/reports/controls.json")
def report_controls_json():
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT {CONTROL_COLUMNS} FROM compliance_controls ORDER BY domain_id, subdomain_id, guideline_id"
        ).fetchall()
    finally:
        conn.close()
    return {
        "product_label": PRODUCT_LABEL,
        "framework": "NCA-CGIoT",
        "framework_version": "1:2024",
        "disclaimer": DISCLAIMER,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "controls": [_row_to_control(r) for r in rows],
    }


@router.get("/reports/evidence.csv")
def report_evidence_csv():
    conn = get_connection()
    try:
        rows = conn.execute(
            f"SELECT {COMPLIANCE_EVIDENCE_COLUMNS} FROM compliance_evidence ORDER BY created_at"
        ).fetchall()
    finally:
        conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in _report_metadata_rows():
        writer.writerow(row)
    writer.writerow([
        "id", "assessment_id", "evidence_type", "linked_evidence_id", "original_filename",
        "sha256", "collected_at", "collected_by", "retention_expires_at",
    ])
    for r in rows:
        e = _row_to_compliance_evidence(r)
        writer.writerow([
            e["id"], e["assessment_id"], e["evidence_type"], e["linked_evidence_id"],
            e["original_filename"], e["sha256"], e["collected_at"], e["collected_by"],
            e["retention_expires_at"],
        ])
    return Response(content=buffer.getvalue(), media_type="text/csv")


@router.get("/reports/executive.pdf")
def report_executive_pdf():
    conn = get_connection()
    try:
        model = build_nca_executive_report_model(conn, _evaluator_rows_for_scope)
    finally:
        conn.close()
    pdf = render_nca_executive_report_pdf(model)
    filename = f"iotguard-nca-executive-{datetime.now(timezone.utc):%Y-%m-%d}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
