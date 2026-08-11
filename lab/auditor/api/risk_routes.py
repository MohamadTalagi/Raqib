"""Dynamic Risk Assessment (IoTGuard Stage 06) read-only API surface - a
separate APIRouter (same pattern as nca_routes.py/vuln_routes.py) mounted via
app.include_router() in main.py.

This router's only job is assembling the 7 real inputs
policies/risk/risk_engine.py needs, per device, by reusing what every other
part of this application already computes - it never reimplements a
compliance score, a CVE lookup, or a violation count. The score itself is
never cached or persisted: like device_score() and
vuln_routes._summarize_packages(), it's computed fresh from current data on
every request, since every input already lives somewhere real.

No write endpoints - a device's risk score is entirely derived from data
recorded elsewhere (NCA assessments, vulnerability-intel
evidence, device_services) plus the two auditor-set fields
(devices.criticality/exposure) that already have their own write path via
the existing PATCH /devices/{id}.
"""

from fastapi import APIRouter

from db import get_connection
from device_validation import validate_device_id
from nca_routes import _evaluator_rows_for_scope
from policies.nca.evaluator import device_score
from policies.risk.risk_engine import DeviceRiskInputs, compute_device_risk
from vuln_routes import _manifest_packages, _summarize_packages

router = APIRouter(prefix="/risk", tags=["risk"])






def _insecure_service_count(conn, device_id: str) -> int:
    row = conn.execute(
        """
        SELECT COUNT(*) FROM device_services
        WHERE device_id = %s AND enabled = true AND service_type IN ('http', 'mqtt', 'telnet')
        """,
        (device_id,),
    ).fetchone()
    return row[0]


def _vuln_summary_for_device(conn, device_id: str) -> dict:
    row = conn.execute(
        """
        SELECT observations FROM evidence
        WHERE device_id = %s AND test_id = 'TEST-FW-MANIFEST'
        ORDER BY timestamp DESC LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return {"highest_cvss": None, "kev_listed_cves": 0}
    return _summarize_packages(_manifest_packages(row[0]))


def _compute_risk_for_device(conn, device_id: str) -> dict:
    """Assembles the 7 real inputs for one device and calls the pure
    scoring engine. The one place this router does any real work - every
    endpoint below is a thin wrapper around this."""
    device_row = conn.execute(
        "SELECT criticality, exposure FROM devices WHERE device_id = %s", (device_id,),
    ).fetchone()
    criticality, exposure = device_row if device_row else ("medium", "internal_only")

    compliance_score = device_score(_evaluator_rows_for_scope(conn, device_id=device_id))
    vuln_summary = _vuln_summary_for_device(conn, device_id)
    insecure_service_count = _insecure_service_count(conn, device_id)

    inputs = DeviceRiskInputs(
        compliance_score=compliance_score,
        highest_cvss=vuln_summary["highest_cvss"],
        has_kev_listed_cve=vuln_summary["kev_listed_cves"] > 0,
        criticality=criticality,
        exposure=exposure,
        insecure_service_count=insecure_service_count,
    )
    return compute_device_risk(inputs)


@router.get("/devices")
def get_risk_devices() -> dict:
    """Every registered device, computed live, sorted worst-first
    (descending risk score) - this sorted list IS the org-wide priority
    ranking: rank position is implicit in list order."""
    conn = get_connection()
    try:
        device_ids = [
            r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id").fetchall()
        ]
        devices = []
        for device_id in device_ids:
            risk = _compute_risk_for_device(conn, device_id)
            devices.append({
                "device_id": device_id,
                "risk_score": risk["risk_score"],
                "risk_category": risk["risk_category"],
            })
    finally:
        conn.close()

    devices.sort(key=lambda d: d["risk_score"], reverse=True)
    for rank, device in enumerate(devices, start=1):
        device["priority_rank"] = rank

    return {"devices": devices}


@router.get("/devices/{device_id}")
def get_device_risk(device_id: str) -> dict:
    """One device's full risk score, category, and the complete per-factor
    breakdown - value, normalized contribution, weight, and weighted
    contribution for each of the 7 inputs - so the number is never a black
    box."""
    validate_device_id(device_id)
    conn = get_connection()
    try:
        exists = conn.execute(
            "SELECT 1 FROM devices WHERE device_id = %s", (device_id,),
        ).fetchone()
        if exists is None:
            return {"device_id": device_id, "known": False}
        risk = _compute_risk_for_device(conn, device_id)
    finally:
        conn.close()

    return {"device_id": device_id, "known": True, **risk}


@router.get("/fleet-summary")
def get_risk_fleet_summary() -> dict:
    """Aggregate stats for the Overview page's fleet-risk tile: count per
    category and the fleet-wide average score."""
    conn = get_connection()
    try:
        device_ids = [
            r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id").fetchall()
        ]
        risks = [_compute_risk_for_device(conn, device_id) for device_id in device_ids]
    finally:
        conn.close()

    by_category = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for risk in risks:
        by_category[risk["risk_category"]] += 1

    return {
        "total_devices": len(device_ids),
        "average_score": (
            round(sum(r["risk_score"] for r in risks) / len(risks)) if risks else None
        ),
        "by_category": by_category,
    }
