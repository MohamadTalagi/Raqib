"""Vulnerability intelligence (IoTGuard Stage 05) read-only API surface - a
separate APIRouter (same pattern as nca_routes.py) mounted via
app.include_router() in main.py.

Every CVE/KEV field returned here was already computed by the worker's
TEST-FW-MANIFEST collector (lab/auditor/worker/scan_scripts/firmware_check.py,
policies/catalog/scan_tests.py's _advisory_from_grype_matches) and stored in
evidence.observations at scan time - this router only ever reads rows that
already exist, exactly like the rest of this API never executes anything
itself. That includes DB freshness: Grype's local vulnerability DB and the
CISA KEV cache both live on the worker's filesystem, which the API has no
access to (and shouldn't - see job_runner.py's own boundary notes), so
GET /vuln-intel/status reports the DB snapshot the *most recent* piece of
evidence actually used, not a live query.

Scope: only TEST-FW-MANIFEST evidence carries the Grype/CISA-KEV-backed
per-package advisory shape (observations.packages[]) - TEST-NET-HTTP-INSPECT's
Server-banner enrichment stayed on the small static policies/catalog/
vuln_reference.py table only, a deliberate scope decision (see the
vulnerability-intelligence plan's Phase 1 notes), so it's not included here.
"""

from fastapi import APIRouter

from db import get_connection
from device_validation import validate_device_id

router = APIRouter(prefix="/vuln-intel", tags=["vuln-intel"])


def _manifest_packages(observations: dict) -> list[dict]:
    return observations.get("packages") or []


def _summarize_packages(packages: list[dict]) -> dict:
    all_cves = [cve for pkg in packages for cve in (pkg.get("cves") or [])]
    kev_cves = [cve for cve in all_cves if cve.get("kev_listed")]
    highest_cvss = max(
        (cve["cvss"] for cve in all_cves if cve.get("cvss") is not None), default=None,
    )
    return {
        "total_packages": len(packages),
        "outdated_packages": sum(1 for pkg in packages if pkg.get("outdated")),
        "total_cves": len(all_cves),
        "kev_listed_cves": len(kev_cves),
        "highest_cvss": highest_cvss,
    }


@router.get("/status")
def get_vuln_intel_status() -> dict:
    """Which Grype vulnerability-DB snapshot the most recent firmware scan
    actually used, and when. `known: false` means no TEST-FW-MANIFEST
    evidence has ever recorded a snapshot - never fabricated as "unknown but
    probably fine"."""
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT observations ->> 'vuln_db_built_at', observations ->> 'vuln_db_checksum',
                   timestamp, evidence_id, device_id
            FROM evidence
            WHERE observations ? 'vuln_db_built_at'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return {
            "known": False,
            "vuln_db_built_at": None,
            "vuln_db_checksum": None,
            "observed_at": None,
            "observed_from_evidence_id": None,
            "observed_from_device_id": None,
        }
    built_at, checksum, observed_at, evidence_id, device_id = row
    return {
        "known": True,
        "vuln_db_built_at": built_at,
        "vuln_db_checksum": checksum,
        "observed_at": observed_at.isoformat(),
        "observed_from_evidence_id": evidence_id,
        "observed_from_device_id": device_id,
    }


@router.get("/fleet-summary")
def get_vuln_intel_fleet_summary() -> dict:
    """One row per device with a firmware manifest scan, worst-first (most
    KEV-listed CVEs, then highest CVSS) - the same ordering convention the
    Overview page's other "needs attention" panels already use."""
    conn = get_connection()
    try:
        # DISTINCT ON device_id, newest first: a re-scanned device's prior
        # manifest read is superseded for this rollup, matching how the NCA
        # module treats a re-assessment as the current answer.
        rows = conn.execute(
            """
            SELECT DISTINCT ON (device_id) device_id, observations, timestamp
            FROM evidence
            WHERE test_id = 'TEST-FW-MANIFEST'
            ORDER BY device_id, timestamp DESC
            """,
        ).fetchall()
    finally:
        conn.close()

    devices = []
    for device_id, observations, timestamp in rows:
        summary = _summarize_packages(_manifest_packages(observations))
        devices.append({
            "device_id": device_id,
            "observed_at": timestamp.isoformat(),
            **summary,
        })
    devices.sort(key=lambda d: (-d["kev_listed_cves"], -(d["highest_cvss"] or 0)))

    return {
        "devices": devices,
        "total_cves": sum(d["total_cves"] for d in devices),
        "total_kev_listed_cves": sum(d["kev_listed_cves"] for d in devices),
    }


@router.get("/devices/{device_id}")
def get_device_vuln_summary(device_id: str) -> dict:
    """The most recent TEST-FW-MANIFEST evidence for one device, with its
    full per-package advisory list plus a rollup. `has_data: false` (not a
    404) when the device has never had a firmware manifest scan - a real,
    reachable state, not an error."""
    validate_device_id(device_id)
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT evidence_id, observations, timestamp
            FROM evidence
            WHERE device_id = %s AND test_id = 'TEST-FW-MANIFEST'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (device_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return {
            "device_id": device_id,
            "has_data": False,
            "evidence_id": None,
            "observed_at": None,
            "packages": [],
            "total_packages": 0,
            "outdated_packages": 0,
            "total_cves": 0,
            "kev_listed_cves": 0,
            "highest_cvss": None,
        }

    evidence_id, observations, timestamp = row
    packages = _manifest_packages(observations)
    return {
        "device_id": device_id,
        "has_data": True,
        "evidence_id": evidence_id,
        "observed_at": timestamp.isoformat(),
        "packages": packages,
        **_summarize_packages(packages),
    }
