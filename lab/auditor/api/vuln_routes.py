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

Since the device-level CVE feature, GET /vuln-intel/devices/{id} also serves
a SECOND, independent source: TEST-DEVICE-CVE-LOOKUP evidence, which matches
a device's vendor/model against real NVD data by CPE and needs no firmware
image at all. Same architecture - the worker did the matching at write time,
this only re-reads it. The two are gated by separate flags (`has_data` for
package-level, `has_device_cve_data` for device-level); a device may have
either, both, or neither. This closes the "device-level vendor/model CPE
matching... is not implemented" limitation docs/vulnerability-intelligence.md
named explicitly as scoped out of that pass.
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


def _latest_evidence(conn, device_id: str, test_id: str):
    return conn.execute(
        """
        SELECT evidence_id, observations, timestamp
        FROM evidence
        WHERE device_id = %s AND test_id = %s
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        (device_id, test_id),
    ).fetchone()


def _empty_device_cve_fields() -> dict:
    return {
        "has_device_cve_data": False,
        "device_cve_evidence_id": None,
        "device_cve_observed_at": None,
        "device_identity": None,
        "device_cves": [],
        "total_device_cves": 0,
        "kev_listed_device_cves": 0,
        "highest_device_cvss": None,
        "firmware_currency": None,
    }


def _device_cve_fields(row) -> dict:
    """Reshapes TEST-DEVICE-CVE-LOOKUP evidence for the API response.

    Like the package-level half above, this is a pure re-read: the CPE match
    and the KEV cross-reference both already happened in the worker at scan
    time (policies/catalog/scan_tests.py's
    _parse_device_cve_lookup_observations). No lookup logic lives here."""
    if row is None:
        return _empty_device_cve_fields()

    evidence_id, observations, timestamp = row
    observations = observations or {}
    return {
        "has_device_cve_data": True,
        "device_cve_evidence_id": evidence_id,
        "device_cve_observed_at": timestamp.isoformat(),
        "device_identity": {
            "vendor": observations.get("vendor"),
            "model": observations.get("model"),
            "firmware_version": observations.get("firmware_version"),
            "cpe": observations.get("cpe"),
            "cpe_matched": bool(observations.get("cpe_matched")),
        },
        "device_cves": observations.get("device_cves") or [],
        "total_device_cves": observations.get("total_device_cves") or 0,
        "kev_listed_device_cves": observations.get("kev_listed_device_cves") or 0,
        "highest_device_cvss": observations.get("highest_device_cvss"),
        # Whether the device's reported firmware is behind a published fix.
        # Decided at write time by the worker's comparator; None on evidence
        # recorded before that existed, which the frontend renders as absent
        # rather than as a claim.
        "firmware_currency": observations.get("firmware_currency"),
        "notes": observations.get("notes") or [],
    }


@router.get("/devices/{device_id}")
def get_device_vuln_summary(device_id: str) -> dict:
    """One device's vulnerability intelligence from both independent sources.

    Two reads, deliberately gated separately, because a device may have
    either, both, or neither:

      * package-level (`has_data`, `packages`) - the most recent
        TEST-FW-MANIFEST evidence. Needs an uploaded firmware archive.
      * device-level (`has_device_cve_data`, `device_cves`) - the most recent
        TEST-DEVICE-CVE-LOOKUP evidence. Needs no firmware at all, only a
        known vendor/model.

    `has_data` keeps its original, narrower meaning ("a firmware manifest
    scan happened") on purpose: report.py, risk_routes.py and the frontend's
    lib/pipeline.ts all read it that way, and widening it here would silently
    change a device's risk inputs and pipeline-phase badge. The device-level
    half gets its own flag instead.

    Neither `false` is a 404 - both are real, reachable states."""
    validate_device_id(device_id)
    conn = get_connection()
    try:
        manifest_row = _latest_evidence(conn, device_id, "TEST-FW-MANIFEST")
        device_cve_row = _latest_evidence(conn, device_id, "TEST-DEVICE-CVE-LOOKUP")
    finally:
        conn.close()

    device_cve_fields = _device_cve_fields(device_cve_row)

    if manifest_row is None:
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
            **device_cve_fields,
        }

    evidence_id, observations, timestamp = manifest_row
    packages = _manifest_packages(observations)
    return {
        "device_id": device_id,
        "has_data": True,
        "evidence_id": evidence_id,
        "observed_at": timestamp.isoformat(),
        "packages": packages,
        **_summarize_packages(packages),
        **device_cve_fields,
    }
