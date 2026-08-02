"""Post-Quantum Readiness (bonus pipeline stage, informational only - never
touches policies/risk/risk_engine.py) read-only API surface - a separate
APIRouter (same pattern as vuln_routes.py/risk_routes.py) mounted via
app.include_router() in main.py.

Every field returned here was already computed by the worker's
TEST-PQC-TLS-HANDSHAKE/TEST-PQC-FIRMWARE-CRYPTO collectors
(lab/auditor/worker/scan_scripts/pqc_readiness_check.py,
policies/catalog/pqc_crypto_reference.py) and stored in evidence.observations
at scan time - this router only ever reads rows that already exist, exactly
like every other read-only rollup in this API. No new table, no new
verdict/assessment concept: this is explicitly not a fourth SA-IOT/NCA-style
compliance framework requiring sign-off, just a live-computed summary, never
cached or persisted.
"""

from fastapi import APIRouter

from db import get_connection
from device_validation import validate_device_id
from policies.catalog.pqc_crypto_reference import (
    TIP_CERT_SIGNATURE_FAIL,
    TIP_FIRMWARE_CRYPTO_FAIL,
    TIP_FIRMWARE_CRYPTO_UNKNOWN,
    TIP_TLS_KEY_EXCHANGE_FAIL,
)

router = APIRouter(prefix="/pqc-readiness", tags=["pqc-readiness"])

TLS_TEST_ID = "TEST-PQC-TLS-HANDSHAKE"
FIRMWARE_TEST_ID = "TEST-PQC-FIRMWARE-CRYPTO"

CRITERION_STATUSES = ("pass", "fail", "unknown", "not_applicable")


def _tls_criteria_from_observations(observations: dict | None) -> tuple[dict, dict]:
    """Returns (tls_key_exchange, certificate_signature). `not_applicable`
    when this device has never had a TLS handshake probe at all;
    `unknown` when a probe ran but couldn't reach the service (real infra
    flakiness, not a fabricated fail)."""
    if observations is None:
        return (
            {"status": "not_applicable", "negotiated_group": None},
            {"status": "not_applicable", "signature_algorithm": None},
        )
    if observations.get("connection_error"):
        return (
            {"status": "unknown", "negotiated_group": None},
            {"status": "unknown", "signature_algorithm": None},
        )

    is_pqc_kem = observations.get("is_pqc_kem")
    kem_status = {True: "pass", False: "fail"}.get(is_pqc_kem, "unknown")
    kem: dict = {"status": kem_status, "negotiated_group": observations.get("negotiated_group")}
    if kem_status == "fail":
        kem["tip"] = TIP_TLS_KEY_EXCHANGE_FAIL

    is_pqc_sig = observations.get("is_pqc_signature")
    sig_status = {True: "pass", False: "fail"}.get(is_pqc_sig, "unknown")
    sig: dict = {"status": sig_status, "signature_algorithm": observations.get("cert_signature_algorithm")}
    if sig_status == "fail":
        sig["tip"] = TIP_CERT_SIGNATURE_FAIL

    return kem, sig


def _firmware_criterion_from_observations(observations: dict | None) -> dict:
    """`not_applicable` when this device has never had a firmware manifest
    at all; `unknown` when a manifest exists but no recognized crypto
    library was found in it (never a guessed pass/fail)."""
    if observations is None or not observations.get("manifest_present"):
        return {"status": "not_applicable", "packages": []}

    packages = observations.get("packages") or []
    statuses = {p["pqc_status"] for p in packages}
    if "fail" in statuses:
        result = {"status": "fail", "packages": packages, "tip": TIP_FIRMWARE_CRYPTO_FAIL}
    elif not packages or statuses == {"unknown"}:
        result = {"status": "unknown", "packages": packages, "tip": TIP_FIRMWARE_CRYPTO_UNKNOWN}
    else:
        result = {"status": "pass", "packages": packages}
    return result


def _device_pqc_summary(conn, device_id: str) -> dict:
    tls_row = conn.execute(
        "SELECT observations FROM evidence WHERE device_id = %s AND test_id = %s ORDER BY timestamp DESC LIMIT 1",
        (device_id, TLS_TEST_ID),
    ).fetchone()
    fw_row = conn.execute(
        "SELECT observations FROM evidence WHERE device_id = %s AND test_id = %s ORDER BY timestamp DESC LIMIT 1",
        (device_id, FIRMWARE_TEST_ID),
    ).fetchone()

    tls_key_exchange, certificate_signature = _tls_criteria_from_observations(tls_row[0] if tls_row else None)
    firmware_crypto = _firmware_criterion_from_observations(fw_row[0] if fw_row else None)

    criteria_statuses = [tls_key_exchange["status"], certificate_signature["status"], firmware_crypto["status"]]
    fail_count = criteria_statuses.count("fail")
    if fail_count:
        overall_status = "fail"
    elif "unknown" in criteria_statuses:
        overall_status = "unknown"
    elif all(s == "not_applicable" for s in criteria_statuses):
        overall_status = "not_applicable"
    else:
        overall_status = "pass"

    return {
        "device_id": device_id,
        "overall_status": overall_status,
        "fail_count": fail_count,
        "tls_key_exchange": tls_key_exchange,
        "certificate_signature": certificate_signature,
        "firmware_crypto": firmware_crypto,
    }


@router.get("/devices")
def get_pqc_readiness_devices() -> dict:
    """Every registered device, computed live, worst-first by failing-
    criterion count - matches this app's convention for every other fleet
    ranking (risk, vulnerability intelligence)."""
    conn = get_connection()
    try:
        device_ids = [r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id").fetchall()]
        devices = [_device_pqc_summary(conn, device_id) for device_id in device_ids]
    finally:
        conn.close()
    devices.sort(key=lambda d: -d["fail_count"])
    return {"devices": devices}


@router.get("/devices/{device_id}")
def get_device_pqc_readiness(device_id: str) -> dict:
    """`known: false` (not a 404) for an unregistered device - a real,
    reachable state, matching vuln_routes.py's own `has_data: false`
    convention rather than an error."""
    validate_device_id(device_id)
    conn = get_connection()
    try:
        exists = conn.execute("SELECT 1 FROM devices WHERE device_id = %s", (device_id,)).fetchone()
        if exists is None:
            return {"device_id": device_id, "known": False}
        summary = _device_pqc_summary(conn, device_id)
    finally:
        conn.close()
    return {"known": True, **summary}


@router.get("/fleet-summary")
def get_pqc_readiness_fleet_summary() -> dict:
    conn = get_connection()
    try:
        device_ids = [r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id").fetchall()]
        devices = [_device_pqc_summary(conn, device_id) for device_id in device_ids]
    finally:
        conn.close()

    def _counts(criterion_key: str) -> dict:
        counts = {status: 0 for status in CRITERION_STATUSES}
        for d in devices:
            counts[d[criterion_key]["status"]] += 1
        return counts

    return {
        "total_devices": len(devices),
        "tls_key_exchange": _counts("tls_key_exchange"),
        "certificate_signature": _counts("certificate_signature"),
        "firmware_crypto": _counts("firmware_crypto"),
    }
