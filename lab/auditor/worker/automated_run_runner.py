"""Drives a "Fully Automated Run" (automated_runs row) end to end: Discovery
-> device registration -> Fingerprinting/SA-IOT scans -> verdict recompute ->
conditional Vulnerability Intelligence -> Post-Quantum Readiness (bonus
stage, informational only) -> NCA recompute + auto-recorded assessments.
Risk Assessment needs no action here - it is already live-computed on every
read.

This is NOT a new execution path. Every stage calls the exact same
auditor-api endpoints a human clicking through the dashboard would (POST
/network-scans, POST /devices, POST /scan-jobs, POST /scan-jobs/{id}/record,
POST /verdicts/recompute, POST /nca/assessments/recompute, POST
/nca/assessments), so it inherits every existing security boundary
(device_validation, the scan-test whitelist, the finding-mapping table) with
no new bypass surface to audit. Scan-job/network-scan *execution* itself
reuses job_runner.py's own process_job()/process_network_scan() directly -
not "create via the API, then wait for the next poll_once()/
poll_network_scans_once() iteration to pick it up," which would deadlock
against itself since poll_automated_runs_once() runs inside the very same
single-threaded main loop, after those two functions have already run for
this iteration.

Two things are deliberately never automated, and skipped rather than faked:
the ~60 organizational/mobile/supplier/cloud NCA guidelines need a human's
answers to their guided checklist (nothing in the evidence tells the system
whether a policy was approved), and PACKAGE-level Vulnerability Intelligence
only ever runs against a device that already has firmware uploaded - a run
never invents one. DEVICE-level CVE lookup (TEST-DEVICE-CVE-LOOKUP) does run
for any device with a known vendor and model, since it needs no firmware
image at all.
"""
import os
import re
import sys

import requests

from job_runner import process_job, process_network_scan
from policies.catalog.scan_tests import (
    PIPELINE_PHASE_FINGERPRINTING,
    PIPELINE_PHASE_PQC_READINESS,
    PIPELINE_PHASE_SA_IOT_COMPLIANCE,
    SCAN_CATALOG,
    is_firmware_test,
    is_network_discovery_test,
)

API_URL = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")

AUTOMATED_TEST_PHASES = (PIPELINE_PHASE_FINGERPRINTING, PIPELINE_PHASE_SA_IOT_COMPLIANCE)

# Mirrors lab/auditor/web/src/components/devices/NetworkDiscoveryPanel.tsx's
# own PORT_SERVICE_TYPE map exactly - kept as a separate Python copy rather
# than shared code, since the frontend's version stays a human-reviewable
# *pre-fill* for manual registration (different failure-handling needs than
# this fully-automated path, which must decide unattended).
PORT_SERVICE_TYPE = {
    80: "http", 443: "https", 1883: "mqtt", 8883: "mqtts", 23: "telnet",
    22: "ssh", 502: "modbus", 554: "rtsp", 1900: "upnp", 5353: "mdns",
}

# Matches this lab's own Docker Compose container naming
# (kaust-iot-lab-<name>-<index>.<network>), same regex as
# NetworkDiscoveryPanel.tsx's suggestNameFromHost().
HOSTNAME_PATTERN = re.compile(r"^kaust-iot-lab-(.+?)-\d+\.")

AUTO_RECORDED_ASSESSED_BY = "Fully Automated Run"
AUTO_RECORDED_ATTESTED_ROLE = "system:automated-run"


def _guess_device_registration(host: dict) -> dict | None:
    """Mirrors NetworkDiscoveryPanel.tsx's prefillFromHost(): guess a
    device_id/display_name from the container-naming convention (falling
    back to an IP-based slug for anything that doesn't match) and derive
    services from open ports via the same port->service-type map. Returns
    None when no recognized service port is open - registering a device
    with zero services is rejected by POST /devices anyway, and a host with
    no signature port open has nothing meaningful to scan later."""
    hostname = host.get("hostname") or ""
    match = HOSTNAME_PATTERN.match(hostname)
    if match:
        device_id = display_name = match.group(1)
    else:
        ip = host["ip"]
        device_id = f"host-{ip.replace('.', '-')}"
        display_name = f"Host {ip}"

    services = [
        {"service_type": PORT_SERVICE_TYPE[port], "port": port}
        for port in host.get("open_ports", [])
        if port in PORT_SERVICE_TYPE
    ]
    if not services:
        return None
    return {"device_id": device_id, "display_name": display_name, "host": host["ip"], "services": services}


def _is_already_registered(host: dict, devices: list[dict]) -> bool:
    guess = _guess_device_registration(host)
    guessed_id = guess["device_id"] if guess else None
    return any(
        d["registered"] and (d["host"] == host["ip"] or d["host"] == guessed_id or d["device_id"] == guessed_id)
        for d in devices
    )


def _run_status(run_id: int) -> str:
    response = requests.get(f"{API_URL}/automation/runs/{run_id}", timeout=10)
    response.raise_for_status()
    return response.json()["status"]


def _patch_run(run_id: int, fields: dict) -> None:
    response = requests.patch(f"{API_URL}/automation/runs/{run_id}", json=fields, timeout=10)
    response.raise_for_status()


def _advance(run_id: int, summary: dict, *, stage: str) -> bool:
    """Persists progress and reports whether the run should keep going -
    False once a human has cancelled it. Checked between every device/stage
    boundary; an already-dispatched scan or subprocess is still left to
    finish rather than killed mid-execution, the same documented limitation
    POST /assessments/{id}/cancel already has."""
    _patch_run(run_id, {"status": "running", "current_stage": stage, "summary": summary})
    return _run_status(run_id) != "cancelled"


def _run_discovery_and_register(run_id: int, summary: dict) -> None:
    scan = requests.post(f"{API_URL}/network-scans", timeout=10).json()
    process_network_scan(scan)
    scan = requests.get(f"{API_URL}/network-scans/{scan['id']}", timeout=10).json()

    observations = scan.get("observations") or {}
    hosts = observations.get("hosts", [])
    summary["hosts_discovered"] = len(hosts)

    devices = requests.get(f"{API_URL}/devices", timeout=15).json()
    for host in hosts:
        if host["classification"] not in ("iot_device", "uncertain"):
            continue
        if _is_already_registered(host, devices):
            continue
        registration = _guess_device_registration(host)
        if registration is None:
            continue
        response = requests.post(f"{API_URL}/devices", json=registration, timeout=10)
        if response.status_code == 201:
            summary["devices_registered"] += 1
        else:
            summary["errors"].append(
                f"could not register {registration['device_id']} ({host['ip']}): {response.text[:200]}"
            )


def _applicable_test_ids(device: dict) -> list[str]:
    enabled_service_types = {s["service_type"] for s in device.get("services", []) if s["enabled"]}
    return [
        test_id
        for test_id, spec in SCAN_CATALOG.items()
        if spec.get("pipeline_phase") in AUTOMATED_TEST_PHASES
        and not is_firmware_test(test_id)
        and not is_network_discovery_test(test_id)
        and enabled_service_types & set(spec["applicable_service_types"])
    ]


def _run_scan_test(device_id: str, test_id: str, summary: dict) -> None:
    """Creates and immediately executes one scan job (never waits for a
    later poll iteration - see the module docstring), then auto-submits its
    already-deterministic suggested finding with zero human review. A job
    that ends up 'failed' (invalid target, inapplicable test, or a collector
    exception already turned into INCONCLUSIVE evidence by record-failure)
    needs no further action here."""
    created = requests.post(f"{API_URL}/scan-jobs", json={"device_id": device_id, "test_id": test_id}, timeout=10)
    if created.status_code != 201:
        return
    summary["tests_run"] += 1
    job_id = created.json()["id"]

    # POST /scan-jobs deliberately never returns host/service_type/port -
    # scan_jobs is a pure audit row (device_id, test_id only, see main.py's
    # own comment on GET /scan-jobs). Only the *list* endpoint resolves the
    # live target via a join against device_services, the same one
    # job_runner.py's own poll_once() reads from - reusing it here instead of
    # inventing a second target-resolution path.
    pending = requests.get(f"{API_URL}/scan-jobs", params={"status": "pending"}, timeout=10).json()
    job = next((j for j in pending if j["id"] == job_id), None)
    if job is None:
        summary["errors"].append(f"job {job_id} ({test_id}) vanished before it could run")
        return
    process_job(job)

    job = requests.get(f"{API_URL}/scan-jobs/{job_id}", timeout=10).json()
    if job["status"] != "awaiting_finding":
        return

    record = requests.post(
        f"{API_URL}/scan-jobs/{job['id']}/record",
        json={
            "finding": job["suggested_finding"],
            "confidence": job["suggested_confidence"],
            "confidence_reason": (
                f"Auto-recorded by Fully Automated Run from {job['tool'] or 'the collector'} output; "
                "not reviewed by a human."
            ),
        },
        timeout=10,
    )
    if record.status_code == 201:
        summary["evidence_recorded"] += 1
    else:
        summary["errors"].append(f"could not record evidence for job {job['id']} ({test_id}): {record.text[:200]}")


def _run_fingerprinting_and_sa_iot(devices: list[dict], summary: dict) -> None:
    for device in devices:
        for test_id in _applicable_test_ids(device):
            _run_scan_test(device["device_id"], test_id, summary)

    recompute = requests.post(f"{API_URL}/verdicts/recompute", timeout=30)
    if recompute.status_code == 200:
        summary["verdicts_computed"] = recompute.json().get("created", 0)


def _refresh_devices(devices: list[dict], summary: dict) -> list[dict]:
    """Re-read the same device_ids from auditor-api, preserving order.

    Returns the original list unchanged if the re-read fails - a stale
    snapshot is strictly better than dropping the remaining stages, and the
    failure is recorded rather than swallowed."""
    device_ids = [d["device_id"] for d in devices]
    try:
        response = requests.get(f"{API_URL}/devices", timeout=15)
        response.raise_for_status()
        by_id = {d["device_id"]: d for d in response.json() if d["registered"]}
    except (requests.RequestException, ValueError) as exc:
        summary["errors"].append(f"could not re-read devices after fingerprinting: {exc}")
        return devices
    return [by_id[device_id] for device_id in device_ids if device_id in by_id]


def _run_vuln_intelligence(devices: list[dict], summary: dict) -> None:
    """Two independent sources, each with its own precondition.

    Package-level (TEST-FW-MANIFEST) still only ever runs for a device that
    already has firmware uploaded - a run never invents one.

    Device-level (TEST-DEVICE-CVE-LOOKUP) needs no firmware at all, only a
    known vendor and model, which the fingerprinting stage above has usually
    just auto-detected via TEST-DEVICE-ID. Skipping it here would mean the
    one-click run never exercises the one form of vulnerability intelligence
    that works for a device nobody has a firmware image for - the common case
    this feature exists for. The caller re-reads `devices` (via
    _refresh_devices) before this stage so vendor/model reflect what
    TEST-DEVICE-ID just found, not the pre-fingerprinting snapshot."""
    for device in devices:
        if device.get("firmware_sha256"):
            _run_scan_test(device["device_id"], "TEST-FW-MANIFEST", summary)
            summary["vuln_intel_devices_scanned"] += 1
        if device.get("vendor") and device.get("model"):
            _run_scan_test(device["device_id"], "TEST-DEVICE-CVE-LOOKUP", summary)
            summary["device_cve_devices_scanned"] += 1


def _pqc_applicable_test_ids(device: dict) -> list[str]:
    enabled_service_types = {s["service_type"] for s in device.get("services", []) if s["enabled"]}
    return [
        test_id
        for test_id, spec in SCAN_CATALOG.items()
        if spec.get("pipeline_phase") == PIPELINE_PHASE_PQC_READINESS
        and not is_firmware_test(test_id)
        and enabled_service_types & set(spec["applicable_service_types"])
    ]


def _run_pqc_readiness(devices: list[dict], summary: dict) -> None:
    """Post-Quantum Readiness - a bonus stage beyond IoTGuard's original
    10-stage vision, informational only (never touches
    policies/risk/risk_engine.py). Included in the Fully Automated Run per
    the owner's own explicit choice - unlike AI Remediation (Stage 07),
    which stays manual-only by design."""
    for device in devices:
        for test_id in _pqc_applicable_test_ids(device):
            _run_scan_test(device["device_id"], test_id, summary)
        if device.get("firmware_sha256"):
            _run_scan_test(device["device_id"], "TEST-PQC-FIRMWARE-CRYPTO", summary)
        summary["pqc_devices_scanned"] += 1


def _run_nca_compliance(devices: list[dict], summary: dict) -> None:
    """Auto-recording, not just auto-suggesting: for every finding-mapping
    hit, this inserts a real compliance_assessments row with
    auto_recorded=true, attestation_confirmed=true (satisfying the same
    CHECK constraint a human sign-off does), and a fixed attestation
    statement disclosing that no human reviewed it. The ~60 organizational/
    mobile/supplier/cloud guidelines are untouched - they need a human's
    checklist answers, which nothing here can supply."""
    requests.post(f"{API_URL}/nca/assessments/recompute", timeout=30)

    controls = requests.get(f"{API_URL}/nca/controls", timeout=15).json()
    severity_by_control = {c["id"]: c["severity"] for c in controls}

    for device in devices:
        response = requests.get(f"{API_URL}/nca/devices/{device['device_id']}/suggestions", timeout=15)
        if response.status_code != 200:
            continue
        suggestions = response.json().get("suggestions", {})
        for control_id, suggestion in suggestions.items():
            reasons = "; ".join(suggestion.get("reasons", [])) or "automated evidence mapping"
            payload = {
                "control_id": control_id,
                "device_id": device["device_id"],
                "status": suggestion["suggested_status"],
                "severity": severity_by_control.get(control_id, "medium"),
                "finding": f"Auto-recorded by Fully Automated Run: {reasons}",
                "test_method": "automated",
                "evidence_ids": suggestion.get("evidence_ids", []),
                "assessed_by": AUTO_RECORDED_ASSESSED_BY,
                "attested_role": AUTO_RECORDED_ATTESTED_ROLE,
                "attestation_confirmed": True,
                "attestation_statement": (
                    f"Auto-recorded by Fully Automated Run from evidence "
                    f"{', '.join(suggestion.get('evidence_ids', [])) or 'n/a'} - not reviewed by a human. "
                    "Confirm before relying on it."
                ),
                "auto_recorded": True,
            }
            created = requests.post(f"{API_URL}/nca/assessments", json=payload, timeout=10)
            if created.status_code == 201:
                summary["nca_assessments_recorded"] += 1
            else:
                summary["errors"].append(
                    f"could not auto-record {control_id} for {device['device_id']}: {created.text[:200]}"
                )


def process_automated_run(run: dict) -> None:
    run_id = run["id"]
    summary = {
        "hosts_discovered": 0, "devices_registered": 0, "tests_run": 0,
        "evidence_recorded": 0, "verdicts_computed": 0,
        "vuln_intel_devices_scanned": 0, "device_cve_devices_scanned": 0,
        "pqc_devices_scanned": 0,
        "nca_assessments_recorded": 0, "errors": [],
    }

    try:
        scoped_device_ids = run.get("device_ids")

        if scoped_device_ids is None:
            if not _advance(run_id, summary, stage="discovery"):
                return
            _run_discovery_and_register(run_id, summary)
            all_devices = requests.get(f"{API_URL}/devices", timeout=15).json()
            devices = [d for d in all_devices if d["registered"]]
        else:
            all_devices = requests.get(f"{API_URL}/devices", timeout=15).json()
            by_id = {d["device_id"]: d for d in all_devices if d["registered"]}
            devices = [by_id[device_id] for device_id in scoped_device_ids if device_id in by_id]
            for device_id in scoped_device_ids:
                if device_id not in by_id:
                    summary["errors"].append(f"{device_id} is not a registered device, skipped")

        if not _advance(run_id, summary, stage="fingerprinting_and_compliance"):
            return
        _run_fingerprinting_and_sa_iot(devices, summary)

        if not _advance(run_id, summary, stage="vulnerability_intelligence"):
            return
        # Re-read the fleet first: the fingerprinting stage above just ran
        # TEST-DEVICE-ID, whose recorded evidence auto-populates
        # devices.vendor/model for any device that had none. The device-level
        # CVE lookup keys on exactly those two fields, so using the pre-
        # fingerprinting snapshot would skip every device the run itself just
        # identified.
        devices = _refresh_devices(devices, summary)
        _run_vuln_intelligence(devices, summary)

        if not _advance(run_id, summary, stage="pqc_readiness"):
            return
        _run_pqc_readiness(devices, summary)

        if not _advance(run_id, summary, stage="nca_compliance"):
            return
        _run_nca_compliance(devices, summary)

        _patch_run(run_id, {"status": "completed", "current_stage": "done", "summary": summary})
    except Exception as exc:  # noqa: BLE001 - a run must always end terminal, never hang as "running" forever
        summary["errors"].append(str(exc))
        try:
            _patch_run(run_id, {"status": "failed", "error": str(exc), "summary": summary})
        except Exception as patch_exc:  # noqa: BLE001 - best-effort; never let this mask the original failure
            print(f"automated_run_runner: could not record failure for run {run_id}: {patch_exc}", file=sys.stderr, flush=True)


def poll_automated_runs_once() -> int:
    response = requests.get(f"{API_URL}/automation/runs", params={"status": "pending"}, timeout=10)
    response.raise_for_status()
    runs = response.json()
    for run in runs:
        process_automated_run(run)
    return len(runs)
