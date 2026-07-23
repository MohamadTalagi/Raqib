"""Polls auditor-api for pending scan jobs and executes them.

This is the only place in the whole platform that actually runs a command
against a live device. auditor-api never executes anything itself - it only
manages scan_jobs rows. The database is treated as untrusted input: the
target read back from GET /scan-jobs is re-validated by resolve_target
(the second of two independent validation passes - the API validates at
registration time, this module validates again at execute time) before any
command is built, and commands are built as argv lists (subprocess.run
without shell=True), so there is no interpolation of free-form text into a
shell.
"""
import os
import subprocess
import sys
import time

import requests

from device_validation import (
    ValidationError,
    validate_host,
    validate_port,
    validate_service_type,
)
from policies.catalog.scan_tests import (
    SCAN_CATALOG,
    is_applicable,
    is_firmware_test,
    is_network_discovery_test,
)

API_URL = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")
POLL_INTERVAL_SECONDS = float(os.environ.get("JOB_POLL_INTERVAL_SECONDS", "2"))
COMMAND_TIMEOUT_SECONDS = 30


def resolve_target(job: dict) -> dict:
    """Re-validate the target read from the database before building a command.

    The database is untrusted input: a row written by a buggy or older API
    version must still be refused here. This is the second of the two
    independent validation passes.

    Firmware tests have no host/service_type/port at all - they inspect an
    uploaded archive keyed only by device_id - so they skip the live-target
    validators entirely rather than failing them on empty/None input.
    Network-discovery tests are the same shape: they sweep the whole
    audit-network subnet rather than one device's host/port.
    """
    if is_firmware_test(job["test_id"]) or is_network_discovery_test(job["test_id"]):
        return {"device_id": job["device_id"], "host": None, "service_type": None, "port": None}
    return {
        "device_id": job["device_id"],
        "host": validate_host(job.get("host", "")),
        "service_type": validate_service_type(job.get("service_type", "")),
        "port": validate_port(job.get("port")),
    }


def _tool_version(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        text = (result.stdout or result.stderr or "").strip()
        return text.splitlines()[0] if text else "unknown"
    except Exception:
        return "unknown"


def _patch(job_id: int, fields: dict) -> None:
    response = requests.patch(f"{API_URL}/scan-jobs/{job_id}", json=fields, timeout=10)
    response.raise_for_status()


def _record_failure(job_id: int, error_detail: str) -> None:
    """Called only when the collector genuinely attempted to run and failed
    (timeout, execution exception) - not for pre-execution rejections like an
    invalid target or an inapplicable test/service combo, which are
    configuration mismatches rather than a real collector run gone wrong.
    Deterministically produces INCONCLUSIVE evidence server-side (see
    main.py's record_scan_job_failure) rather than leaving the control
    silently unassessed."""
    response = requests.post(
        f"{API_URL}/scan-jobs/{job_id}/record-failure", json={"error_detail": error_detail}, timeout=10
    )
    response.raise_for_status()


def process_job(job: dict) -> None:
    job_id = job["id"]
    test_id = job["test_id"]

    try:
        target = resolve_target(job)
    except ValidationError as exc:
        _patch(job_id, {"status": "failed", "error": f"invalid target: {exc.message}"})
        return

    # is_applicable() gates on service_type, which firmware and
    # network-discovery tests don't have (applicable_service_types=() would
    # always return False for them).
    if (
        not is_firmware_test(test_id)
        and not is_network_discovery_test(test_id)
        and not is_applicable(target, test_id)
    ):
        _patch(job_id, {"status": "failed", "error": "test does not apply to this service"})
        return

    spec = SCAN_CATALOG[test_id]
    _patch(job_id, {"status": "running"})

    command = spec["build_command"](target)
    timeout_seconds = spec.get("timeout_seconds", COMMAND_TIMEOUT_SECONDS)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
        raw_output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        _record_failure(job_id, f"command timed out after {timeout_seconds}s")
        return
    except Exception as exc:  # noqa: BLE001 - report any execution failure back to the job
        _record_failure(job_id, str(exc))
        return

    observations = spec["parse_observations"](target, raw_output)
    tool_version = _tool_version(spec["tool_version_command"])

    _patch(job_id, {
        "status": "awaiting_finding",
        "tool": spec["tool"],
        "tool_version": tool_version,
        "command": " ".join(command),
        "raw_output": raw_output,
        "observations": observations,
    })


def poll_once() -> int:
    response = requests.get(f"{API_URL}/scan-jobs", params={"status": "pending"}, timeout=10)
    response.raise_for_status()
    jobs = response.json()
    for job in jobs:
        process_job(job)
    return len(jobs)


def _patch_network_scan(scan_id: int, fields: dict) -> None:
    response = requests.patch(f"{API_URL}/network-scans/{scan_id}", json=fields, timeout=10)
    response.raise_for_status()


def process_network_scan(scan: dict) -> None:
    """Runs the same subnet sweep TEST-NET-DISCOVERY uses (build_command/
    parse_observations are pure functions of `target`, which this test never
    reads - see scan_tests.py), but keyed on a network_scans row instead of
    a scan_jobs row tied to a device. This is the discovery-first onboarding
    path: scan first, then decide which hosts are worth registering."""
    scan_id = scan["id"]
    spec = SCAN_CATALOG["TEST-NET-DISCOVERY"]
    _patch_network_scan(scan_id, {"status": "running"})

    target: dict = {}
    command = spec["build_command"](target)
    timeout_seconds = spec.get("timeout_seconds", COMMAND_TIMEOUT_SECONDS)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
        raw_output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        _patch_network_scan(scan_id, {"status": "failed", "error": f"command timed out after {timeout_seconds}s"})
        return
    except Exception as exc:  # noqa: BLE001 - report any execution failure back to the scan
        _patch_network_scan(scan_id, {"status": "failed", "error": str(exc)})
        return

    observations = spec["parse_observations"](target, raw_output)
    tool_version = _tool_version(spec["tool_version_command"])

    _patch_network_scan(scan_id, {
        "status": "completed",
        "tool": spec["tool"],
        "tool_version": tool_version,
        "command": " ".join(command),
        "raw_output": raw_output,
        "observations": observations,
    })


def poll_network_scans_once() -> int:
    response = requests.get(f"{API_URL}/network-scans", params={"status": "pending"}, timeout=10)
    response.raise_for_status()
    scans = response.json()
    for scan in scans:
        process_network_scan(scan)
    return len(scans)


def main() -> None:
    print(f"job_runner: polling {API_URL} every {POLL_INTERVAL_SECONDS}s", flush=True)
    while True:
        try:
            poll_once()
            poll_network_scans_once()
        except Exception as exc:  # noqa: BLE001 - never let a poll failure kill the loop
            print(f"job_runner: poll error: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
