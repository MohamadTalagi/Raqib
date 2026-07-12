"""Polls auditor-api for pending scan jobs and executes them.

This is the only place in the whole platform that actually runs a command
against a live device. auditor-api never executes anything itself - it only
manages scan_jobs rows. Every command run here comes from the fixed
policies.catalog.scan_tests whitelist: device_id/test_id are re-validated
against that catalog before anything runs, and commands are built as argv
lists (subprocess.run without shell=True), so there is no interpolation of
free-form text into a shell.
"""
import os
import subprocess
import sys
import time

import requests

from policies.catalog.scan_tests import SCAN_CATALOG, is_allowed

API_URL = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")
POLL_INTERVAL_SECONDS = float(os.environ.get("JOB_POLL_INTERVAL_SECONDS", "2"))
COMMAND_TIMEOUT_SECONDS = 30


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


def process_job(job: dict) -> None:
    job_id = job["id"]
    device_id = job["device_id"]
    test_id = job["test_id"]

    if not is_allowed(device_id, test_id):
        _patch(job_id, {"status": "failed", "error": "device_id/test_id not in the scan catalog"})
        return

    spec = SCAN_CATALOG[test_id]
    _patch(job_id, {"status": "running"})

    command = spec["build_command"](device_id)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS)
        raw_output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        _patch(job_id, {"status": "failed", "error": f"command timed out after {COMMAND_TIMEOUT_SECONDS}s"})
        return
    except Exception as exc:  # noqa: BLE001 - report any execution failure back to the job
        _patch(job_id, {"status": "failed", "error": str(exc)})
        return

    observations = spec["parse_observations"](device_id, raw_output)
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


def main() -> None:
    print(f"job_runner: polling {API_URL} every {POLL_INTERVAL_SECONDS}s", flush=True)
    while True:
        try:
            poll_once()
        except Exception as exc:  # noqa: BLE001 - never let a poll failure kill the loop
            print(f"job_runner: poll error: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
