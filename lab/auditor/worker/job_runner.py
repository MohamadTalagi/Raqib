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
from datetime import datetime, timezone

import psutil
import requests

from device_validation import (
    ValidationError,
    configure_allowed_networks,
    validate_host,
    validate_port,
    validate_service_type,
)
from policies.catalog.scan_tests import (
    SCAN_CATALOG,
    configure_active_scopes,
    is_applicable,
    is_firmware_test,
    is_network_discovery_test,
)
from lab.auditor.worker.scan_scripts import cisa_kev, oui_lookup
from lab.auditor.worker.scan_scripts.interface_detect import detect_candidate_subnets

API_URL = os.environ.get("AUDITOR_API_URL", "http://auditor-api:8000")
POLL_INTERVAL_SECONDS = float(os.environ.get("JOB_POLL_INTERVAL_SECONDS", "2"))
COMMAND_TIMEOUT_SECONDS = 30

# Vulnerability-intelligence hybrid model: firmware scans themselves never
# touch the network (scan_scripts/firmware_check.py's _run_grype only reads
# Grype's local on-disk DB) - this is the one place that does, and only
# occasionally. Checked at most every GRYPE_DB_CHECK_INTERVAL_SECONDS (not
# every 2s poll iteration); a DB update itself runs inline and blocks job
# polling for its duration - acceptable given how infrequently it fires, and
# simpler than a second thread for what's currently a once-a-week operation.
#
# Staleness is tracked via our OWN sentinel file, written after each
# successful `grype db update` - NOT via `grype db status`'s "Built" field.
# That field is when Anchore built their upstream snapshot, not when we last
# fetched it; confirmed live that it can be many weeks old even seconds after
# a fresh, successful `grype db update`, which made an earlier version of
# this check re-attempt an update on every single interval forever.
GRYPE_DB_CHECK_INTERVAL_SECONDS = float(os.environ.get("GRYPE_DB_CHECK_INTERVAL_SECONDS", str(6 * 3600)))
GRYPE_DB_MAX_AGE_SECONDS = float(os.environ.get("GRYPE_DB_MAX_AGE_SECONDS", str(7 * 24 * 3600)))
GRYPE_DB_UPDATE_TIMEOUT_SECONDS = 600
GRYPE_DB_REFRESH_SENTINEL = os.environ.get(
    "GRYPE_DB_REFRESH_SENTINEL", os.path.expanduser("~/.cache/grype/db/.vuln-intel-last-refresh"),
)

# Same hybrid model, same cadence, same sentinel-file pattern as the Grype DB
# above - CISA's KEV feed is a plain HTTPS GET (cisa_kev.py), not a
# subprocess, but the staleness bookkeeping is identical.
CISA_KEV_CHECK_INTERVAL_SECONDS = float(os.environ.get("CISA_KEV_CHECK_INTERVAL_SECONDS", str(6 * 3600)))
CISA_KEV_MAX_AGE_SECONDS = float(os.environ.get("CISA_KEV_MAX_AGE_SECONDS", str(7 * 24 * 3600)))
CISA_KEV_REFRESH_SENTINEL = os.environ.get(
    "CISA_KEV_REFRESH_SENTINEL", os.path.expanduser("~/.cache/grype/db/.cisa-kev-last-refresh"),
)

# Same hybrid model, cadence, and sentinel-file pattern again - the IEEE OUI
# (MA-L) registry (oui_lookup.py) is also a plain HTTPS GET, refreshed far
# less often than a scan runs, never fetched at scan time. It changes even
# more rarely than Grype's vuln DB or the KEV feed (IEEE assigns new OUI
# blocks, but existing entries essentially never change), so it reuses the
# same 7-day max-age default rather than inventing a third cadence.
OUI_CHECK_INTERVAL_SECONDS = float(os.environ.get("OUI_CHECK_INTERVAL_SECONDS", str(6 * 3600)))
OUI_MAX_AGE_SECONDS = float(os.environ.get("OUI_MAX_AGE_SECONDS", str(7 * 24 * 3600)))
OUI_REFRESH_SENTINEL = os.environ.get(
    "OUI_REFRESH_SENTINEL", os.path.expanduser("~/.cache/grype/db/.oui-last-refresh"),
)

_last_grype_check_monotonic: float | None = None
_last_kev_check_monotonic: float | None = None
_last_oui_check_monotonic: float | None = None

# Network Scope: unlike auditor-api, which reconfigures device_validation/
# scan_tests in-process on every write (see network_scope_routes.py), this
# worker process has no direct DB access and can only poll
# GET /network-scope/active - bounded to this interval, not every 2s poll
# iteration, since the value changes rarely.
NETWORK_SCOPE_REFRESH_INTERVAL_SECONDS = float(
    os.environ.get("NETWORK_SCOPE_REFRESH_INTERVAL_SECONDS", "15")
)
_last_network_scope_check_monotonic: float | None = None
_last_configured_cidrs: list[str] | None = None


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
    if is_network_discovery_test(test_id):
        observations = _enrich_mac_vendors(observations)
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


def _process_interface_detect(scan_id: int) -> None:
    """The worker-side half of Network Scope's "Detect automatically"
    action - see scan_scripts/interface_detect.py for the actual detection
    logic; this just wires it into the same network_scans row/poll shape
    the subnet-sweep kind below already uses, rather than a new mechanism."""
    _patch_network_scan(scan_id, {"status": "running"})
    result = detect_candidate_subnets()
    _patch_network_scan(scan_id, {
        "status": "completed",
        "tool": "psutil-interface-scan",
        "tool_version": psutil.__version__,
        "observations": result,
    })


def process_network_scan(scan: dict) -> None:
    """Runs the same subnet sweep TEST-NET-DISCOVERY uses (build_command/
    parse_observations are pure functions of `target`, which this test never
    reads - see scan_tests.py), but keyed on a network_scans row instead of
    a scan_jobs row tied to a device. This is the discovery-first onboarding
    path: scan first, then decide which hosts are worth registering.

    A network_scans row can also carry kind='interface_detect' (Network
    Scope's "Detect automatically" action) instead - same table, same poll
    loop, a different one-shot worker-side routine."""
    scan_id = scan["id"]
    if scan.get("kind", "subnet_sweep") == "interface_detect":
        _process_interface_detect(scan_id)
        return

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
    observations = _enrich_mac_vendors(observations)  # this branch is always TEST-NET-DISCOVERY
    tool_version = _tool_version(spec["tool_version_command"])

    _patch_network_scan(scan_id, {
        "status": "completed",
        "tool": spec["tool"],
        "tool_version": tool_version,
        "command": " ".join(command),
        "raw_output": raw_output,
        "observations": observations,
    })


def _sentinel_age_seconds(path: str) -> float | None:
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    return time.time() - mtime


def _touch_sentinel(path: str) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())
    except OSError as exc:
        # Non-fatal: the refresh itself did succeed, only our own staleness
        # bookkeeping failed - worst case we re-check needlessly often,
        # never silently stop refreshing.
        print(f"job_runner: could not write refresh sentinel {path}: {exc}", file=sys.stderr, flush=True)


def maybe_refresh_grype_db(now: float | None = None) -> None:
    """The scheduled half of the vulnerability-intelligence hybrid model:
    refresh Grype's local DB if we haven't successfully refreshed it within
    GRYPE_DB_MAX_AGE_SECONDS, but check no more often than
    GRYPE_DB_CHECK_INTERVAL_SECONDS. Never raises - a failed refresh leaves
    the last-good DB in place (Grype's own update mechanism swaps in the new
    DB only on success) and is retried at the next check."""
    global _last_grype_check_monotonic
    now = time.monotonic() if now is None else now
    if (
        _last_grype_check_monotonic is not None
        and (now - _last_grype_check_monotonic) < GRYPE_DB_CHECK_INTERVAL_SECONDS
    ):
        return
    _last_grype_check_monotonic = now

    sentinel_age = _sentinel_age_seconds(GRYPE_DB_REFRESH_SENTINEL)
    if sentinel_age is not None and sentinel_age < GRYPE_DB_MAX_AGE_SECONDS:
        return

    try:
        result = subprocess.run(
            ["grype", "db", "update"],
            capture_output=True, text=True, timeout=GRYPE_DB_UPDATE_TIMEOUT_SECONDS, check=False,
        )
        if result.returncode == 0:
            print("job_runner: grype db update completed", flush=True)
            _touch_sentinel(GRYPE_DB_REFRESH_SENTINEL)
        else:
            print(f"job_runner: grype db update failed: {result.stderr.strip()}", file=sys.stderr, flush=True)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"job_runner: grype db update failed: {exc}", file=sys.stderr, flush=True)


def maybe_refresh_cisa_kev(now: float | None = None) -> None:
    """Same hybrid model and sentinel pattern as maybe_refresh_grype_db, for
    CISA's KEV feed (cisa_kev.py - a plain HTTPS GET, not a subprocess).
    Never raises - a failed fetch leaves the last-good cache in place
    (cisa_kev.fetch_and_cache_kev_feed does an atomic swap only on success)
    and is retried at the next check."""
    global _last_kev_check_monotonic
    now = time.monotonic() if now is None else now
    if (
        _last_kev_check_monotonic is not None
        and (now - _last_kev_check_monotonic) < CISA_KEV_CHECK_INTERVAL_SECONDS
    ):
        return
    _last_kev_check_monotonic = now

    sentinel_age = _sentinel_age_seconds(CISA_KEV_REFRESH_SENTINEL)
    if sentinel_age is not None and sentinel_age < CISA_KEV_MAX_AGE_SECONDS:
        return

    if cisa_kev.fetch_and_cache_kev_feed():
        print("job_runner: CISA KEV feed refresh completed", flush=True)
        _touch_sentinel(CISA_KEV_REFRESH_SENTINEL)
    else:
        print("job_runner: CISA KEV feed refresh failed", file=sys.stderr, flush=True)


def maybe_refresh_oui_registry(now: float | None = None) -> None:
    """Same hybrid model and sentinel pattern as maybe_refresh_cisa_kev, for
    the IEEE OUI registry (oui_lookup.py - a plain HTTPS GET). Never raises -
    a failed fetch leaves the last-good cache in place
    (oui_lookup.fetch_and_cache_oui_registry does an atomic swap only on
    success) and is retried at the next check."""
    global _last_oui_check_monotonic
    now = time.monotonic() if now is None else now
    if (
        _last_oui_check_monotonic is not None
        and (now - _last_oui_check_monotonic) < OUI_CHECK_INTERVAL_SECONDS
    ):
        return
    _last_oui_check_monotonic = now

    sentinel_age = _sentinel_age_seconds(OUI_REFRESH_SENTINEL)
    if sentinel_age is not None and sentinel_age < OUI_MAX_AGE_SECONDS:
        return

    if oui_lookup.fetch_and_cache_oui_registry():
        print("job_runner: IEEE OUI registry refresh completed", flush=True)
        _touch_sentinel(OUI_REFRESH_SENTINEL)
    else:
        print("job_runner: IEEE OUI registry refresh failed", file=sys.stderr, flush=True)


def _enrich_mac_vendors(observations: dict) -> dict:
    """Overrides each host's mac_vendor/mac_vendor_source with a maintained
    IEEE OUI-registry lookup when one resolves, falling back to whatever
    scan_tests.py's pure parser already filled in from nmap's own bundled
    guess (never silently dropping nmap's own answer). This is a live
    filesystem read (oui_lookup.load_oui_index/lookup_vendor), so it cannot
    live inside scan_tests.py's pure build_command/parse_observations
    functions - it runs here, once per TEST-NET-DISCOVERY result, after the
    pure parser has already returned."""
    hosts = observations.get("hosts")
    if not hosts:
        return observations
    index = oui_lookup.load_oui_index()
    for host in hosts:
        mac_address = host.get("mac_address")
        if not mac_address:
            continue
        registry_vendor = oui_lookup.lookup_vendor(mac_address, index=index)
        if registry_vendor:
            host["mac_vendor"] = registry_vendor
            host["mac_vendor_source"] = "ieee_registry"
    return observations


def maybe_refresh_network_scope(now: float | None = None) -> None:
    """Keeps this worker process's in-memory allowlist
    (device_validation.ALLOWED_NETWORKS, scan_tests.ACTIVE_SCOPES) in sync
    with whatever is currently configured on the Network Scope settings
    page. auditor-api reconfigures in-process on every write
    (network_scope_routes.py); this worker has no direct DB access, so it
    polls GET /network-scope/active at a bounded interval instead - a
    change takes effect here within NETWORK_SCOPE_REFRESH_INTERVAL_SECONDS,
    not instantly, which is acceptable for a rarely-changed value. Never
    raises - a failed fetch just means this worker keeps using whatever it
    already has configured until the next successful check, the same
    "last-good state survives a failed refresh" rule
    maybe_refresh_grype_db/maybe_refresh_cisa_kev already follow."""
    global _last_network_scope_check_monotonic, _last_configured_cidrs
    now = time.monotonic() if now is None else now
    if (
        _last_network_scope_check_monotonic is not None
        and (now - _last_network_scope_check_monotonic) < NETWORK_SCOPE_REFRESH_INTERVAL_SECONDS
    ):
        return
    _last_network_scope_check_monotonic = now

    try:
        response = requests.get(f"{API_URL}/network-scope/active", timeout=10)
        response.raise_for_status()
        cidrs = response.json()["cidrs"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        print(f"job_runner: network scope refresh failed: {exc}", file=sys.stderr, flush=True)
        return

    if cidrs != _last_configured_cidrs:
        configure_allowed_networks(cidrs)
        configure_active_scopes(cidrs)
        _last_configured_cidrs = cidrs
        print(f"job_runner: network scope reconfigured to {cidrs}", flush=True)


def poll_network_scans_once() -> int:
    response = requests.get(f"{API_URL}/network-scans", params={"status": "pending"}, timeout=10)
    response.raise_for_status()
    scans = response.json()
    for scan in scans:
        process_network_scan(scan)
    return len(scans)


def main() -> None:
    # Imported here, not at module top-level: automated_run_runner.py itself
    # imports process_job/process_network_scan from this module, so a
    # top-level import here would be circular. By the time main() runs,
    # job_runner is fully loaded, so automated_run_runner can safely import
    # from it.
    from automated_run_runner import poll_automated_runs_once

    print(f"job_runner: polling {API_URL} every {POLL_INTERVAL_SECONDS}s", flush=True)
    while True:
        try:
            maybe_refresh_network_scope()
            poll_once()
            poll_network_scans_once()
            poll_automated_runs_once()
            maybe_refresh_grype_db()
            maybe_refresh_cisa_kev()
            maybe_refresh_oui_registry()
        except Exception as exc:  # noqa: BLE001 - never let a poll failure kill the loop
            print(f"job_runner: poll error: {exc}", file=sys.stderr, flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
