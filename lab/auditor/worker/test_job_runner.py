import subprocess
from unittest.mock import MagicMock, patch

import requests

import job_runner
from job_runner import (
    maybe_refresh_grype_db,
    maybe_refresh_network_scope,
    poll_once,
    poll_network_scans_once,
    process_job,
    process_network_scan,
)


def _mock_completed(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_runs_whitelisted_command_and_marks_awaiting_finding(mock_run, mock_patch):
    mock_run.side_effect = [
        _mock_completed(stdout="80/tcp   open  http\n"),  # the scan itself
        _mock_completed(stdout="Nmap version 7.95\n"),     # tool --version probe
    ]

    process_job({
        "id": 1, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "http", "port": 80,
    })

    scan_call_args = mock_run.call_args_list[0].args[0]
    assert scan_call_args[0] == "nmap"
    assert "device-insecure" in scan_call_args

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "awaiting_finding"
    observations = final_call.kwargs["json"]["observations"]
    assert observations["open_ports"] == [80]
    assert final_call.kwargs["json"]["tool"] == "nmap"


@patch("job_runner.requests.patch")
def test_process_job_rejects_disallowed_device_test_combo(mock_patch):
    # telnet-sim only exposes telnet, so the HTTP-only default-creds test does
    # not apply - rejected by is_applicable, not a device/test whitelist.
    process_job({
        "id": 2, "device_id": "telnet-sim", "test_id": "TEST-AUTH-DEFAULT-CREDS",
        "host": "telnet-sim", "service_type": "telnet", "port": 23,
    })

    mock_patch.assert_called_once()
    call = mock_patch.call_args
    assert call.kwargs["json"]["status"] == "failed"
    assert "error" in call.kwargs["json"]


@patch("job_runner.requests.post")
@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_marks_failed_on_timeout(mock_run, mock_patch, mock_post):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=30)

    process_job({
        "id": 3, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "http", "port": 80,
    })

    # A genuine collector failure (as opposed to a pre-execution rejection)
    # calls record-failure, which the API turns into INCONCLUSIVE evidence -
    # never left silent, never a plain PATCH to "failed" with no evidence.
    # requests.patch is still called once, for the earlier "running" transition.
    assert mock_patch.call_args_list[-1].kwargs["json"]["status"] == "running"
    final_call = mock_post.call_args_list[-1]
    assert "record-failure" in final_call.args[0]
    assert "timed out" in final_call.kwargs["json"]["error_detail"]


@patch("job_runner.requests.post")
@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_marks_inconclusive_on_nonzero_exit(mock_run, mock_patch, mock_post):
    # A collector that runs and exits non-zero (e.g. curl: connection
    # refused) must be treated exactly like a timeout - real INCONCLUSIVE
    # evidence via record-failure, never a false "clean" awaiting_finding
    # result built from whatever near-empty output the failed run produced.
    mock_run.return_value = _mock_completed(stdout="", stderr="curl: (7) Failed to connect", returncode=7)

    process_job({
        "id": 13, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "http", "port": 80,
    })

    assert mock_patch.call_args_list[-1].kwargs["json"]["status"] == "running"
    final_call = mock_post.call_args_list[-1]
    assert "record-failure" in final_call.args[0]
    detail = final_call.kwargs["json"]["error_detail"]
    assert "exited with status 7" in detail
    assert "Failed to connect" in detail


@patch("job_runner.requests.post")
@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_network_discovery_stage_a_nonzero_exit_never_attempts_stage_b(mock_run, mock_patch, mock_post):
    mock_run.return_value = _mock_completed(stdout="", stderr="nmap: bad option", returncode=1)

    process_job({
        "id": 14, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    })

    # Only the one (failed) Stage A call - never a second attempt.
    assert mock_run.call_count == 1
    final_call = mock_post.call_args_list[-1]
    assert "record-failure" in final_call.args[0]
    detail = final_call.kwargs["json"]["error_detail"]
    assert "discovery phase (Stage A)" in detail
    assert "exited with status 1" in detail


@patch("job_runner.requests.post")
@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_network_discovery_stage_b_nonzero_exit_reports_failure(mock_run, mock_patch, mock_post):
    mock_run.side_effect = [
        _mock_completed(stdout="Nmap scan report for 172.30.0.5\nHost is up.\n"),  # Stage A - succeeds
        _mock_completed(stdout="nmap version 7.95\n"),  # tool --version probe
        _mock_completed(stdout="", stderr="nmap: fatal error", returncode=1),  # Stage B - fails
    ]

    process_job({
        "id": 15, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    })

    final_call = mock_post.call_args_list[-1]
    assert "record-failure" in final_call.args[0]
    detail = final_call.kwargs["json"]["error_detail"]
    assert "service-scan phase (Stage B)" in detail
    assert "exited with status 1" in detail


@patch("job_runner.requests.get")
@patch("job_runner.process_job")
def test_poll_once_processes_every_pending_job(mock_process_job, mock_get):
    response = MagicMock()
    response.json.return_value = [
        {"id": 10, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"},
        {"id": 11, "device_id": "device-hardened", "test_id": "TEST-AUTH-DEFAULT-CREDS"},
    ]
    response.raise_for_status.return_value = None
    mock_get.return_value = response

    count = poll_once()

    assert count == 2
    assert mock_process_job.call_count == 2
    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["params"] == {"status": "pending"}


import pytest

from device_validation import ValidationError
from job_runner import resolve_target


def test_rejects_malicious_host_written_directly_to_the_database():
    # Simulates a row that bypassed the API entirely (buggy or older version).
    # The worker must not trust the database.
    job = {
        "id": 1, "device_id": "evil", "test_id": "TEST-NET-PORTSCAN",
        "host": "--script=http-shellshock", "service_type": "http", "port": 80,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_rejects_out_of_range_host_from_the_database():
    job = {
        "id": 2, "device_id": "evil", "test_id": "TEST-NET-PORTSCAN",
        "host": "10.0.0.5", "service_type": "http", "port": 80,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_rejects_job_whose_device_was_deregistered():
    # The LEFT JOIN yields NULLs when the device row is gone, so the job must
    # fail cleanly rather than crash the poll loop.
    job = {
        "id": 4, "device_id": "gone", "test_id": "TEST-NET-PORTSCAN",
        "host": None, "service_type": None, "port": None,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_rejects_bogus_service_type_from_the_database():
    # resolve_target's docstring promises host AND port get re-validated on
    # this second pass; service_type must get the same treatment, since it is
    # read raw from the (untrusted) database row just like host and port are.
    job = {
        "id": 5, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "gopher", "port": 80,
    }
    with pytest.raises(ValidationError):
        resolve_target(job)


def test_accepts_a_legitimate_target():
    job = {
        "id": 3, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "http", "port": 80,
    }
    assert resolve_target(job) == {
        "device_id": "device-insecure", "host": "device-insecure",
        "service_type": "http", "port": 80,
    }


def test_firmware_job_bypasses_live_target_validators_entirely():
    # A firmware job's row has no host/service_type/port at all - unlike the
    # live-device tests above, empty/None values here must NOT raise, since
    # firmware tests never had a network target to validate in the first place.
    job = {
        "id": 6, "device_id": "device-insecure", "test_id": "TEST-FW-SECRETS",
        "host": None, "service_type": None, "port": None,
    }
    assert resolve_target(job) == {
        "device_id": "device-insecure", "host": None, "service_type": None, "port": None,
    }


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_runs_a_firmware_test_without_a_live_target(mock_run, mock_patch):
    mock_run.side_effect = [
        _mock_completed(stdout="hardcoded_secret_found=True\n"),
        _mock_completed(stdout="yara 4.5.1\n"),
    ]

    process_job({
        "id": 7, "device_id": "device-insecure", "test_id": "TEST-FW-SECRETS",
        "host": None, "service_type": None, "port": None,
    })

    scan_call_args = mock_run.call_args_list[0].args[0]
    assert scan_call_args[-2:] == ["device-insecure", "secrets"]

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "awaiting_finding"
    assert final_call.kwargs["json"]["observations"]["hardcoded_secret_found"] is True


def test_network_discovery_job_bypasses_live_target_validators_entirely():
    # Same shape as the firmware case: a subnet-wide test's row has no
    # host/service_type/port at all, and None here must not raise.
    job = {
        "id": 8, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    }
    assert resolve_target(job) == {
        "device_id": "device-insecure", "host": None, "service_type": None, "port": None,
    }


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_runs_a_network_discovery_test_two_stage(mock_run, mock_patch):
    # Stage A (a fast -sn ping sweep) finds a live host, then Stage B (the
    # full -sV scan) targets that host specifically - both real subprocess
    # calls, in order, not one flat sweep.
    mock_run.side_effect = [
        _mock_completed(stdout="Nmap scan report for 172.30.0.5\nHost is up.\n"),  # Stage A
        _mock_completed(stdout="nmap version 7.95\n"),  # tool --version probe
        _mock_completed(
            stdout="Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-03 00:00 UTC\n"
            "Nmap scan report for device-insecure (172.30.0.5)\nHost is up.\n\n"
            "PORT     STATE SERVICE VERSION\n80/tcp   open  http\n\n",
        ),  # Stage B
    ]

    process_job({
        "id": 9, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    })

    stage_a_call = mock_run.call_args_list[0].args[0]
    assert stage_a_call[0] == "nmap"
    assert "-sn" in stage_a_call
    assert "172.30.0.0/24" in stage_a_call

    stage_b_call = mock_run.call_args_list[2].args[0]
    assert stage_b_call[0] == "nmap"
    assert "-sV" in stage_b_call
    assert "172.30.0.5" in stage_b_call
    # Targets the live host explicitly, not the whole scope - the point of
    # two-stage discovery.
    assert "172.30.0.0/24" not in stage_b_call

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "awaiting_finding"
    hosts = final_call.kwargs["json"]["observations"]["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "172.30.0.5"
    assert hosts[0]["classification"] == "iot_device"
    # Stage A's own raw output is preserved, never silently discarded.
    assert "Stage A" in final_call.kwargs["json"]["raw_output"]
    assert "Stage B" in final_call.kwargs["json"]["raw_output"]


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_network_discovery_short_circuits_on_zero_live_hosts(mock_run, mock_patch):
    # A real, honest, valid outcome - Stage B must never run when Stage A
    # found nothing to target.
    mock_run.side_effect = [
        _mock_completed(stdout="Nmap done: 256 IP addresses (0 hosts up) scanned in 11.00 seconds\n"),
        _mock_completed(stdout="nmap version 7.95\n"),
    ]

    process_job({
        "id": 10, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    })

    # Only Stage A + the tool-version probe ran - no third (Stage B) call.
    assert mock_run.call_count == 2

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "awaiting_finding"
    observations = final_call.kwargs["json"]["observations"]
    assert observations["hosts"] == []
    assert any("No live hosts" in note for note in observations["notes"])


@patch("job_runner.requests.post")
@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_network_discovery_stage_a_failure_never_attempts_stage_b(mock_run, mock_patch, mock_post):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=22)

    process_job({
        "id": 11, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    })

    # Only the one (failed) Stage A call - never a second attempt.
    assert mock_run.call_count == 1
    # A genuine collector failure calls record-failure (real INCONCLUSIVE
    # evidence server-side), same as every other test's collector-failure
    # path - never a silent plain PATCH.
    final_call = mock_post.call_args_list[-1]
    assert "record-failure" in final_call.args[0]
    assert "discovery phase (Stage A)" in final_call.kwargs["json"]["error_detail"]


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_network_discovery_stage_timeouts_reach_subprocess_run(mock_run, mock_patch):
    # Each stage gets its own estimated timeout, not job_runner's flat
    # default - confirm the real computed values actually reach
    # subprocess.run, not just that some number does.
    from policies.catalog.scan_tests import estimate_stage_a_timeout, estimate_stage_b_timeout

    mock_run.side_effect = [
        _mock_completed(stdout="Nmap scan report for 172.30.0.5\nHost is up.\n"),
        _mock_completed(stdout="nmap version 7.95\n"),
        _mock_completed(stdout="Nmap scan report for device-insecure (172.30.0.5)\nHost is up.\n"),
    ]

    process_job({
        "id": 12, "device_id": "device-insecure", "test_id": "TEST-NET-DISCOVERY",
        "host": None, "service_type": None, "port": None,
    })

    assert mock_run.call_args_list[0].kwargs["timeout"] == estimate_stage_a_timeout(["172.30.0.0/24"])
    assert mock_run.call_args_list[2].kwargs["timeout"] == estimate_stage_b_timeout(1)


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_network_scan_runs_the_sweep_and_marks_completed(mock_run, mock_patch):
    # A network_scans row is not tied to any device at all - this is the
    # discovery-first onboarding path, distinct from a scan_jobs row.
    mock_run.side_effect = [
        _mock_completed(stdout="Nmap scan report for 172.30.0.6\nHost is up.\n"),  # Stage A
        _mock_completed(stdout="nmap version 7.95\n"),  # tool --version probe
        _mock_completed(
            stdout="Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-03 00:00 UTC\n"
            "Nmap scan report for device-insecure (172.30.0.6)\nHost is up.\n\n"
            "PORT     STATE SERVICE VERSION\n80/tcp   open  http\n\n",
        ),  # Stage B
    ]

    process_network_scan({"id": 1, "status": "pending"})

    stage_a_call = mock_run.call_args_list[0].args[0]
    assert stage_a_call[0] == "nmap"
    assert "172.30.0.0/24" in stage_a_call
    # Stage A's own estimated timeout, not job_runner's flat default.
    from policies.catalog.scan_tests import estimate_stage_a_timeout
    assert mock_run.call_args_list[0].kwargs["timeout"] == estimate_stage_a_timeout(["172.30.0.0/24"])

    calls = mock_patch.call_args_list
    assert calls[0].args[0] == "http://auditor-api:8000/network-scans/1"
    assert calls[0].kwargs["json"]["status"] == "running"
    final_call = calls[-1]
    assert final_call.kwargs["json"]["status"] == "completed"
    assert final_call.kwargs["json"]["observations"]["hosts"][0]["ip"] == "172.30.0.6"


@patch("job_runner.requests.patch")
@patch("job_runner.detect_candidate_subnets")
def test_process_network_scan_dispatches_interface_detect_kind_without_running_nmap(mock_detect, mock_patch):
    mock_detect.return_value = {
        "candidates": [{"interface": "eth0", "cidr": "172.30.0.0/24"}],
        "excluded_backend_subnet": "172.31.0.0/24",
    }

    process_network_scan({"id": 5, "status": "pending", "kind": "interface_detect"})

    mock_detect.assert_called_once()
    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "completed"
    assert final_call.kwargs["json"]["tool"] == "psutil-interface-scan"
    assert final_call.kwargs["json"]["observations"]["excluded_backend_subnet"] == "172.31.0.0/24"


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_network_scan_defaults_to_subnet_sweep_kind(mock_run, mock_patch):
    # A row with no `kind` at all (the shape before this migration) must
    # still run the real (two-stage) sweep, not silently do nothing.
    mock_run.side_effect = [
        _mock_completed(stdout="Nmap done: 256 IP addresses (0 hosts up) scanned in 11.00 seconds\n"),
        _mock_completed(stdout="nmap version 7.95\n"),
    ]

    process_network_scan({"id": 6, "status": "pending"})

    assert mock_run.call_args_list[0].args[0][0] == "nmap"


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_uses_the_default_timeout_for_a_test_with_no_override(mock_run, mock_patch):
    mock_run.side_effect = [
        _mock_completed(stdout="80/tcp   open  http\n"),
        _mock_completed(stdout="Nmap version 7.95\n"),
    ]

    process_job({
        "id": 20, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
        "host": "device-insecure", "service_type": "http", "port": 80,
    })

    assert mock_run.call_args_list[0].kwargs["timeout"] == 30


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_network_scan_marks_failed_on_timeout(mock_run, mock_patch):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=30)

    process_network_scan({"id": 2, "status": "pending"})

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "failed"
    assert "timed out" in final_call.kwargs["json"]["error"]


@patch("job_runner.requests.get")
@patch("job_runner.process_network_scan")
def test_poll_network_scans_once_processes_every_pending_scan(mock_process_scan, mock_get):
    response = MagicMock()
    response.json.return_value = [{"id": 5, "status": "pending"}, {"id": 6, "status": "pending"}]
    response.raise_for_status.return_value = None
    mock_get.return_value = response

    count = poll_network_scans_once()

    assert count == 2
    assert mock_process_scan.call_count == 2
    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["params"] == {"status": "pending"}


# -- Grype DB scheduled refresh (vulnerability intelligence) ----------------
#
# Staleness is tracked via our OWN sentinel file (touched after a successful
# `grype db update`), not via grype's own "Built" field - that field reflects
# when Anchore built their upstream snapshot, not when we last fetched it,
# and comparing it against wall-clock time made an earlier version of this
# check re-attempt an update on every single interval forever (caught live:
# a real, freshly-updated DB's "Built" date was still 100+ real days old).


@patch("job_runner.subprocess.run")
def test_maybe_refresh_grype_db_skips_check_within_the_interval(mock_run, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_grype_check_monotonic", 100.0)
    maybe_refresh_grype_db(now=100.0 + job_runner.GRYPE_DB_CHECK_INTERVAL_SECONDS - 1)
    mock_run.assert_not_called()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.subprocess.run")
def test_maybe_refresh_grype_db_updates_when_sentinel_is_stale(mock_run, mock_age, monkeypatch, tmp_path):
    monkeypatch.setattr(job_runner, "_last_grype_check_monotonic", None)
    monkeypatch.setattr(job_runner, "GRYPE_DB_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = job_runner.GRYPE_DB_MAX_AGE_SECONDS + 1
    mock_run.return_value = _mock_completed(returncode=0)

    maybe_refresh_grype_db(now=0.0)

    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == ["grype", "db", "update"]
    assert (tmp_path / "sentinel").exists()  # a successful update touches it


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.subprocess.run")
def test_maybe_refresh_grype_db_skips_update_when_sentinel_is_fresh(mock_run, mock_age, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_grype_check_monotonic", None)
    mock_age.return_value = 60.0

    maybe_refresh_grype_db(now=0.0)

    mock_run.assert_not_called()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.subprocess.run")
def test_maybe_refresh_grype_db_updates_when_sentinel_is_missing(mock_run, mock_age, monkeypatch, tmp_path):
    # No prior successful refresh at all (fresh volume) - must attempt an
    # update rather than silently doing nothing forever.
    monkeypatch.setattr(job_runner, "_last_grype_check_monotonic", None)
    monkeypatch.setattr(job_runner, "GRYPE_DB_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None
    mock_run.return_value = _mock_completed(returncode=0)

    maybe_refresh_grype_db(now=0.0)

    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == ["grype", "db", "update"]


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.subprocess.run")
def test_maybe_refresh_grype_db_never_raises_when_update_fails(mock_run, mock_age, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_grype_check_monotonic", None)
    mock_age.return_value = None
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["grype", "db", "update"], timeout=600)

    maybe_refresh_grype_db(now=0.0)  # must not raise


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.subprocess.run")
def test_maybe_refresh_grype_db_does_not_touch_sentinel_on_failed_update(mock_run, mock_age, monkeypatch, tmp_path):
    monkeypatch.setattr(job_runner, "_last_grype_check_monotonic", None)
    monkeypatch.setattr(job_runner, "GRYPE_DB_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None
    mock_run.return_value = _mock_completed(returncode=1, stderr="network unreachable")

    maybe_refresh_grype_db(now=0.0)

    assert not (tmp_path / "sentinel").exists()


def test_sentinel_age_seconds_returns_none_when_sentinel_does_not_exist(tmp_path):
    assert job_runner._sentinel_age_seconds(str(tmp_path / "does-not-exist")) is None


def test_touch_sentinel_creates_parent_directories(tmp_path):
    sentinel = tmp_path / "nested" / "dir" / "sentinel"
    job_runner._touch_sentinel(str(sentinel))
    assert sentinel.exists()


# -- CISA KEV scheduled refresh (vulnerability intelligence) ----------------
# Same sentinel-based staleness pattern as the Grype DB refresh above, just
# fetching over HTTPS (cisa_kev.py) instead of shelling out to a subprocess.


@patch("job_runner.cisa_kev.fetch_and_cache_kev_feed")
def test_maybe_refresh_cisa_kev_skips_check_within_the_interval(mock_fetch, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_kev_check_monotonic", 100.0)
    job_runner.maybe_refresh_cisa_kev(now=100.0 + job_runner.CISA_KEV_CHECK_INTERVAL_SECONDS - 1)
    mock_fetch.assert_not_called()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.cisa_kev.fetch_and_cache_kev_feed")
def test_maybe_refresh_cisa_kev_fetches_when_sentinel_is_stale(mock_fetch, mock_age, monkeypatch, tmp_path):
    monkeypatch.setattr(job_runner, "_last_kev_check_monotonic", None)
    monkeypatch.setattr(job_runner, "CISA_KEV_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = job_runner.CISA_KEV_MAX_AGE_SECONDS + 1
    mock_fetch.return_value = True

    job_runner.maybe_refresh_cisa_kev(now=0.0)

    mock_fetch.assert_called_once()
    assert (tmp_path / "sentinel").exists()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.cisa_kev.fetch_and_cache_kev_feed")
def test_maybe_refresh_cisa_kev_skips_fetch_when_sentinel_is_fresh(mock_fetch, mock_age, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_kev_check_monotonic", None)
    mock_age.return_value = 60.0

    job_runner.maybe_refresh_cisa_kev(now=0.0)

    mock_fetch.assert_not_called()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.cisa_kev.fetch_and_cache_kev_feed")
def test_maybe_refresh_cisa_kev_does_not_touch_sentinel_on_failed_fetch(mock_fetch, mock_age, monkeypatch, tmp_path):
    monkeypatch.setattr(job_runner, "_last_kev_check_monotonic", None)
    monkeypatch.setattr(job_runner, "CISA_KEV_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None
    mock_fetch.return_value = False

    job_runner.maybe_refresh_cisa_kev(now=0.0)

    assert not (tmp_path / "sentinel").exists()


# -- IEEE OUI registry scheduled refresh (network discovery MAC-vendor) -----
# Same sentinel-based staleness pattern again, fetching over HTTPS
# (oui_lookup.py) instead of shelling out to a subprocess.


@patch("job_runner.oui_lookup.fetch_and_cache_oui_registry")
def test_maybe_refresh_oui_registry_skips_check_within_the_interval(mock_fetch, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_oui_check_monotonic", 100.0)
    job_runner.maybe_refresh_oui_registry(now=100.0 + job_runner.OUI_CHECK_INTERVAL_SECONDS - 1)
    mock_fetch.assert_not_called()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.oui_lookup.fetch_and_cache_oui_registry")
def test_maybe_refresh_oui_registry_fetches_when_sentinel_is_stale(mock_fetch, mock_age, monkeypatch, tmp_path):
    monkeypatch.setattr(job_runner, "_last_oui_check_monotonic", None)
    monkeypatch.setattr(job_runner, "OUI_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = job_runner.OUI_MAX_AGE_SECONDS + 1
    mock_fetch.return_value = True

    job_runner.maybe_refresh_oui_registry(now=0.0)

    mock_fetch.assert_called_once()
    assert (tmp_path / "sentinel").exists()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.oui_lookup.fetch_and_cache_oui_registry")
def test_maybe_refresh_oui_registry_skips_fetch_when_sentinel_is_fresh(mock_fetch, mock_age, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_oui_check_monotonic", None)
    mock_age.return_value = 60.0

    job_runner.maybe_refresh_oui_registry(now=0.0)

    mock_fetch.assert_not_called()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.oui_lookup.fetch_and_cache_oui_registry")
def test_maybe_refresh_oui_registry_does_not_touch_sentinel_on_failed_fetch(mock_fetch, mock_age, monkeypatch, tmp_path):
    monkeypatch.setattr(job_runner, "_last_oui_check_monotonic", None)
    monkeypatch.setattr(job_runner, "OUI_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None
    mock_fetch.return_value = False

    job_runner.maybe_refresh_oui_registry(now=0.0)

    assert not (tmp_path / "sentinel").exists()


# -- MAC-vendor enrichment (network discovery) -------------------------------
# oui_lookup.py needs a live filesystem read, so it cannot live inside
# scan_tests.py's pure parse_observations - job_runner enriches after the
# fact instead.


@patch("job_runner.oui_lookup.load_oui_index")
@patch("job_runner.oui_lookup.lookup_vendor")
def test_enrich_mac_vendors_overrides_with_a_registry_match(mock_lookup, mock_index):
    mock_index.return_value = {"286FB9": "Nokia Shanghai Bell Co., Ltd."}
    mock_lookup.return_value = "Nokia Shanghai Bell Co., Ltd."
    observations = {"hosts": [{"mac_address": "28:6F:B9:11:22:33", "mac_vendor": None, "mac_vendor_source": None}]}

    result = job_runner._enrich_mac_vendors(observations)

    host = result["hosts"][0]
    assert host["mac_vendor"] == "Nokia Shanghai Bell Co., Ltd."
    assert host["mac_vendor_source"] == "ieee_registry"


@patch("job_runner.oui_lookup.load_oui_index")
@patch("job_runner.oui_lookup.lookup_vendor")
def test_enrich_mac_vendors_falls_back_to_nmaps_own_bundled_guess_when_registry_has_no_match(mock_lookup, mock_index):
    mock_index.return_value = {}
    mock_lookup.return_value = None
    observations = {
        "hosts": [{"mac_address": "AC:DE:48:00:11:22", "mac_vendor": "Some Real Vendor Inc.", "mac_vendor_source": "nmap_bundled"}],
    }

    result = job_runner._enrich_mac_vendors(observations)

    host = result["hosts"][0]
    assert host["mac_vendor"] == "Some Real Vendor Inc."
    assert host["mac_vendor_source"] == "nmap_bundled"


@patch("job_runner.oui_lookup.load_oui_index")
@patch("job_runner.oui_lookup.lookup_vendor")
def test_enrich_mac_vendors_leaves_hosts_with_no_mac_address_untouched(mock_lookup, mock_index):
    mock_index.return_value = {}
    observations = {"hosts": [{"mac_address": None, "mac_vendor": None, "mac_vendor_source": None}]}

    result = job_runner._enrich_mac_vendors(observations)

    assert result["hosts"][0]["mac_vendor"] is None
    mock_lookup.assert_not_called()


def test_enrich_mac_vendors_handles_observations_with_no_hosts_key():
    assert job_runner._enrich_mac_vendors({}) == {}


# -- Network Scope refresh (auditor-worker has no direct DB access) ---------


@patch("job_runner.requests.get")
def test_maybe_refresh_network_scope_skips_check_within_the_interval(mock_get, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_network_scope_check_monotonic", 100.0)
    maybe_refresh_network_scope(now=100.0 + job_runner.NETWORK_SCOPE_REFRESH_INTERVAL_SECONDS - 1)
    mock_get.assert_not_called()


@patch("job_runner.configure_active_scopes")
@patch("job_runner.configure_allowed_networks")
@patch("job_runner.requests.get")
def test_maybe_refresh_network_scope_reconfigures_on_change(mock_get, mock_configure_allowed, mock_configure_active, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_network_scope_check_monotonic", None)
    monkeypatch.setattr(job_runner, "_last_configured_cidrs", ["172.30.0.0/24"])
    mock_get.return_value = MagicMock(
        json=lambda: {"cidrs": ["172.30.0.0/24", "10.4.0.0/24"]},
        raise_for_status=lambda: None,
    )

    maybe_refresh_network_scope(now=0.0)

    mock_configure_allowed.assert_called_once_with(["172.30.0.0/24", "10.4.0.0/24"])
    mock_configure_active.assert_called_once_with(["172.30.0.0/24", "10.4.0.0/24"])
    assert job_runner._last_configured_cidrs == ["172.30.0.0/24", "10.4.0.0/24"]


@patch("job_runner.configure_active_scopes")
@patch("job_runner.configure_allowed_networks")
@patch("job_runner.requests.get")
def test_maybe_refresh_network_scope_skips_reconfigure_when_unchanged(mock_get, mock_configure_allowed, mock_configure_active, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_network_scope_check_monotonic", None)
    monkeypatch.setattr(job_runner, "_last_configured_cidrs", ["172.30.0.0/24"])
    mock_get.return_value = MagicMock(
        json=lambda: {"cidrs": ["172.30.0.0/24"]},
        raise_for_status=lambda: None,
    )

    maybe_refresh_network_scope(now=0.0)

    mock_configure_allowed.assert_not_called()
    mock_configure_active.assert_not_called()


@patch("job_runner.requests.get")
def test_maybe_refresh_network_scope_never_raises_on_a_failed_fetch(mock_get, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_network_scope_check_monotonic", None)
    mock_get.side_effect = job_runner.requests.RequestException("connection refused")

    maybe_refresh_network_scope(now=0.0)  # must not raise


# -- NVD device-CVE index scheduled refresh --------------------------------
# Fourth use of the same sentinel-based staleness pattern. The one structural
# difference from the other three: this refresher is fleet-scoped, so it asks
# auditor-api which devices exist before deciding what (if anything) to fetch.


@patch("job_runner.nvd_lookup.fetch_and_cache_device_advisories")
def test_maybe_refresh_device_cve_index_skips_check_within_the_interval(mock_fetch, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_nvd_cve_check_monotonic", 100.0)
    job_runner.maybe_refresh_device_cve_index(
        now=100.0 + job_runner.NVD_CVE_CHECK_INTERVAL_SECONDS - 1,
    )
    mock_fetch.assert_not_called()


@patch("job_runner._fleet_cpe_prefixes", return_value=["o:netgear:r7000_firmware"])
@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.nvd_lookup.fetch_and_cache_device_advisories")
def test_maybe_refresh_device_cve_index_fetches_when_sentinel_is_stale(
    mock_fetch, mock_age, _prefixes, monkeypatch, tmp_path,
):
    monkeypatch.setattr(job_runner, "_last_nvd_cve_check_monotonic", None)
    monkeypatch.setattr(job_runner, "NVD_CVE_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = job_runner.NVD_CVE_MAX_AGE_SECONDS + 1
    mock_fetch.return_value = True

    job_runner.maybe_refresh_device_cve_index(now=0.0)

    mock_fetch.assert_called_once_with(["o:netgear:r7000_firmware"])
    assert (tmp_path / "sentinel").exists()


@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.nvd_lookup.fetch_and_cache_device_advisories")
def test_maybe_refresh_device_cve_index_skips_fetch_when_sentinel_is_fresh(mock_fetch, mock_age, monkeypatch):
    monkeypatch.setattr(job_runner, "_last_nvd_cve_check_monotonic", None)
    mock_age.return_value = 60.0

    job_runner.maybe_refresh_device_cve_index(now=0.0)

    mock_fetch.assert_not_called()


@patch("job_runner._fleet_cpe_prefixes", return_value=["o:netgear:r7000_firmware"])
@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.nvd_lookup.fetch_and_cache_device_advisories")
def test_maybe_refresh_device_cve_index_does_not_touch_sentinel_on_failed_fetch(
    mock_fetch, mock_age, _prefixes, monkeypatch, tmp_path,
):
    monkeypatch.setattr(job_runner, "_last_nvd_cve_check_monotonic", None)
    monkeypatch.setattr(job_runner, "NVD_CVE_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None
    mock_fetch.return_value = False

    job_runner.maybe_refresh_device_cve_index(now=0.0)

    assert not (tmp_path / "sentinel").exists()


@patch("job_runner._fleet_cpe_prefixes", return_value=None)
@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.nvd_lookup.fetch_and_cache_device_advisories")
def test_maybe_refresh_device_cve_index_does_not_fetch_when_the_device_list_is_unreadable(
    mock_fetch, mock_age, _prefixes, monkeypatch, tmp_path,
):
    # None means "could not read the fleet" - a failure worth retrying, so no
    # sentinel touch either.
    monkeypatch.setattr(job_runner, "_last_nvd_cve_check_monotonic", None)
    monkeypatch.setattr(job_runner, "NVD_CVE_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None

    job_runner.maybe_refresh_device_cve_index(now=0.0)

    mock_fetch.assert_not_called()
    assert not (tmp_path / "sentinel").exists()


@patch("job_runner._fleet_cpe_prefixes", return_value=[])
@patch("job_runner._sentinel_age_seconds")
@patch("job_runner.nvd_lookup.fetch_and_cache_device_advisories")
def test_maybe_refresh_device_cve_index_treats_an_unmapped_fleet_as_a_real_answer(
    mock_fetch, mock_age, _prefixes, monkeypatch, tmp_path,
):
    # [] is different from None: no registered device maps to a known CPE yet,
    # which is the normal state of a fresh install. Touch the sentinel so it
    # isn't re-asked every single interval.
    monkeypatch.setattr(job_runner, "_last_nvd_cve_check_monotonic", None)
    monkeypatch.setattr(job_runner, "NVD_CVE_REFRESH_SENTINEL", str(tmp_path / "sentinel"))
    mock_age.return_value = None

    job_runner.maybe_refresh_device_cve_index(now=0.0)

    mock_fetch.assert_not_called()
    assert (tmp_path / "sentinel").exists()


@patch("job_runner.requests.get")
def test_fleet_cpe_prefixes_maps_only_devices_with_a_verified_cpe(mock_get):
    response = MagicMock()
    response.raise_for_status.side_effect = None
    response.json.return_value = [
        {"device_id": "device-router-gw", "vendor": "Netgear", "model": "R7000"},
        {"device_id": "device-nvr", "vendor": "Dahua", "model": "NVR4108-8P"},  # no CPE coverage
        {"device_id": "device-new", "vendor": None, "model": None},
        {"device_id": "device-insecure", "vendor": "Hikvision", "model": "DS-2CD2143G2-I"},
    ]
    mock_get.return_value = response

    prefixes = job_runner._fleet_cpe_prefixes()

    assert prefixes == [
        r"o:hikvision:ds-2cd2143g2-i\(s\)_firmware",
        "o:netgear:r7000_firmware",
    ]


@patch("job_runner.requests.get", side_effect=requests.ConnectionError("api down"))
def test_fleet_cpe_prefixes_returns_none_when_the_device_list_cannot_be_read(_mock_get):
    assert job_runner._fleet_cpe_prefixes() is None
