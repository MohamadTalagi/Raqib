import subprocess
from unittest.mock import MagicMock, patch

from job_runner import poll_once, process_job


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
