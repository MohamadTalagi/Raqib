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

    process_job({"id": 1, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})

    scan_call_args = mock_run.call_args_list[0].args[0]
    assert scan_call_args[0] == "nmap"
    assert "device-insecure" in scan_call_args

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "awaiting_finding"
    assert final_call.kwargs["json"]["observations"] == {"open_ports": [80], "telnet_open": False}
    assert final_call.kwargs["json"]["tool"] == "nmap"


@patch("job_runner.requests.patch")
def test_process_job_rejects_disallowed_device_test_combo(mock_patch):
    process_job({"id": 2, "device_id": "telnet-sim", "test_id": "TEST-AUTH-DEFAULT-CREDS"})

    mock_patch.assert_called_once()
    call = mock_patch.call_args
    assert call.kwargs["json"]["status"] == "failed"
    assert "error" in call.kwargs["json"]


@patch("job_runner.requests.patch")
@patch("job_runner.subprocess.run")
def test_process_job_marks_failed_on_timeout(mock_run, mock_patch):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=30)

    process_job({"id": 3, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})

    final_call = mock_patch.call_args_list[-1]
    assert final_call.kwargs["json"]["status"] == "failed"
    assert "timed out" in final_call.kwargs["json"]["error"]


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
