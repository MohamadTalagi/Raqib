from unittest.mock import MagicMock, patch

from automated_run_runner import (
    _applicable_test_ids,
    _guess_device_registration,
    _is_already_registered,
    _run_discovery_and_register,
    _run_nca_compliance,
    _run_scan_test,
    poll_automated_runs_once,
    process_automated_run,
)


def _response(status_code=200, json_body=None, text=""):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_body
    response.text = text
    response.raise_for_status.return_value = None
    return response


# -- _guess_device_registration / _is_already_registered --------------------


def test_guess_device_registration_uses_lab_container_naming_convention():
    host = {
        "ip": "172.30.0.9", "hostname": "kaust-iot-lab-smartlock-1.audit-network",
        "open_ports": [443, 23], "classification": "iot_device",
    }
    guess = _guess_device_registration(host)
    assert guess["device_id"] == "smartlock"
    assert guess["display_name"] == "smartlock"
    assert guess["host"] == "172.30.0.9"
    assert {"service_type": "https", "port": 443} in guess["services"]
    assert {"service_type": "telnet", "port": 23} in guess["services"]


def test_guess_device_registration_falls_back_to_ip_slug_for_unknown_hostname():
    host = {"ip": "10.0.0.5", "hostname": None, "open_ports": [80], "classification": "uncertain"}
    guess = _guess_device_registration(host)
    assert guess["device_id"] == "host-10-0-0-5"
    assert guess["display_name"] == "Host 10.0.0.5"


def test_guess_device_registration_returns_none_with_no_recognized_ports():
    host = {"ip": "10.0.0.6", "hostname": None, "open_ports": [9999], "classification": "unknown"}
    assert _guess_device_registration(host) is None


def test_is_already_registered_matches_by_ip_guessed_id_or_device_id():
    host = {"ip": "172.30.0.5", "hostname": None, "open_ports": [80], "classification": "iot_device"}
    devices = [{"registered": True, "host": "172.30.0.5", "device_id": "some-other-name"}]
    assert _is_already_registered(host, devices)

    devices_by_guessed_id = [{"registered": True, "host": "host-172-30-0-5", "device_id": "host-172-30-0-5"}]
    assert _is_already_registered(host, devices_by_guessed_id)

    assert not _is_already_registered(host, [{"registered": True, "host": "unrelated", "device_id": "unrelated"}])


# -- _applicable_test_ids ----------------------------------------------------


def test_applicable_test_ids_filters_by_enabled_service_and_pipeline_phase():
    device = {
        "device_id": "device-insecure",
        "services": [
            {"service_type": "http", "enabled": True},
            {"service_type": "mqtt", "enabled": False},
        ],
    }
    test_ids = _applicable_test_ids(device)
    assert "TEST-NET-PORTSCAN" in test_ids  # fingerprinting, applies to http
    assert "TEST-FW-MANIFEST" not in test_ids  # firmware tests are excluded
    assert "TEST-NET-DISCOVERY" not in test_ids  # network-discovery tests are excluded
    assert "TEST-MQTT-OPEN" not in test_ids  # mqtt service is disabled on this device


# -- _run_scan_test -----------------------------------------------------------


@patch("automated_run_runner.process_job")
@patch("automated_run_runner.requests")
def test_run_scan_test_auto_submits_the_suggested_finding(mock_requests, mock_process_job):
    mock_requests.post.side_effect = [
        _response(201, {"id": 42, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}),
        _response(201, {"evidence_id": "EV-1"}),
    ]
    mock_requests.get.side_effect = [
        _response(200, [{"id": 42, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN", "host": "device-insecure"}]),
        _response(200, {
            "id": 42, "status": "awaiting_finding", "tool": "nmap",
            "suggested_finding": "2 open ports found.", "suggested_confidence": "high",
        }),
    ]

    summary = {"tests_run": 0, "evidence_recorded": 0, "errors": []}
    _run_scan_test("device-insecure", "TEST-NET-PORTSCAN", summary)

    mock_process_job.assert_called_once()
    record_call = mock_requests.post.call_args_list[-1]
    assert "record" in record_call.args[0]
    assert record_call.kwargs["json"]["finding"] == "2 open ports found."
    assert record_call.kwargs["json"]["confidence"] == "high"
    assert "not reviewed by a human" in record_call.kwargs["json"]["confidence_reason"]
    assert summary["tests_run"] == 1
    assert summary["evidence_recorded"] == 1


@patch("automated_run_runner.process_job")
@patch("automated_run_runner.requests")
def test_run_scan_test_records_nothing_when_job_ends_failed(mock_requests, mock_process_job):
    mock_requests.post.return_value = _response(201, {"id": 43})
    mock_requests.get.side_effect = [
        _response(200, [{"id": 43, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN", "host": "device-insecure"}]),
        _response(200, {"id": 43, "status": "failed"}),
    ]

    summary = {"tests_run": 0, "evidence_recorded": 0, "errors": []}
    _run_scan_test("device-insecure", "TEST-NET-PORTSCAN", summary)

    assert mock_requests.post.call_count == 1  # only the job creation, never a record call
    assert summary["tests_run"] == 1
    assert summary["evidence_recorded"] == 0


@patch("automated_run_runner.process_job")
@patch("automated_run_runner.requests")
def test_run_scan_test_skips_entirely_when_job_creation_is_rejected(mock_requests, mock_process_job):
    mock_requests.post.return_value = _response(400, text="test does not apply to this device's services")

    summary = {"tests_run": 0, "evidence_recorded": 0, "errors": []}
    _run_scan_test("device-insecure", "TEST-NET-PORTSCAN", summary)

    mock_process_job.assert_not_called()
    assert summary["tests_run"] == 0


@patch("automated_run_runner.process_job")
@patch("automated_run_runner.requests")
def test_run_scan_test_fetches_the_live_target_from_the_pending_list_not_the_post_response(
    mock_requests, mock_process_job
):
    """Regression: POST /scan-jobs deliberately never returns host/
    service_type/port (scan_jobs is a pure audit row) - passing that
    response straight to process_job() made every real run fail every test
    with "invalid target: host is required", caught live against the real
    lab. The target must come from GET /scan-jobs?status=pending, the same
    endpoint job_runner.py's own poll_once() already reads it from."""
    mock_requests.post.return_value = _response(201, {"id": 44, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})
    mock_requests.get.side_effect = [
        _response(200, [
            {"id": 44, "device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN",
             "host": "device-insecure", "service_type": "http", "port": 80},
        ]),
        _response(200, {"id": 44, "status": "failed"}),
    ]

    summary = {"tests_run": 0, "evidence_recorded": 0, "errors": []}
    _run_scan_test("device-insecure", "TEST-NET-PORTSCAN", summary)

    job_passed_to_process_job = mock_process_job.call_args.args[0]
    assert job_passed_to_process_job["host"] == "device-insecure"
    assert job_passed_to_process_job["service_type"] == "http"
    assert job_passed_to_process_job["port"] == 80


@patch("automated_run_runner.process_job")
@patch("automated_run_runner.requests")
def test_run_scan_test_records_an_error_when_the_job_vanishes_before_running(mock_requests, mock_process_job):
    mock_requests.post.return_value = _response(201, {"id": 45})
    mock_requests.get.return_value = _response(200, [])  # not in the pending list anymore

    summary = {"tests_run": 0, "evidence_recorded": 0, "errors": []}
    _run_scan_test("device-insecure", "TEST-NET-PORTSCAN", summary)

    mock_process_job.assert_not_called()
    assert "vanished" in summary["errors"][0]


# -- _run_discovery_and_register ---------------------------------------------


@patch("automated_run_runner.process_network_scan")
@patch("automated_run_runner.requests")
def test_run_discovery_and_register_registers_new_iot_and_uncertain_hosts(mock_requests, mock_process_scan):
    hosts = [
        {"ip": "172.30.0.10", "hostname": "kaust-iot-lab-nvr-1.audit-network",
         "open_ports": [554], "classification": "iot_device"},
        {"ip": "172.30.0.11", "hostname": None, "open_ports": [23], "classification": "uncertain"},
        {"ip": "172.30.0.12", "hostname": None, "open_ports": [9999], "classification": "unknown"},
    ]
    mock_requests.post.side_effect = [
        _response(201, {"id": 1}),  # POST /network-scans
        _response(201, {"device_id": "nvr"}),  # POST /devices for the iot_device host
        _response(201, {"device_id": "host-172-30-0-11"}),  # POST /devices for the uncertain host
    ]
    mock_requests.get.side_effect = [
        _response(200, {"id": 1, "observations": {"hosts": hosts}}),  # GET /network-scans/1
        _response(200, []),  # GET /devices (none registered yet)
    ]

    summary = {"hosts_discovered": 0, "devices_registered": 0, "errors": []}
    _run_discovery_and_register(1, summary)

    mock_process_scan.assert_called_once()
    assert summary["hosts_discovered"] == 3
    assert summary["devices_registered"] == 2  # the "unknown" host is never registered
    device_post_calls = mock_requests.post.call_args_list[1:]
    assert {c.kwargs["json"]["device_id"] for c in device_post_calls} == {"nvr", "host-172-30-0-11"}


@patch("automated_run_runner.process_network_scan")
@patch("automated_run_runner.requests")
def test_run_discovery_and_register_skips_already_registered_hosts(mock_requests, mock_process_scan):
    hosts = [{"ip": "172.30.0.5", "hostname": None, "open_ports": [80], "classification": "iot_device"}]
    mock_requests.post.return_value = _response(201, {"id": 1})
    mock_requests.get.side_effect = [
        _response(200, {"id": 1, "observations": {"hosts": hosts}}),
        _response(200, [{"registered": True, "host": "172.30.0.5", "device_id": "device-insecure"}]),
    ]

    summary = {"hosts_discovered": 0, "devices_registered": 0, "errors": []}
    _run_discovery_and_register(1, summary)

    assert mock_requests.post.call_count == 1  # only the network-scan creation, no device registration
    assert summary["devices_registered"] == 0


# -- _run_nca_compliance ------------------------------------------------------


@patch("automated_run_runner.requests")
def test_run_nca_compliance_auto_records_with_attestation_and_auto_recorded_flag(mock_requests):
    mock_requests.post.side_effect = [
        _response(200, {}),  # POST /nca/assessments/recompute
        _response(201, {"id": "ASM-1"}),  # POST /nca/assessments
    ]
    mock_requests.get.side_effect = [
        _response(200, [{"id": "2-2-2", "severity": "critical"}]),  # GET /nca/controls
        _response(200, {"suggestions": {
            "2-2-2": {
                "suggested_status": "fail", "evidence_ids": ["EV-1"], "test_ids": ["TEST-AUTH-DEFAULT-CREDS"],
                "reasons": ["Default credentials accepted (evidence EV-1)"],
            },
        }}),
    ]

    summary = {"nca_assessments_recorded": 0, "errors": []}
    _run_nca_compliance([{"device_id": "device-insecure"}], summary)

    record_call = mock_requests.post.call_args_list[-1]
    payload = record_call.kwargs["json"]
    assert payload["control_id"] == "2-2-2"
    assert payload["status"] == "fail"
    assert payload["severity"] == "critical"
    assert payload["auto_recorded"] is True
    assert payload["attestation_confirmed"] is True
    assert payload["assessed_by"] == "Fully Automated Run"
    assert "not reviewed by a human" in payload["attestation_statement"]
    assert summary["nca_assessments_recorded"] == 1


# -- process_automated_run: cancellation and end-to-end summary -------------


@patch("automated_run_runner._run_nca_compliance")
@patch("automated_run_runner._run_vuln_intelligence")
@patch("automated_run_runner._run_fingerprinting_and_sa_iot")
@patch("automated_run_runner._run_discovery_and_register")
@patch("automated_run_runner._patch_run")
@patch("automated_run_runner._run_status")
@patch("automated_run_runner.requests")
def test_process_automated_run_stops_when_cancelled_between_stages(
    mock_requests, mock_run_status, mock_patch_run, mock_discovery, mock_fingerprint, mock_vuln, mock_nca
):
    mock_requests.get.return_value = _response(200, [])  # GET /devices after discovery
    mock_run_status.side_effect = ["running", "cancelled"]

    process_automated_run({"id": 7, "device_ids": None})

    mock_discovery.assert_called_once()
    mock_fingerprint.assert_not_called()
    mock_vuln.assert_not_called()
    mock_nca.assert_not_called()
    # never patched to "completed" - the run stays wherever cancellation left it
    assert all(c.args[1].get("status") != "completed" for c in mock_patch_run.call_args_list)


@patch("automated_run_runner._run_nca_compliance")
@patch("automated_run_runner._run_vuln_intelligence")
@patch("automated_run_runner._run_fingerprinting_and_sa_iot")
@patch("automated_run_runner._run_discovery_and_register")
@patch("automated_run_runner._patch_run")
@patch("automated_run_runner._run_status")
@patch("automated_run_runner.requests")
def test_process_automated_run_completes_and_scopes_to_explicit_device_ids(
    mock_requests, mock_run_status, mock_patch_run, mock_discovery, mock_fingerprint, mock_vuln, mock_nca
):
    mock_requests.get.return_value = _response(200, [
        {"device_id": "device-insecure", "registered": True},
        {"device_id": "device-hardened", "registered": True},
    ])
    mock_run_status.return_value = "running"

    process_automated_run({"id": 8, "device_ids": ["device-insecure"]})

    # explicit scope: discovery is never run
    mock_discovery.assert_not_called()
    mock_fingerprint.assert_called_once()
    scoped_devices = mock_fingerprint.call_args.args[0]
    assert [d["device_id"] for d in scoped_devices] == ["device-insecure"]

    final_call = mock_patch_run.call_args_list[-1]
    assert final_call.args[1]["status"] == "completed"


@patch("automated_run_runner.requests")
def test_process_automated_run_marks_failed_on_unexpected_exception(mock_requests):
    mock_requests.get.side_effect = RuntimeError("auditor-api unreachable")
    mock_requests.patch.return_value = _response(200, {})

    process_automated_run({"id": 9, "device_ids": ["device-insecure"]})

    failed_call = mock_requests.patch.call_args_list[-1]
    assert failed_call.kwargs["json"]["status"] == "failed"
    assert "auditor-api unreachable" in failed_call.kwargs["json"]["error"]


# -- poll_automated_runs_once -------------------------------------------------


@patch("automated_run_runner.process_automated_run")
@patch("automated_run_runner.requests.get")
def test_poll_automated_runs_once_processes_every_pending_run(mock_get, mock_process_run):
    mock_get.return_value = _response(200, [{"id": 1, "device_ids": None}, {"id": 2, "device_ids": ["device-insecure"]}])

    count = poll_automated_runs_once()

    assert count == 2
    assert mock_process_run.call_count == 2
    assert mock_get.call_args.kwargs["params"] == {"status": "pending"}
