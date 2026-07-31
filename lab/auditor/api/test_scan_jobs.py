import hashlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def _register_device(client, device_id, service_type="http", port=80):
    # Scan jobs now resolve their target by joining devices + device_services,
    # so every test that creates a scan job needs a registered device first.
    response = client.post(
        "/devices",
        json={
            "device_id": device_id,
            "display_name": device_id,
            "tier": "unknown",
            "host": device_id,
            "services": [{"service_type": service_type, "port": port}],
        },
    )
    assert response.status_code == 201, response.text


def test_get_scan_tests_returns_the_catalog(client):
    response = client.get("/scan-tests")
    assert response.status_code == 200
    test_ids = {t["test_id"] for t in response.json()}
    assert "TEST-NET-PORTSCAN" in test_ids
    assert "TEST-AUTH-DEFAULT-CREDS" in test_ids
    assert "TEST-HTTP-HEADERS" in test_ids


def test_get_scan_tests_includes_the_pipeline_phase(client):
    tests_by_id = {t["test_id"]: t for t in client.get("/scan-tests").json()}
    assert tests_by_id["TEST-NET-PORTSCAN"]["pipeline_phase"] == "fingerprinting"
    assert tests_by_id["TEST-AUTH-DEFAULT-CREDS"]["pipeline_phase"] == "sa_iot_compliance"
    assert tests_by_id["TEST-FW-MANIFEST"]["pipeline_phase"] == "vuln_intelligence"
    # The standalone subnet sweep isn't part of any per-device pipeline phase.
    assert tests_by_id["TEST-NET-DISCOVERY"]["pipeline_phase"] is None


def test_post_scan_job_creates_pending_job(client):
    _register_device(client, "device-insecure")
    response = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    assert body["device_id"] == "device-insecure"
    assert body["test_id"] == "TEST-NET-PORTSCAN"
    assert isinstance(body["id"], int)


def test_post_scan_job_rejects_disallowed_combo(client):
    # telnet-sim only exposes a telnet service, so an HTTP-only test does not apply.
    _register_device(client, "telnet-sim", service_type="telnet", port=23)
    response = client.post("/scan-jobs", json={"device_id": "telnet-sim", "test_id": "TEST-AUTH-DEFAULT-CREDS"})
    assert response.status_code == 400


def test_post_scan_job_resolves_matching_service_when_first_service_does_not_apply(client):
    # Regression: service #1 (mqtt) does not match an HTTP-only test, but
    # service #2 (http) does. The old query took "first enabled service by
    # insertion order" and would 400 even though the device genuinely speaks
    # HTTP. This must succeed by picking the http service instead of mqtt.
    response = client.post(
        "/devices",
        json={
            "device_id": "multi-service-device",
            "display_name": "multi-service-device",
            "tier": "unknown",
            "host": "multi-service-device",
            "services": [
                {"service_type": "mqtt", "port": 1883},
                {"service_type": "http", "port": 80},
            ],
        },
    )
    assert response.status_code == 201, response.text

    response = client.post(
        "/scan-jobs",
        json={"device_id": "multi-service-device", "test_id": "TEST-AUTH-DEFAULT-CREDS"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["device_id"] == "multi-service-device"
    assert body["test_id"] == "TEST-AUTH-DEFAULT-CREDS"


def test_post_scan_job_rejects_when_only_mqtt_service_for_http_test(client):
    _register_device(client, "mqtt-only-device", service_type="mqtt", port=1883)
    response = client.post(
        "/scan-jobs",
        json={"device_id": "mqtt-only-device", "test_id": "TEST-AUTH-DEFAULT-CREDS"},
    )
    assert response.status_code == 400


def test_post_scan_job_rejects_unknown_test_id(client):
    _register_device(client, "device-insecure")
    response = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-DOES-NOT-EXIST"})
    assert response.status_code == 400


def test_post_scan_job_rejects_unregistered_device(client):
    response = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})
    assert response.status_code == 400


def test_post_scan_job_for_network_discovery_test_needs_no_enabled_service(client):
    # TEST-NET-DISCOVERY sweeps the whole audit-network subnet rather than
    # one device's registered service - it must succeed even for a device
    # with zero enabled services, exactly like a firmware test does.
    response = client.post(
        "/devices",
        json={
            "device_id": "discovery-only-device",
            "display_name": "discovery-only-device",
            "tier": "unknown",
            "host": "discovery-only-device",
            "services": [{"service_type": "http", "port": 80, "enabled": False}],
        },
    )
    assert response.status_code == 201, response.text

    response = client.post(
        "/scan-jobs",
        json={"device_id": "discovery-only-device", "test_id": "TEST-NET-DISCOVERY"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "pending"


def test_post_scan_job_for_network_discovery_test_rejects_unregistered_device(client):
    response = client.post(
        "/scan-jobs",
        json={"device_id": "no-such-device", "test_id": "TEST-NET-DISCOVERY"},
    )
    assert response.status_code == 400
    assert "registered" in response.json()["detail"]


def test_get_scan_jobs_lists_created_jobs(client):
    _register_device(client, "device-insecure")
    client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})
    response = client.get("/scan-jobs")
    assert response.status_code == 200
    jobs = response.json()
    assert len(jobs) == 1
    # The worker resolves its target from these fields - they must be joined
    # in from the current device/service state, not stored on scan_jobs.
    assert jobs[0]["host"] == "device-insecure"
    assert jobs[0]["service_type"] == "http"
    assert jobs[0]["port"] == 80


def test_get_scan_jobs_resolves_matching_service_when_first_service_does_not_apply(client):
    # Regression: service #1 (mqtt) does not match an HTTP-only test, but
    # service #2 (http) does. The old LATERAL join took "first enabled
    # service by insertion order" and would hand the worker the mqtt service
    # for an HTTP-only test, so process_job's is_applicable() check would
    # fail at execution time even though post_scan_job had already accepted
    # the job. GET /scan-jobs must resolve the http service instead.
    response = client.post(
        "/devices",
        json={
            "device_id": "multi-service-device",
            "display_name": "multi-service-device",
            "tier": "unknown",
            "host": "multi-service-device",
            "services": [
                {"service_type": "mqtt", "port": 1883},
                {"service_type": "http", "port": 80},
            ],
        },
    )
    assert response.status_code == 201, response.text

    created = client.post(
        "/scan-jobs",
        json={"device_id": "multi-service-device", "test_id": "TEST-AUTH-DEFAULT-CREDS"},
    ).json()

    jobs = client.get("/scan-jobs", params={"status": "pending"}).json()
    matching = next(j for j in jobs if j["id"] == created["id"])
    assert matching["service_type"] == "http"
    assert matching["port"] == 80
    assert matching["host"] == "multi-service-device"


def test_get_scan_jobs_target_is_null_when_no_enabled_service_matches_test(client):
    # A device that only ever speaks mqtt has no service an HTTP-only test
    # applies to. This must resolve to the same all-NULL target contract as
    # a deregistered device, not to the (wrong) mqtt service, since
    # resolve_target's validate_host(None) is what makes the worker fail the
    # job cleanly instead of crashing on an inapplicable target.
    _register_device(client, "mqtt-only-device-2", service_type="mqtt", port=1883)

    # post_scan_job itself already rejects this combo (test_post_scan_job_
    # rejects_when_only_mqtt_service_for_http_test covers that at creation
    # time), so insert the pending job directly to exercise GET /scan-jobs's
    # resolution in isolation, the way a job created by an older API version
    # (before the test-aware fix) could still be sitting in the table.
    from db import get_connection

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO scan_jobs (device_id, test_id) VALUES (%s, %s)",
            ("mqtt-only-device-2", "TEST-AUTH-DEFAULT-CREDS"),
        )
        conn.commit()
    finally:
        conn.close()

    jobs = client.get("/scan-jobs", params={"status": "pending"}).json()
    matching = next(j for j in jobs if j["device_id"] == "mqtt-only-device-2")
    assert matching["host"] is None
    assert matching["service_type"] is None
    assert matching["port"] is None


def test_get_scan_jobs_target_is_null_when_device_deregistered(client):
    _register_device(client, "device-insecure")
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}).json()
    delete_response = client.delete("/devices/device-insecure")
    assert delete_response.status_code == 204

    jobs = client.get("/scan-jobs").json()
    matching = next(j for j in jobs if j["id"] == job["id"])
    assert matching["host"] is None
    assert matching["service_type"] is None
    assert matching["port"] is None


def test_get_scan_jobs_filters_by_status(client):
    _register_device(client, "device-insecure")
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}).json()
    client.patch(f"/scan-jobs/{job['id']}", json={"status": "running"})
    pending = client.get("/scan-jobs", params={"status": "pending"}).json()
    running = client.get("/scan-jobs", params={"status": "running"}).json()
    assert pending == []
    assert len(running) == 1


def test_get_scan_job_by_id_404_when_missing(client):
    response = client.get("/scan-jobs/999999")
    assert response.status_code == 404


def test_get_scan_job_has_no_suggestion_while_still_pending(client):
    _register_device(client, "device-insecure")
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}).json()

    fetched = client.get(f"/scan-jobs/{job['id']}").json()
    assert fetched["status"] == "pending"
    assert fetched["suggested_finding"] is None
    assert fetched["suggested_confidence"] is None


def test_get_scan_job_suggests_a_finding_and_confidence_once_awaiting_finding(client):
    _register_device(client, "device-insecure")
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-HTTP-HEADERS"}).json()
    client.patch(
        f"/scan-jobs/{job['id']}",
        json={
            "status": "awaiting_finding", "tool": "curl", "tool_version": "8.5.0",
            "command": "curl -I http://device-insecure/",
            "observations": {
                "missing_security_headers": ["X-Frame-Options"],
                "notes": ["Missing X-Frame-Options - the page can be embedded in a hidden iframe."],
            },
        },
    )

    fetched = client.get(f"/scan-jobs/{job['id']}").json()
    assert fetched["suggested_finding"] == "Missing X-Frame-Options - the page can be embedded in a hidden iframe."
    assert fetched["suggested_confidence"] == "high"


def test_get_scan_job_suggests_medium_confidence_for_an_uncertain_tls_result(client):
    _register_device(client, "device-hardened", service_type="https", port=443)
    job = client.post("/scan-jobs", json={"device_id": "device-hardened", "test_id": "TEST-TLS-CONFIG"}).json()
    client.patch(
        f"/scan-jobs/{job['id']}",
        json={
            "status": "awaiting_finding", "tool": "openssl", "tool_version": "3.5.6",
            "command": "python3 tls_cert_check.py device-hardened 443",
            "observations": {
                "tls_version": "TLSv1.3", "weak_cipher": False, "cert_expired": False,
                "protocol_probe": {"TLSv1": None, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True},
                "supported_tls_versions": ["TLSv1.2", "TLSv1.3"],
                "deprecated_tls_versions_supported": False,
                "notes": ["Could not determine whether the server accepts TLSv1, TLSv1.1."],
            },
        },
    )

    fetched = client.get(f"/scan-jobs/{job['id']}").json()
    assert fetched["suggested_confidence"] == "medium"


def test_get_scan_job_has_no_suggestion_once_recorded(client):
    job_id = _make_awaiting_finding_job(client)
    client.post(f"/scan-jobs/{job_id}/record", json={"finding": "Only HTTP open", "confidence": "high"})

    fetched = client.get(f"/scan-jobs/{job_id}").json()
    assert fetched["status"] == "recorded"
    assert fetched["suggested_finding"] is None
    assert fetched["suggested_confidence"] is None


def test_patch_scan_job_updates_fields(client):
    _register_device(client, "device-insecure")
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}).json()
    response = client.patch(
        f"/scan-jobs/{job['id']}",
        json={
            "status": "awaiting_finding",
            "tool": "nmap",
            "tool_version": "7.95",
            "command": "nmap -sV -p- device-insecure",
            "raw_output": "80/tcp open http\n",
            "observations": {"open_ports": [80], "telnet_open": False},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "awaiting_finding"
    assert body["observations"] == {"open_ports": [80], "telnet_open": False}


def test_patch_scan_job_404_when_missing(client):
    response = client.patch("/scan-jobs/999999", json={"status": "running"})
    assert response.status_code == 404


def _make_awaiting_finding_job(client, device_id="device-insecure", test_id="TEST-NET-PORTSCAN"):
    _register_device(client, device_id)
    job = client.post("/scan-jobs", json={"device_id": device_id, "test_id": test_id}).json()
    client.patch(
        f"/scan-jobs/{job['id']}",
        json={
            "status": "awaiting_finding",
            "tool": "nmap",
            "tool_version": "7.95",
            "command": f"nmap -sV -p- {device_id}",
            "raw_output": "80/tcp open http\n",
            "observations": {"open_ports": [80], "telnet_open": False},
        },
    )
    return job["id"]


def test_record_scan_job_creates_real_evidence(client, tmp_path):
    job_id = _make_awaiting_finding_job(client)
    response = client.post(
        f"/scan-jobs/{job_id}/record",
        json={"finding": "Only HTTP open, no unnecessary Telnet", "confidence": "high"},
    )
    assert response.status_code == 201
    evidence = response.json()
    assert evidence["finding"] == "Only HTTP open, no unnecessary Telnet"
    assert evidence["device_id"] == "device-insecure"
    assert evidence["test_id"] == "TEST-NET-PORTSCAN"

    # raw output was actually written to disk and hashed for real
    raw_file = tmp_path / "raw" / f"{evidence['evidence_id']}.txt"
    assert raw_file.exists()
    assert raw_file.read_text() == "80/tcp open http\n"
    assert evidence["sha256"] == hashlib.sha256(raw_file.read_bytes()).hexdigest()

    # it's genuinely queryable afterwards, same as any other evidence
    fetched = client.get(f"/evidence/{evidence['evidence_id']}")
    assert fetched.status_code == 200

    # the job itself is marked recorded and links back to the evidence
    job = client.get(f"/scan-jobs/{job_id}").json()
    assert job["status"] == "recorded"
    assert job["evidence_id"] == evidence["evidence_id"]


def test_record_scan_job_requires_finding_and_confidence(client):
    job_id = _make_awaiting_finding_job(client)
    response = client.post(f"/scan-jobs/{job_id}/record", json={"finding": "", "confidence": "high"})
    assert response.status_code == 422


def test_record_scan_job_auto_fills_a_confidence_reason_when_none_is_given(client):
    job_id = _make_awaiting_finding_job(client)
    evidence = client.post(
        f"/scan-jobs/{job_id}/record",
        json={"finding": "Only HTTP open, no unnecessary Telnet", "confidence": "high"},
    ).json()
    assert evidence["confidence_reason"] is not None
    assert "High confidence" in evidence["confidence_reason"]
    assert "TEST-NET-PORTSCAN" in evidence["confidence_reason"]
    assert "nmap" in evidence["confidence_reason"]


def test_record_scan_job_keeps_an_explicit_confidence_reason_from_the_auditor(client):
    job_id = _make_awaiting_finding_job(client)
    evidence = client.post(
        f"/scan-jobs/{job_id}/record",
        json={
            "finding": "Only HTTP open, no unnecessary Telnet", "confidence": "high",
            "confidence_reason": "Cross-checked against a manual nmap run from a second host.",
        },
    ).json()
    assert evidence["confidence_reason"] == "Cross-checked against a manual nmap run from a second host."


def test_record_scan_job_failure_always_carries_a_confidence_reason(client):
    _register_device(client, "device-insecure")
    job = client.post(
        "/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"},
    ).json()
    evidence = client.post(
        f"/scan-jobs/{job['id']}/record-failure", json={"error_detail": "connection timed out"},
    ).json()
    assert evidence["confidence"] == "low"
    assert evidence["confidence_reason"] == "Automated collector execution failed; confidence fixed at low."


def test_record_scan_job_rejects_wrong_status(client):
    _register_device(client, "device-insecure")
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}).json()
    # still "pending", never moved to awaiting_finding
    response = client.post(f"/scan-jobs/{job['id']}/record", json={"finding": "x", "confidence": "high"})
    assert response.status_code == 409


def test_record_scan_job_twice_is_rejected_second_time(client):
    job_id = _make_awaiting_finding_job(client)
    first = client.post(f"/scan-jobs/{job_id}/record", json={"finding": "first", "confidence": "high"})
    assert first.status_code == 201
    second = client.post(f"/scan-jobs/{job_id}/record", json={"finding": "second", "confidence": "high"})
    assert second.status_code == 409


def test_record_scan_job_evidence_ids_increment_within_same_day(client):
    job_a = _make_awaiting_finding_job(client, device_id="device-insecure")
    job_b = _make_awaiting_finding_job(client, device_id="device-hardened")
    ev_a = client.post(f"/scan-jobs/{job_a}/record", json={"finding": "a", "confidence": "high"}).json()
    ev_b = client.post(f"/scan-jobs/{job_b}/record", json={"finding": "b", "confidence": "high"}).json()
    assert ev_a["evidence_id"] != ev_b["evidence_id"]
    seq_a = int(ev_a["evidence_id"].rsplit("-", 1)[1])
    seq_b = int(ev_b["evidence_id"].rsplit("-", 1)[1])
    assert seq_b == seq_a + 1
