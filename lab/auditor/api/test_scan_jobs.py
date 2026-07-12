import hashlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def test_get_scan_tests_returns_the_catalog(client):
    response = client.get("/scan-tests")
    assert response.status_code == 200
    test_ids = {t["test_id"] for t in response.json()}
    assert "TEST-NET-PORTSCAN" in test_ids
    assert "TEST-AUTH-DEFAULT-CREDS" in test_ids
    assert "TEST-HTTP-HEADERS" in test_ids


def test_post_scan_job_creates_pending_job(client):
    response = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    assert body["device_id"] == "device-insecure"
    assert body["test_id"] == "TEST-NET-PORTSCAN"
    assert isinstance(body["id"], int)


def test_post_scan_job_rejects_disallowed_combo(client):
    response = client.post("/scan-jobs", json={"device_id": "telnet-sim", "test_id": "TEST-AUTH-DEFAULT-CREDS"})
    assert response.status_code == 422


def test_post_scan_job_rejects_unknown_test_id(client):
    response = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-DOES-NOT-EXIST"})
    assert response.status_code == 422


def test_get_scan_jobs_lists_created_jobs(client):
    client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"})
    response = client.get("/scan-jobs")
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_get_scan_jobs_filters_by_status(client):
    job = client.post("/scan-jobs", json={"device_id": "device-insecure", "test_id": "TEST-NET-PORTSCAN"}).json()
    client.patch(f"/scan-jobs/{job['id']}", json={"status": "running"})
    pending = client.get("/scan-jobs", params={"status": "pending"}).json()
    running = client.get("/scan-jobs", params={"status": "running"}).json()
    assert pending == []
    assert len(running) == 1


def test_get_scan_job_by_id_404_when_missing(client):
    response = client.get("/scan-jobs/999999")
    assert response.status_code == 404


def test_patch_scan_job_updates_fields(client):
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


def test_record_scan_job_rejects_wrong_status(client):
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
