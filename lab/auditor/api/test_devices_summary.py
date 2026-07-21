import pytest
from fastapi.testclient import TestClient

EVIDENCE_A = {
    "evidence_id": "EV-2026-07-08-9001", "device_id": "device-insecure",
    "test_id": "TEST-NET-PORTSCAN", "tool": "nmap", "tool_version": "7.95",
    "command": "nmap -sV -p- device-insecure", "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Port 80 open", "observations": {"open_ports": [80]},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9001.txt",
    "confidence": "high", "sha256": "a" * 64,
}
EVIDENCE_B = dict(EVIDENCE_A, evidence_id="EV-2026-07-08-9002", device_id="device-hardened")

VERDICT_FAIL = {
    "verdict_id": "VD-2026-07-08-9001", "control_id": "SA-IOT-002",
    "device_id": "device-insecure", "status": "FAIL", "severity": "high",
    "evidence_ids": ["EV-2026-07-08-9001"], "matched": "fail",
    "reason": "observations.default_creds equals True",
    "saudi_source": "CGIoT-1:2024 §2-2-2",
    "remediation": "Force password change", "timestamp": "2026-07-08T08:06:42Z",
}
VERDICT_PASS = dict(
    VERDICT_FAIL, verdict_id="VD-2026-07-08-9002", device_id="device-hardened",
    status="PASS", matched="pass",
)


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_get_devices_returns_counts(client):
    client.post("/evidence", json=EVIDENCE_A)
    client.post("/evidence", json=EVIDENCE_B)
    client.post("/verdicts", json=VERDICT_FAIL)

    response = client.get("/devices")
    by_id = {d["device_id"]: d for d in response.json()}
    assert by_id["device-insecure"]["evidence_count"] == 1
    assert by_id["device-insecure"]["verdict_count"] == 1
    assert by_id["device-hardened"]["evidence_count"] == 1
    assert by_id["device-hardened"]["verdict_count"] == 0

    # Neither device was ever POSTed to /devices, so both are orphans: they
    # come from the evidence/verdicts UNION half of the query, not the
    # devices table, and must be flagged unregistered with no services.
    assert by_id["device-insecure"]["registered"] is False
    assert by_id["device-insecure"]["services"] == []
    assert by_id["device-hardened"]["registered"] is False
    assert by_id["device-hardened"]["services"] == []


def test_get_summary_returns_aggregate_counts(client):
    client.post("/evidence", json=EVIDENCE_A)
    client.post("/evidence", json=EVIDENCE_B)
    client.post("/verdicts", json=VERDICT_FAIL)
    client.post("/verdicts", json=VERDICT_PASS)

    response = client.get("/summary")
    body = response.json()
    assert body["total_evidence"] == 2
    assert body["total_verdicts"] == 2
    assert body["verdicts_by_status"]["FAIL"] == 1
    assert body["verdicts_by_status"]["PASS"] == 1


def test_get_summary_includes_per_device_nca_compliance(client):
    client.post("/verdicts", json=VERDICT_FAIL)
    client.post("/verdicts", json=VERDICT_PASS)

    body = client.get("/summary").json()
    by_device = {d["device_id"]: d for d in body["device_compliance"]}
    assert by_device["device-insecure"] == {
        "device_id": "device-insecure", "framework": "CGIoT-1:2024",
        "tested_controls": 1, "passing_controls": 0, "percentage": 0,
    }
    assert by_device["device-hardened"] == {
        "device_id": "device-hardened", "framework": "CGIoT-1:2024",
        "tested_controls": 1, "passing_controls": 1, "percentage": 100,
    }


def test_device_compliance_keeps_only_the_latest_verdict_per_control(client):
    # device-insecure gets two verdicts for the SAME control - an older FAIL
    # and a newer PASS (re-tested after a fix). Only the newer one should
    # count, not both (which would otherwise read as 50%).
    client.post("/devices", json={
        "device_id": VERDICT_FAIL["device_id"], "display_name": "Device Insecure",
        "tier": "insecure", "host": VERDICT_FAIL["device_id"],
        "services": [{"service_type": "http", "port": 80, "published_port": None}],
    })
    older_fail = dict(VERDICT_FAIL, timestamp="2026-01-01T00:00:00Z")
    newer_pass = dict(
        VERDICT_FAIL, verdict_id="VD-2026-07-08-9003", status="PASS",
        matched="pass", timestamp="2026-06-01T00:00:00Z",
    )
    client.post("/verdicts", json=older_fail)
    client.post("/verdicts", json=newer_pass)

    body = client.get(f"/devices/{VERDICT_FAIL['device_id']}").json()
    assert body["compliance"] == {
        "framework": "CGIoT-1:2024", "tested_controls": 1,
        "passing_controls": 1, "percentage": 100,
    }


def test_device_compliance_is_none_when_no_controls_tested(client):
    client.post("/devices", json={
        "device_id": "untested-device", "display_name": "Untested",
        "tier": "unknown", "host": "untested-device",
        "services": [{"service_type": "http", "port": 80, "published_port": None}],
    })
    body = client.get("/devices/untested-device").json()
    assert body["compliance"] == {
        "framework": "CGIoT-1:2024", "tested_controls": 0,
        "passing_controls": 0, "percentage": None,
    }
