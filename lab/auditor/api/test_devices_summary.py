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
