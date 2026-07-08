import os

import pytest
from fastapi.testclient import TestClient

VALID_EVIDENCE = {
    "evidence_id": "EV-2026-07-08-9001",
    "device_id": "device-insecure",
    "test_id": "TEST-NET-PORTSCAN",
    "tool": "nmap",
    "tool_version": "7.95",
    "command": "nmap -sV -p- device-insecure",
    "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Port 80 open",
    "observations": {"open_ports": [80]},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9001.txt",
    "confidence": "high",
    "sha256": "a" * 64,
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_post_evidence_returns_201(client):
    response = client.post("/evidence", json=VALID_EVIDENCE)
    assert response.status_code == 201
    assert response.json()["evidence_id"] == "EV-2026-07-08-9001"


def test_post_evidence_rejects_invalid_payload(client):
    bad = dict(VALID_EVIDENCE)
    del bad["finding"]
    response = client.post("/evidence", json=bad)
    assert response.status_code == 422


def test_get_evidence_list_returns_posted_record(client):
    client.post("/evidence", json=VALID_EVIDENCE)
    response = client.get("/evidence")
    assert response.status_code == 200
    ids = [e["evidence_id"] for e in response.json()]
    assert "EV-2026-07-08-9001" in ids


def test_get_evidence_filters_by_device_id(client):
    client.post("/evidence", json=VALID_EVIDENCE)
    other = dict(VALID_EVIDENCE, evidence_id="EV-2026-07-08-9002", device_id="device-hardened")
    client.post("/evidence", json=other)

    response = client.get("/evidence", params={"device_id": "device-hardened"})
    ids = [e["evidence_id"] for e in response.json()]
    assert ids == ["EV-2026-07-08-9002"]


def test_get_evidence_by_id_returns_record(client):
    client.post("/evidence", json=VALID_EVIDENCE)
    response = client.get("/evidence/EV-2026-07-08-9001")
    assert response.status_code == 200
    assert response.json()["finding"] == "Port 80 open"


def test_get_evidence_by_id_404_when_missing(client):
    response = client.get("/evidence/EV-DOES-NOT-EXIST")
    assert response.status_code == 404
