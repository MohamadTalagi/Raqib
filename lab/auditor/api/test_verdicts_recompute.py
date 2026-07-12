from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REAL_CONTROLS_DIR = str(Path(__file__).resolve().parents[3] / "policies" / "controls")

EVIDENCE_DEFAULT_CREDS_FAIL = {
    "evidence_id": "EV-2026-07-08-9010",
    "device_id": "device-insecure",
    "test_id": "TEST-AUTH-DEFAULT-CREDS",
    "tool": "curl",
    "tool_version": "8.9.1",
    "command": "curl POST login",
    "timestamp": "2026-07-08T08:06:42Z",
    "finding": "Default creds accepted",
    "observations": {"default_creds": True},
    "raw_output_path": "document-store/raw/EV-2026-07-08-9010.txt",
    "confidence": "high",
    "sha256": "a" * 64,
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("CONTROLS_DIR", REAL_CONTROLS_DIR)
    from main import app
    return TestClient(app)


def test_recompute_creates_a_verdict_for_matching_evidence(client):
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    response = client.post("/verdicts/recompute")
    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 1
    assert body["verdicts"][0]["control_id"] == "SA-IOT-002"
    assert body["verdicts"][0]["status"] == "FAIL"

    verdicts = client.get("/verdicts").json()
    assert len(verdicts) == 1


def test_recompute_is_idempotent_no_duplicates_on_second_call(client):
    client.post("/evidence", json=EVIDENCE_DEFAULT_CREDS_FAIL)

    first = client.post("/verdicts/recompute")
    assert first.json()["created"] == 1

    second = client.post("/verdicts/recompute")
    assert second.status_code == 200
    assert second.json()["created"] == 0

    verdicts = client.get("/verdicts").json()
    assert len(verdicts) == 1


def test_recompute_only_generates_for_evidence_matching_a_control(client):
    unrelated = dict(EVIDENCE_DEFAULT_CREDS_FAIL, evidence_id="EV-2026-07-08-9011", test_id="TEST-DOES-NOT-MAP")
    client.post("/evidence", json=unrelated)

    response = client.post("/verdicts/recompute")
    assert response.json()["created"] == 0
