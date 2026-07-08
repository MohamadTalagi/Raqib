import pytest
from fastapi.testclient import TestClient

VALID_VERDICT = {
    "verdict_id": "VD-2026-07-08-9001",
    "control_id": "SA-IOT-002",
    "device_id": "device-insecure",
    "status": "FAIL",
    "severity": "high",
    "evidence_ids": ["EV-2026-07-08-9001"],
    "matched": "fail",
    "reason": "observations.default_creds equals True",
    "saudi_source": "CGIoT-1:2024 §2-2-2",
    "remediation": "Force password change on first boot",
    "timestamp": "2026-07-08T08:06:42Z",
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_post_verdict_returns_201(client):
    response = client.post("/verdicts", json=VALID_VERDICT)
    assert response.status_code == 201
    assert response.json()["verdict_id"] == "VD-2026-07-08-9001"


def test_post_verdict_rejects_invalid_payload(client):
    bad = dict(VALID_VERDICT)
    del bad["status"]
    response = client.post("/verdicts", json=bad)
    assert response.status_code == 422


def test_get_verdicts_filters_by_control_id(client):
    client.post("/verdicts", json=VALID_VERDICT)
    other = dict(VALID_VERDICT, verdict_id="VD-2026-07-08-9002", control_id="SA-IOT-003")
    client.post("/verdicts", json=other)

    response = client.get("/verdicts", params={"control_id": "SA-IOT-003"})
    ids = [v["verdict_id"] for v in response.json()]
    assert ids == ["VD-2026-07-08-9002"]


def test_get_verdict_by_id_returns_record(client):
    client.post("/verdicts", json=VALID_VERDICT)
    response = client.get("/verdicts/VD-2026-07-08-9001")
    assert response.status_code == 200
    assert response.json()["status"] == "FAIL"


def test_get_verdict_by_id_404_when_missing(client):
    response = client.get("/verdicts/VD-DOES-NOT-EXIST")
    assert response.status_code == 404
