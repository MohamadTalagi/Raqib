from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "smart-speaker"


def test_voice_log_reports_unencrypted_at_rest():
    resp = client.get("/api/voice-log")
    assert resp.status_code == 200
    body = resp.json()
    assert body["encrypted_at_rest"] is False
    assert len(body["entries"]) >= 1


def test_voice_log_accepts_new_transcript_with_no_authentication():
    resp = client.post("/api/voice-log", json={"transcript": "turn off the lights"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "recorded"

    entries = client.get("/api/voice-log").json()["entries"]
    assert any(e["transcript"] == "turn off the lights" for e in entries)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
