from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_page_loads():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Access Panel" in resp.text


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "smart-lock"


def test_unlock_succeeds_with_no_pin_when_auth_not_required():
    resp = client.post("/api/unlock")
    assert resp.status_code == 200
    assert resp.json()["status"] == "unlocked"


def test_status_reports_tamper_never_detected():
    client.post("/api/unlock")
    resp = client.get("/api/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tamper_detected"] is False
    assert body["tamper_detection_wired"] is False


def test_unlock_then_lock_records_access_log_entries():
    client.post("/api/unlock")
    client.post("/api/lock")
    resp = client.get("/api/access-log")
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert len(entries) >= 2
    assert entries[-1]["action"] == "lock"
    assert entries[-1]["method"] == "unauthenticated"


def test_login_with_default_pin_succeeds():
    resp = client.post("/login", params={"pin": "0000"})
    assert resp.status_code == 200


def test_login_with_wrong_pin_fails():
    resp = client.post("/login", params={"pin": "9999"})
    assert resp.status_code == 401


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
