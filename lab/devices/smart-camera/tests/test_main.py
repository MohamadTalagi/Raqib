from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_page_loads():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Login" in resp.text


def test_login_success_with_default_creds():
    resp = client.post("/login", data={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_login_fails_with_wrong_creds():
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["device_type"] == "smart-camera"
    assert body["mac"] == "AA:BB:CC:00:11:22"


def test_config_leaks_api_key_when_exposed():
    resp = client.get("/api/config")
    assert resp.status_code == 200
    assert "api_key" in resp.json()


def test_config_post_echoes_payload():
    resp = client.post("/api/config", json={"logging_mode": "basic"})
    assert resp.status_code == 200
    assert resp.json()["received"] == {"logging_mode": "basic"}


def test_firmware_version_endpoint():
    resp = client.get("/api/firmware/version")
    assert resp.status_code == 200
    assert "version" in resp.json()


def test_admin_reset_unauthenticated_allowed_when_not_required():
    resp = client.get("/api/admin/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "reset-triggered"


def test_privacy_endpoint_returns_text_even_if_file_missing():
    resp = client.get("/privacy")
    assert resp.status_code == 200


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
