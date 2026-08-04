import importlib

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def _fresh_app(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from app import config as config_module
    importlib.reload(config_module)
    from app import main as main_module
    importlib.reload(main_module)
    return TestClient(main_module.app)


def test_cors_allows_any_origin_on_device_info():
    resp = client.get("/api/device/info", headers={"Origin": "http://localhost:8080"})
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "*"


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
    assert body["mac"] == "A4:14:37:00:11:22"


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


def test_config_does_not_leak_api_key_when_not_exposed(monkeypatch):
    fresh_client = _fresh_app(monkeypatch, EXPOSE_API_KEY="false")
    resp = fresh_client.get("/api/config")
    assert resp.status_code == 200
    assert "api_key" not in resp.json()


def test_admin_reset_requires_auth_when_required_and_rejects_missing_header(monkeypatch):
    fresh_client = _fresh_app(monkeypatch, REQUIRE_ADMIN_AUTH="true")
    resp = fresh_client.get("/api/admin/reset")
    assert resp.status_code == 401


def test_dashboard_loads_and_shows_device_identity():
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Hikvision" in resp.text
    assert "DS-2CD2143G2-I" in resp.text


def test_dashboard_shows_api_key_when_exposed():
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "sk-insecure-hardcoded-key-000111222" in resp.text


def test_dashboard_hides_api_key_when_not_exposed(monkeypatch):
    fresh_client = _fresh_app(monkeypatch, EXPOSE_API_KEY="false")
    resp = fresh_client.get("/dashboard")
    assert resp.status_code == 200
    assert "API key" not in resp.text


def test_login_page_links_to_dashboard():
    resp = client.get("/")
    assert resp.status_code == 200
    assert '/dashboard' in resp.text
