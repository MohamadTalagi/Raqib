from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_success_with_default_creds():
    resp = client.post("/login", data={"username": "admin", "password": "admin"})
    assert resp.status_code == 200


def test_login_fails_with_wrong_creds():
    resp = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "network-video-recorder"


def test_clips_endpoint_shows_indefinite_retention():
    resp = client.get("/api/clips")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["clips"]) >= 1
    assert body["retention_policy"] == "none"


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
