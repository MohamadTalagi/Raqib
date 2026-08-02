from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_device_info_endpoint():
    resp = client.get("/api/device/info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["device_type"] == "industrial-sensor-gateway"
    assert body["modbus_port"] == 502


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
