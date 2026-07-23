import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def test_post_network_scan_creates_pending_scan_with_no_device(client):
    # The whole point: no device_id, no host, no service - just "scan the
    # subnet," so onboarding can start from discovery instead of manual entry.
    response = client.post("/network-scans")
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    assert isinstance(body["id"], int)
    assert body["observations"] is None


def test_get_network_scans_lists_created_scans(client):
    client.post("/network-scans")
    client.post("/network-scans")
    response = client.get("/network-scans")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_network_scans_filters_by_status(client):
    scan = client.post("/network-scans").json()
    client.patch(f"/network-scans/{scan['id']}", json={"status": "running"})
    pending = client.get("/network-scans", params={"status": "pending"}).json()
    running = client.get("/network-scans", params={"status": "running"}).json()
    assert pending == []
    assert len(running) == 1


def test_get_network_scan_by_id(client):
    scan = client.post("/network-scans").json()
    response = client.get(f"/network-scans/{scan['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == scan["id"]


def test_get_network_scan_404_when_missing(client):
    response = client.get("/network-scans/999999")
    assert response.status_code == 404


def test_patch_network_scan_updates_fields(client):
    scan = client.post("/network-scans").json()
    response = client.patch(
        f"/network-scans/{scan['id']}",
        json={
            "status": "completed",
            "tool": "nmap",
            "tool_version": "7.95",
            "command": "nmap -sV -p 22,23,80,443,1883,8883 --open -T4 172.30.0.0/24",
            "raw_output": "Nmap scan report for device-insecure (172.30.0.6)\n",
            "observations": {
                "subnet": "172.30.0.0/24",
                "hosts": [{"ip": "172.30.0.6", "classification": "iot_device"}],
                "iot_device_count": 1,
                "uncertain_count": 0,
                "unknown_count": 0,
                "notes": [],
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["observations"]["iot_device_count"] == 1


def test_patch_network_scan_404_when_missing(client):
    response = client.patch("/network-scans/999999", json={"status": "running"})
    assert response.status_code == 404


def test_patch_network_scan_422_with_no_valid_fields(client):
    scan = client.post("/network-scans").json()
    response = client.patch(f"/network-scans/{scan['id']}", json={"not_a_real_field": "x"})
    assert response.status_code == 422
