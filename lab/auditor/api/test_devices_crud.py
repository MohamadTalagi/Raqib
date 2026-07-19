import psycopg
import pytest
from fastapi.testclient import TestClient


def _payload(**overrides) -> dict:
    payload = {
        "device_id": "test-camera",
        "display_name": "Test Camera",
        "description": "A registered test device.",
        "tier": "insecure",
        "host": "test-camera",
        "vendor": "AcmeCam",
        "model": "AC-100",
        "location": "Lab bench",
        "owner": "Security team",
        "notes": "Registered by hand.",
        "services": [{"service_type": "http", "port": 80, "published_port": 8091}],
    }
    payload.update(overrides)
    return payload


# Matches the client fixture convention used by every other test file in this
# suite: postgres_url + monkeypatch set DATABASE_URL before main.app is
# imported, since main.get_connection() reads DATABASE_URL lazily at request
# time via os.environ[...].
@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_register_device_returns_201_with_services(client):
    response = client.post("/devices", json=_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["device_id"] == "test-camera"
    assert body["source"] == "manual"
    assert len(body["services"]) == 1
    assert body["services"][0]["port"] == 80
    assert body["services"][0]["published_port"] == 8091


def test_duplicate_device_id_returns_409(client):
    client.post("/devices", json=_payload())
    response = client.post("/devices", json=_payload())
    assert response.status_code == 409


def test_invalid_host_returns_400_naming_the_field(client):
    response = client.post("/devices", json=_payload(host="10.0.0.5"))
    assert response.status_code == 400
    assert response.json()["field"] == "host"


def test_argv_injection_host_returns_400(client):
    response = client.post("/devices", json=_payload(host="--script=http-shellshock"))
    assert response.status_code == 400


def test_registered_device_appears_in_list(client):
    client.post("/devices", json=_payload())
    devices = client.get("/devices").json()
    entry = next(d for d in devices if d["device_id"] == "test-camera")
    assert entry["registered"] is True
    assert entry["evidence_count"] == 0
    assert entry["display_name"] == "Test Camera"


def test_orphan_device_with_evidence_still_appears_unregistered(client, postgres_url):
    # Evidence exists for a device that was never registered. It must not
    # vanish from the dashboard just because devices now come from a table.
    conn = psycopg.connect(postgres_url)
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-ORPHAN-1', 'ghost-device', 'TEST-NET-PORTSCAN', 'nmap', '7.94',
                'nmap -sV ghost-device', now(), 'ghost finding', '{}'::jsonb,
                'document-store/raw/ghost.txt', 'high', 'abc123')
        """
    )
    conn.commit()
    conn.close()

    devices = client.get("/devices").json()
    entry = next(d for d in devices if d["device_id"] == "ghost-device")
    assert entry["registered"] is False
    assert entry["evidence_count"] == 1
