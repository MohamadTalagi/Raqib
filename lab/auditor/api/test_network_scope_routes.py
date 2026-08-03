import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def test_list_network_scopes_includes_lab_preset_by_default(client):
    scopes = client.get("/network-scope").json()
    assert len(scopes) == 1
    assert scopes[0]["cidr"] == "172.30.0.0/24"
    assert scopes[0]["kind"] == "lab_preset"
    assert scopes[0]["is_active"] is True


def test_active_network_scope_cidrs_returns_lab_preset_by_default(client):
    assert client.get("/network-scope/active").json() == {"cidrs": ["172.30.0.0/24"]}


def test_create_network_scope_adds_a_custom_range(client):
    response = client.post(
        "/network-scope",
        json={"label": "Building 2 IoT VLAN", "cidr": "10.5.0.0/24", "added_by": "auditor"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["kind"] == "custom"
    assert body["source"] == "manual"
    assert body["is_active"] is True

    active = client.get("/network-scope/active").json()["cidrs"]
    assert set(active) == {"172.30.0.0/24", "10.5.0.0/24"}


def test_create_network_scope_reconfigures_validation_in_process(client):
    # Not just a DB row - device_validation/scan_tests must actually accept
    # a host in the newly-added range on the very next request.
    client.post("/network-scope", json={"label": "New VLAN", "cidr": "10.5.0.0/24", "added_by": "auditor"})
    response = client.post(
        "/devices",
        json={
            "device_id": "new-vlan-device",
            "display_name": "New VLAN Device",
            "host": "10.5.0.9",
            "services": [{"service_type": "http", "port": 80}],
        },
    )
    assert response.status_code == 201


@pytest.mark.parametrize(
    "cidr",
    [
        "8.8.8.0/24",  # public
        "172.31.0.0/24",  # overlaps this platform's own backend network
        "127.0.0.0/24",  # loopback
        "10.0.0.0/8",  # broader than the /16 floor
        "10.5.0.5/24",  # host bits set - not a valid network address
        "not-a-cidr",
    ],
)
def test_create_network_scope_rejects_bad_cidrs(client, cidr):
    response = client.post(
        "/network-scope", json={"label": "Bad", "cidr": cidr, "added_by": "auditor"},
    )
    assert response.status_code == 400
    assert response.json()["field"] == "cidr"


def test_create_network_scope_rejects_duplicate_active_cidr(client):
    response = client.post(
        "/network-scope",
        json={"label": "Dup", "cidr": "172.30.0.0/24", "added_by": "auditor"},
    )
    assert response.status_code == 400
    assert response.json()["field"] == "cidr"


def test_create_network_scope_requires_label_and_added_by(client):
    response = client.post("/network-scope", json={"cidr": "10.5.0.0/24"})
    assert response.status_code == 400
    assert response.json()["field"] == "label"


def test_deactivate_network_scope_removes_it_from_active_list(client):
    scope_id = client.get("/network-scope").json()[0]["id"]
    response = client.post(f"/network-scope/{scope_id}/deactivate", json={"actor": "auditor"})
    assert response.status_code == 200
    body = response.json()
    assert body["is_active"] is False
    assert body["deactivated_by"] == "auditor"
    assert client.get("/network-scope/active").json() == {"cidrs": []}


def test_deactivate_requires_actor(client):
    scope_id = client.get("/network-scope").json()[0]["id"]
    response = client.post(f"/network-scope/{scope_id}/deactivate", json={})
    assert response.status_code == 400
    assert response.json()["field"] == "actor"


def test_deactivate_404_for_missing_scope(client):
    response = client.post("/network-scope/999999/deactivate", json={"actor": "auditor"})
    assert response.status_code == 404


def test_deactivation_impact_counts_matching_registered_devices(client):
    client.post(
        "/devices",
        json={
            "device_id": "device-in-scope",
            "display_name": "In scope",
            "host": "172.30.0.9",
            "services": [{"service_type": "http", "port": 80}],
        },
    )
    scope_id = client.get("/network-scope").json()[0]["id"]
    response = client.get(f"/network-scope/{scope_id}/deactivation-impact")
    assert response.status_code == 200
    assert response.json() == {"affected_device_count": 1}


def test_reactivate_restores_an_inactive_scope(client):
    scope_id = client.get("/network-scope").json()[0]["id"]
    client.post(f"/network-scope/{scope_id}/deactivate", json={"actor": "auditor"})
    response = client.post(f"/network-scope/{scope_id}/reactivate")
    assert response.status_code == 200
    body = response.json()
    assert body["is_active"] is True
    assert body["deactivated_at"] is None
    assert client.get("/network-scope/active").json() == {"cidrs": ["172.30.0.0/24"]}


def test_reactivate_rejects_conflict_with_a_newer_active_row_for_the_same_cidr(client):
    scope_id = client.get("/network-scope").json()[0]["id"]
    client.post(f"/network-scope/{scope_id}/deactivate", json={"actor": "auditor"})
    # The same CIDR can be re-added as a new row once the old one is inactive.
    recreated = client.post(
        "/network-scope",
        json={"label": "Re-added lab preset", "cidr": "172.30.0.0/24", "added_by": "auditor"},
    )
    assert recreated.status_code == 201

    response = client.post(f"/network-scope/{scope_id}/reactivate")
    assert response.status_code == 400
    assert response.json()["field"] == "cidr"
