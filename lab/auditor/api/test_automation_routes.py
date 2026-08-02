import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("DOCUMENT_STORE_DIR", str(tmp_path))
    from main import app
    return TestClient(app)


def test_post_run_creates_pending_run_with_no_device_scope(client):
    response = client.post("/automation/runs")
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    assert isinstance(body["id"], int)
    assert body["device_ids"] is None
    assert body["summary"] == {}


def test_post_run_accepts_a_device_scope(client):
    response = client.post("/automation/runs", json={"device_ids": ["device-insecure", "device-nvr"]})
    assert response.status_code == 201
    assert response.json()["device_ids"] == ["device-insecure", "device-nvr"]


def test_get_runs_lists_created_runs(client):
    client.post("/automation/runs")
    client.post("/automation/runs")
    response = client.get("/automation/runs")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_run_by_id(client):
    run = client.post("/automation/runs").json()
    response = client.get(f"/automation/runs/{run['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == run["id"]


def test_get_run_404_when_missing(client):
    response = client.get("/automation/runs/999999")
    assert response.status_code == 404


def test_cancel_pending_run_marks_it_cancelled(client):
    run = client.post("/automation/runs").json()
    response = client.post(f"/automation/runs/{run['id']}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled"
    assert body["completed_at"] is not None


def test_cancel_already_completed_run_is_rejected(client):
    run = client.post("/automation/runs").json()
    client.post(f"/automation/runs/{run['id']}/cancel")
    response = client.post(f"/automation/runs/{run['id']}/cancel")
    assert response.status_code == 409


def test_cancel_unknown_run_is_404(client):
    response = client.post("/automation/runs/999999/cancel")
    assert response.status_code == 404
