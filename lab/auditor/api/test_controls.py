from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_get_controls_returns_all_five():
    response = client.get("/controls")
    assert response.status_code == 200
    control_ids = {c["control_id"] for c in response.json()}
    assert control_ids == {
        "SA-IOT-001", "SA-IOT-002", "SA-IOT-003", "SA-IOT-004", "SA-IOT-005",
    }


def test_get_control_by_id_returns_real_control():
    response = client.get("/controls/SA-IOT-002")
    assert response.status_code == 200
    assert response.json()["title"] == "No default or hard-coded credentials"


def test_get_control_by_id_404_when_missing():
    response = client.get("/controls/SA-IOT-999")
    assert response.status_code == 404
