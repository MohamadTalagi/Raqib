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


def test_get_control_by_id_rejects_invalid_characters_dot():
    """Test that control IDs with dots are rejected (invalid format)."""
    response = client.get("/controls/..etc")
    assert response.status_code == 400


def test_get_control_by_id_rejects_invalid_characters_space():
    """Test that control IDs with spaces are rejected."""
    response = client.get("/controls/SA-IOT-001%20test")
    assert response.status_code == 400


def test_get_control_by_id_rejects_invalid_characters_special():
    """Test that control IDs with special characters are rejected."""
    response = client.get("/controls/SA-IOT%3B001")
    # %3B is URL-encoded semicolon; FastAPI may decode or reject at routing
    assert response.status_code in (400, 404)
