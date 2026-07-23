import psycopg
import pytest
from fastapi.testclient import TestClient


def _insert_verdict(conn, verdict_id: str, control_id: str, device_id: str, status: str) -> None:
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                              evidence_ids, reason, saudi_source, remediation, timestamp)
        VALUES (%s, %s, %s, %s, 'high', '[]'::jsonb, 'because', '{}'::jsonb, 'fix it', now())
        """,
        (verdict_id, control_id, device_id, status),
    )


# Fixture pattern: postgres_url + monkeypatch set DATABASE_URL before app import
# This ensures get_connection() reads the test database URL at request time.
@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_rollup_groups_devices_by_status(client, postgres_url) -> None:
    """Test that verdicts are grouped by status for a given control."""
    conn = psycopg.connect(postgres_url)
    _insert_verdict(conn, "V-1", "SA-IOT-002", "device-insecure", "FAIL")
    _insert_verdict(conn, "V-2", "SA-IOT-002", "device-hardened", "PASS")
    conn.commit()
    conn.close()

    body = client.get("/controls/SA-IOT-002/verdicts").json()
    assert body["control_id"] == "SA-IOT-002"
    assert body["counts"]["PASS"] == 1
    assert body["counts"]["FAIL"] == 1
    assert body["counts"]["PARTIAL"] == 0
    assert body["counts"]["INCONCLUSIVE"] == 0
    devices = {v["device_id"]: v["status"] for v in body["verdicts"]}
    assert devices == {"device-insecure": "FAIL", "device-hardened": "PASS"}


def test_control_with_no_verdicts_returns_zero_counts(client) -> None:
    """Test that a control with no verdicts returns empty list and zero-filled counts."""
    body = client.get("/controls/SA-IOT-005/verdicts").json()
    assert body["verdicts"] == []
    assert body["counts"] == {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0, "NOT_APPLICABLE": 0}


def test_path_traversal_control_id_rejected(client) -> None:
    """Test that path traversal attempts in control_id are rejected with 400."""
    response = client.get("/controls/..%2F..%2Fetc%2Fpasswd/verdicts")
    assert response.status_code == 400
