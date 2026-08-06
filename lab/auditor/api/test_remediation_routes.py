from pathlib import Path
from unittest.mock import patch

import psycopg
import pytest
from fastapi.testclient import TestClient

REAL_CONTROLS_DIR = str(Path(__file__).resolve().parents[3] / "policies" / "controls")

GEMINI_RESULT = {
    "root_cause": "Default credentials were never rotated on first boot.",
    "remediation_steps": ["Force a password change on first boot.", "Remove the vendor default account."],
    "priority": "immediate",
    "estimated_effort": "Low - config change only.",
    "caveats": "Confirm no automation depends on the default account.",
}


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("CONTROLS_DIR", REAL_CONTROLS_DIR)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    from main import app
    return TestClient(app)


@pytest.fixture
def conn(postgres_url):
    connection = psycopg.connect(postgres_url)
    yield connection
    connection.close()


def _register_device(conn, device_id="device-insecure"):
    conn.execute(
        "INSERT INTO devices (device_id, display_name, description, tier, host, source) "
        "VALUES (%s, 'Insecure Camera', '', 'insecure', %s, 'manual')",
        (device_id, device_id),
    )
    conn.commit()


def _seed_verdict(conn, *, verdict_id="VD-2026-08-02-0001", status="FAIL", device_id="device-insecure"):
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity, evidence_ids,
                               reason, saudi_source, remediation, timestamp)
        VALUES (%s, 'SA-IOT-002', %s, %s, 'high', '[]'::jsonb,
                'observations.default_creds equals True', '["CGIoT-1:2024 2-2-2"]'::jsonb,
                'Force a unique strong password on first boot.', now())
        """,
        (verdict_id, device_id, status),
    )
    conn.commit()


def _seed_nca_control(conn, control_id="NCA-CGIoT-1_2024-2-2-2"):
    conn.execute(
        """
        INSERT INTO compliance_controls (
            id, domain_id, domain_name, subdomain_id, subdomain_name, guideline_id,
            canonical_requirement, implementation_summary, scope_type, assessment_type,
            required, severity, blocking
        ) VALUES (%s, '2', 'Cybersecurity Defense', '2-2', 'Access and Permission Restriction',
                  '2-2-2', 'Do not use default or hard-coded passwords.', 'No default creds.',
                  'device', 'automated', true, 'high', true)
        """,
        (control_id,),
    )
    conn.commit()


def _seed_nca_assessment(conn, *, assessment_id="ASM-2026-08-02-0001", status="fail", control_id="NCA-CGIoT-1_2024-2-2-2", device_id="device-insecure"):
    conn.execute(
        """
        INSERT INTO compliance_assessments (
            id, control_id, device_id, applicability, status, severity, finding,
            test_method, assessed_by, attested_role, attestation_confirmed, attestation_statement
        ) VALUES (%s, %s, %s, 'applicable', %s, 'high', 'Default credentials accepted on login.',
                  'automated', 'reviewer', 'Lead Auditor', true, 'Reviewed and certified.')
        """,
        (assessment_id, control_id, device_id, status),
    )
    conn.commit()


def _mock_gemini(result=None):
    return patch("remediation_routes.generate_remediation_blueprint", return_value=result or GEMINI_RESULT)


# -- POST /remediation/generate ---------------------------------------------


def test_generate_for_a_failing_sa_iot_verdict(client, conn):
    _register_device(conn)
    _seed_verdict(conn)

    with _mock_gemini():
        response = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        )

    assert response.status_code == 201
    body = response.json()
    assert body["finding_type"] == "sa_iot_verdict"
    assert body["finding_id"] == "VD-2026-08-02-0001"
    assert body["control_id"] == "SA-IOT-002"
    assert body["device_id"] == "device-insecure"
    assert body["root_cause"] == GEMINI_RESULT["root_cause"]
    assert body["remediation_steps"] == GEMINI_RESULT["remediation_steps"]
    assert body["priority"] == "immediate"
    assert body["reviewed"] is False
    assert body["superseded_by"] is None


def test_generate_for_a_failing_nca_assessment(client, conn):
    _register_device(conn)
    _seed_nca_control(conn)
    _seed_nca_assessment(conn)

    with _mock_gemini():
        response = client.post(
            "/remediation/generate",
            json={"finding_type": "nca_assessment", "finding_id": "ASM-2026-08-02-0001"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["finding_type"] == "nca_assessment"
    assert body["control_id"] == "NCA-CGIoT-1_2024-2-2-2"


def test_generate_404_for_unknown_finding(client):
    with _mock_gemini():
        response = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-does-not-exist"}
        )
    assert response.status_code == 404


def test_generate_400_when_finding_is_not_failing_or_partial(client, conn):
    _register_device(conn)
    _seed_verdict(conn, status="PASS")

    with _mock_gemini():
        response = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        )
    assert response.status_code == 400


def test_generate_422_for_invalid_finding_type(client):
    response = client.post("/remediation/generate", json={"finding_type": "bogus", "finding_id": "x"})
    assert response.status_code == 422


def test_generate_502_when_gemini_returns_nothing_usable(client, conn):
    _register_device(conn)
    _seed_verdict(conn)

    with patch("remediation_routes.generate_remediation_blueprint", return_value=None):
        response = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        )
    assert response.status_code == 502


def test_regenerate_supersedes_the_prior_blueprint(client, conn):
    _register_device(conn)
    _seed_verdict(conn)

    with _mock_gemini():
        first = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        ).json()
        second = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        ).json()

    assert first["id"] != second["id"]
    assert second["superseded_by"] is None

    latest_only = client.get(
        "/remediation/blueprints", params={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
    ).json()
    assert len(latest_only) == 1
    assert latest_only[0]["id"] == second["id"]

    every_row = client.get(
        "/remediation/blueprints",
        params={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001", "latest_only": False},
    ).json()
    assert len(every_row) == 2


# -- POST /remediation/blueprints/{id}/review -------------------------------


def test_review_marks_a_blueprint_reviewed(client, conn):
    _register_device(conn)
    _seed_verdict(conn)
    with _mock_gemini():
        created = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        ).json()

    response = client.post(f"/remediation/blueprints/{created['id']}/review", json={"reviewed_by": "Lead Auditor"})
    assert response.status_code == 200
    body = response.json()
    assert body["reviewed"] is True
    assert body["reviewed_by"] == "Lead Auditor"
    assert body["reviewed_at"] is not None


def test_review_requires_reviewed_by(client, conn):
    _register_device(conn)
    _seed_verdict(conn)
    with _mock_gemini():
        created = client.post(
            "/remediation/generate", json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"}
        ).json()

    response = client.post(f"/remediation/blueprints/{created['id']}/review", json={})
    assert response.status_code == 422


def test_review_404_for_unknown_blueprint(client):
    response = client.post("/remediation/blueprints/RB-does-not-exist/review", json={"reviewed_by": "x"})
    assert response.status_code == 404


# -- Distinguishing "not configured" from "the model call failed" -----------
# These are different problems with different fixes: a missing key is a
# deployment issue an operator resolves in seconds, a failed call is a quota/
# network/response issue they cannot. Reporting both identically sent a real
# user to check a quota that had never been consumed, because no request was
# ever sent.


def test_generate_503s_with_a_config_message_when_no_api_key_is_set(client, conn, monkeypatch):
    _register_device(conn)
    _seed_verdict(conn)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with patch("remediation_routes.generate_remediation_blueprint") as mock_generate:
        response = client.post(
            "/remediation/generate",
            json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"},
        )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "no GEMINI_API_KEY is set" in detail
    assert "no request was sent" in detail
    # The whole point: don't send anyone to check a quota that was never used.
    assert "quota" not in detail.split("nothing was charged against any quota")[1]
    # And never call the model at all when it cannot possibly work.
    mock_generate.assert_not_called()


def test_generate_502s_with_a_quota_message_when_the_call_itself_fails(client, conn):
    _register_device(conn)
    _seed_verdict(conn)

    # Key IS set (the client fixture sets one) but generation returned None.
    with patch("remediation_routes.generate_remediation_blueprint", return_value=None):
        response = client.post(
            "/remediation/generate",
            json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"},
        )

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert "was called" in detail
    assert "quota" in detail
    # Must never imply a blueprint was invented in place of the failed call.
    assert "fabricated" in detail


def test_no_blueprint_row_is_written_when_generation_is_unavailable(client, conn, monkeypatch):
    # An honest failure must leave no trace in the append-only blueprint
    # history - a half-written record would be worse than no record.
    _register_device(conn)
    _seed_verdict(conn)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    client.post(
        "/remediation/generate",
        json={"finding_type": "sa_iot_verdict", "finding_id": "VD-2026-08-02-0001"},
    )

    assert client.get("/remediation/blueprints").json() == []
