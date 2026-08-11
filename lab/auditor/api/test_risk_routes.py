import json

import psycopg
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


@pytest.fixture
def conn(postgres_url):
    connection = psycopg.connect(postgres_url)
    yield connection
    connection.close()


def _register_device(conn, device_id="risk-cam", criticality="medium", exposure="internal_only"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host, source,
                             criticality, exposure)
        VALUES (%s, 'Risk Cam', '', 'insecure', 'device-insecure', 'manual', %s, %s)
        """,
        (device_id, criticality, exposure),
    )
    conn.commit()


def _seed_control(conn, control_id, *, domain_id="2", required=True, severity="high"):
    guideline_id = "-".join(control_id.rsplit("-", 3)[-3:])
    subdomain_id = "-".join(guideline_id.split("-")[:2])
    conn.execute(
        """
        INSERT INTO compliance_controls (
            id, domain_id, domain_name, subdomain_id, subdomain_name, guideline_id,
            canonical_requirement, implementation_summary, scope_type, assessment_type,
            required, severity, blocking
        ) VALUES (%s, %s, 'Cybersecurity Defense', %s, 'Access and Permission Restriction',
                  %s, 'Do not use default or hard-coded passwords.', 'No default creds.',
                  'device', 'automated', %s, %s, false)
        """,
        (control_id, domain_id, subdomain_id, guideline_id, required, severity),
    )
    conn.commit()


CONTROL_ID = "NCA-CGIoT-1_2024-2-2-2"


# -- GET /risk/devices --------------------------------------------------


def test_risk_devices_is_empty_with_no_devices(client):
    assert client.get("/risk/devices").json() == {"devices": []}


def test_risk_devices_ranks_worst_first(client, conn):
    _register_device(conn, "cam-low", criticality="low", exposure="none")
    _register_device(conn, "cam-critical", criticality="critical", exposure="internet_facing")

    body = client.get("/risk/devices").json()
    device_ids = [d["device_id"] for d in body["devices"]]
    assert device_ids.index("cam-critical") < device_ids.index("cam-low")
    ranked = {d["device_id"]: d["priority_rank"] for d in body["devices"]}
    assert ranked["cam-critical"] == 1
    assert ranked["cam-low"] == 2


# -- GET /risk/devices/{id} -----------------------------------------------


def test_device_risk_reports_unknown_for_unregistered_device(client):
    assert client.get("/risk/devices/does-not-exist").json() == {
        "device_id": "does-not-exist", "known": False,
    }


def test_device_risk_rejects_an_invalid_device_id(client):
    response = client.get("/risk/devices/NOT%20valid!!")
    assert response.status_code == 400


def test_device_risk_uses_the_devices_own_criticality_and_exposure(client, conn):
    _register_device(conn, "cam-1", criticality="critical", exposure="internet_facing")

    body = client.get("/risk/devices/cam-1").json()

    assert body["known"] is True
    assert body["breakdown"]["criticality"]["raw_value"] == "critical"
    assert body["breakdown"]["criticality"]["normalized"] == 100
    assert body["breakdown"]["exposure"]["raw_value"] == "internet_facing"
    assert body["breakdown"]["exposure"]["normalized"] == 100


def test_device_risk_treats_never_assessed_compliance_as_maximum_risk(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)

    body = client.get("/risk/devices/risk-cam").json()

    assert body["breakdown"]["compliance"]["raw_value"] is None
    assert body["breakdown"]["compliance"]["normalized"] == 100


def test_device_risk_reflects_a_real_nca_fail_through_the_compliance_score(client, conn):
    # The `violations` factor was retired with the SA-IOT stage: counting NCA
    # failures separately double-counted what the NCA compliance score already
    # measures. An NCA fail must still move the score - through compliance.
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "risk-cam", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    )

    body = client.get("/risk/devices/risk-cam").json()

    assert "violations" not in body["breakdown"]
    assert body["breakdown"]["compliance"]["raw_value"] == 0  # the only control, and it failed
    assert body["breakdown"]["compliance"]["weight"] == 0.30


def test_device_risk_ignores_sa_iot_verdicts_entirely(client, conn):
    # SA-IOT verdicts used to contribute to the violation count. The stage is
    # retired, so a FAIL verdict must now have no effect on the risk score at
    # all - the score is NCA-only.
    _register_device(conn)
    before = client.get("/risk/devices/risk-cam").json()["risk_score"]
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                              evidence_ids, reason, saudi_source, remediation, timestamp)
        VALUES ('VD-RISK-1', 'SA-IOT-002', 'risk-cam', 'FAIL', 'critical',
                '[]'::jsonb, 'default creds accepted', '{}'::jsonb, 'change creds', now())
        """
    )
    conn.commit()

    assert client.get("/risk/devices/risk-cam").json()["risk_score"] == before

def test_device_risk_counts_enabled_insecure_services_only(client, conn):
    _register_device(conn)
    conn.execute(
        """
        INSERT INTO device_services (device_id, service_type, port, enabled)
        VALUES ('risk-cam', 'http', 80, true),
               ('risk-cam', 'telnet', 23, false),
               ('risk-cam', 'https', 443, true)
        """
    )
    conn.commit()

    body = client.get("/risk/devices/risk-cam").json()

    # http (enabled) counts; telnet (disabled) doesn't; https isn't insecure.
    assert body["breakdown"]["insecure_services"]["raw_value"] == 1


def test_device_risk_reflects_real_vuln_intel_cvss_and_kev(client, conn):
    _register_device(conn)
    observations = {
        "manifest_present": True,
        "packages": [{
            "name": "openssl", "version": "1.0.1e", "outdated": True, "eol": None,
            "latest_known_version": None, "official_patch_available": True,
            "patched_version": "1.0.1g", "kev_listed_count": 1,
            "cves": [{
                "id": "CVE-2014-0160", "cvss": 7.5, "summary": "Heartbleed",
                "kev_listed": True, "kev_date_added": "2022-05-04",
            }],
            "notes": [],
        }],
        "notes": [],
    }
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-RISK-1', 'risk-cam', 'TEST-FW-MANIFEST', 'python3', '3.12',
                'firmware_check.py manifest', now(), 'firmware manifest analyzed', %s::jsonb,
                'document-store/raw/x.txt', 'high', 'abc123')
        """,
        (json.dumps(observations),),
    )
    conn.commit()

    body = client.get("/risk/devices/risk-cam").json()

    assert body["breakdown"]["cvss"]["raw_value"] == 7.5
    assert body["breakdown"]["cvss"]["normalized"] == 75
    assert body["breakdown"]["exploit_availability"]["raw_value"] is True
    assert body["breakdown"]["exploit_availability"]["normalized"] == 100


def test_device_risk_with_no_firmware_scan_has_zero_cvss_and_no_exploit(client, conn):
    _register_device(conn)

    body = client.get("/risk/devices/risk-cam").json()

    assert body["breakdown"]["cvss"]["raw_value"] is None
    assert body["breakdown"]["cvss"]["normalized"] == 0
    assert body["breakdown"]["exploit_availability"]["raw_value"] is False


# -- GET /risk/fleet-summary ------------------------------------------------


def test_fleet_summary_with_no_devices(client):
    assert client.get("/risk/fleet-summary").json() == {
        "total_devices": 0, "average_score": None,
        "by_category": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    }


def test_fleet_summary_counts_by_category(client, conn):
    _register_device(conn, "cam-low", criticality="low", exposure="none")
    _register_device(conn, "cam-critical", criticality="critical", exposure="internet_facing")

    body = client.get("/risk/fleet-summary").json()

    assert body["total_devices"] == 2
    assert body["average_score"] is not None
    assert sum(body["by_category"].values()) == 2
