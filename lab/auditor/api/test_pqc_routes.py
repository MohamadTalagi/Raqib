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


def _register_device(conn, device_id="pqc-cam"):
    conn.execute(
        "INSERT INTO devices (device_id, display_name, description, tier, host, source) "
        "VALUES (%s, 'PQC Cam', '', 'insecure', %s, 'manual')",
        (device_id, device_id),
    )
    conn.commit()


def _seed_evidence(conn, evidence_id, device_id, test_id, observations):
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES (%s, %s, %s, 'python3', '3.12', 'pqc_readiness_check.py', now(),
                'a finding', %s::jsonb, 'document-store/raw/test.txt', 'high', 'abc123')
        """,
        (evidence_id, device_id, test_id, json.dumps(observations)),
    )
    conn.commit()


HYBRID_KEM_CLASSICAL_CERT = {
    "negotiated_group": "X25519MLKEM768", "is_pqc_kem": True,
    "cert_signature_algorithm": "sha256WithRSAEncryption", "is_pqc_signature": False,
    "connection_error": False, "notes": [],
}

CLASSICAL_KEM_AND_CERT = {
    "negotiated_group": "X25519", "is_pqc_kem": False,
    "cert_signature_algorithm": "sha256WithRSAEncryption", "is_pqc_signature": False,
    "connection_error": False, "notes": [],
}

CONNECTION_ERROR_OBSERVATIONS = {
    "negotiated_group": None, "is_pqc_kem": None,
    "cert_signature_algorithm": None, "is_pqc_signature": None,
    "connection_error": True, "notes": [],
}

FIRMWARE_FAILING = {
    "manifest_present": True,
    "packages": [{"name": "openssl", "version": "1.0.1e", "pqc_status": "fail"}],
    "notes": [],
}

FIRMWARE_PASSING = {
    "manifest_present": True,
    "packages": [{"name": "openssl", "version": "3.5.6", "pqc_status": "pass"}],
    "notes": [],
}


# -- GET /pqc-readiness/devices/{id} ----------------------------------------


def test_unknown_device_reports_known_false(client):
    response = client.get("/pqc-readiness/devices/does-not-exist")
    assert response.status_code == 200
    assert response.json()["known"] is False


def test_device_with_no_evidence_is_not_applicable(client, conn):
    _register_device(conn)
    body = client.get("/pqc-readiness/devices/pqc-cam").json()
    assert body["known"] is True
    assert body["overall_status"] == "not_applicable"
    assert body["tls_key_exchange"]["status"] == "not_applicable"
    assert body["firmware_crypto"]["status"] == "not_applicable"


def test_hybrid_kem_with_classical_cert_reports_a_mixed_result(client, conn):
    _register_device(conn)
    _seed_evidence(conn, "EV-1", "pqc-cam", "TEST-PQC-TLS-HANDSHAKE", HYBRID_KEM_CLASSICAL_CERT)

    body = client.get("/pqc-readiness/devices/pqc-cam").json()
    assert body["tls_key_exchange"]["status"] == "pass"
    assert body["tls_key_exchange"]["negotiated_group"] == "X25519MLKEM768"
    assert body["certificate_signature"]["status"] == "fail"
    assert "tip" in body["certificate_signature"]
    assert body["overall_status"] == "fail"
    assert body["fail_count"] == 1


def test_connection_error_reports_unknown_never_a_fabricated_fail(client, conn):
    _register_device(conn)
    _seed_evidence(conn, "EV-1", "pqc-cam", "TEST-PQC-TLS-HANDSHAKE", CONNECTION_ERROR_OBSERVATIONS)

    body = client.get("/pqc-readiness/devices/pqc-cam").json()
    assert body["tls_key_exchange"]["status"] == "unknown"
    assert body["certificate_signature"]["status"] == "unknown"
    assert body["overall_status"] == "unknown"
    assert body["fail_count"] == 0


def test_firmware_crypto_failing_package_includes_a_tip(client, conn):
    _register_device(conn)
    _seed_evidence(conn, "EV-1", "pqc-cam", "TEST-PQC-FIRMWARE-CRYPTO", FIRMWARE_FAILING)

    body = client.get("/pqc-readiness/devices/pqc-cam").json()
    assert body["firmware_crypto"]["status"] == "fail"
    assert "tip" in body["firmware_crypto"]


def test_only_the_latest_evidence_per_test_counts(client, conn):
    _register_device(conn)
    _seed_evidence(conn, "EV-1", "pqc-cam", "TEST-PQC-FIRMWARE-CRYPTO", FIRMWARE_FAILING)
    _seed_evidence(conn, "EV-2", "pqc-cam", "TEST-PQC-FIRMWARE-CRYPTO", FIRMWARE_PASSING)

    body = client.get("/pqc-readiness/devices/pqc-cam").json()
    assert body["firmware_crypto"]["status"] == "pass"


# -- GET /pqc-readiness/devices ----------------------------------------------


def test_devices_list_is_sorted_worst_first(client, conn):
    _register_device(conn, "device-clean")
    _register_device(conn, "device-failing")
    _seed_evidence(conn, "EV-1", "device-failing", "TEST-PQC-TLS-HANDSHAKE", CLASSICAL_KEM_AND_CERT)

    body = client.get("/pqc-readiness/devices").json()
    device_ids = [d["device_id"] for d in body["devices"]]
    assert device_ids.index("device-failing") < device_ids.index("device-clean")


# -- GET /pqc-readiness/fleet-summary -----------------------------------------


def test_fleet_summary_counts_every_criterion(client, conn):
    _register_device(conn, "device-1")
    _register_device(conn, "device-2")
    _seed_evidence(conn, "EV-1", "device-1", "TEST-PQC-TLS-HANDSHAKE", HYBRID_KEM_CLASSICAL_CERT)
    _seed_evidence(conn, "EV-2", "device-2", "TEST-PQC-TLS-HANDSHAKE", CLASSICAL_KEM_AND_CERT)

    body = client.get("/pqc-readiness/fleet-summary").json()
    assert body["total_devices"] == 2
    assert body["tls_key_exchange"]["pass"] == 1
    assert body["tls_key_exchange"]["fail"] == 1
    assert body["certificate_signature"]["fail"] == 2
