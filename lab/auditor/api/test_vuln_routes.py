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


def _seed_manifest_evidence(
    conn, evidence_id, device_id, packages, *, vuln_db_built_at=None, vuln_db_checksum=None, timestamp="now()",
):
    observations = {"manifest_present": True, "packages": packages, "notes": []}
    if vuln_db_built_at is not None:
        observations["vuln_db_built_at"] = vuln_db_built_at
    if vuln_db_checksum is not None:
        observations["vuln_db_checksum"] = vuln_db_checksum
    conn.execute(
        f"""
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES (%s, %s, 'TEST-FW-MANIFEST', 'python3', '3.12', 'firmware_check.py manifest',
                {timestamp}, 'firmware manifest analyzed', %s::jsonb,
                'document-store/raw/test.txt', 'high', 'abc123')
        """,
        (evidence_id, device_id, json.dumps(observations)),
    )
    conn.commit()


OPENSSL_PACKAGE_WITH_KEV = {
    "name": "openssl", "version": "1.0.1e", "outdated": True, "eol": None,
    "latest_known_version": None, "official_patch_available": True, "patched_version": "1.0.1g",
    "kev_listed_count": 1,
    "cves": [
        {"id": "CVE-2014-0160", "cvss": 7.5, "summary": "Heartbleed", "kev_listed": True, "kev_date_added": "2022-05-04"},
        {"id": "CVE-2016-6304", "cvss": 5.9, "summary": "OOB write", "kev_listed": False, "kev_date_added": None},
    ],
    "notes": [],
}

BUSYBOX_PACKAGE_NO_KEV = {
    "name": "busybox", "version": "1.19.4", "outdated": True, "eol": None,
    "latest_known_version": None, "official_patch_available": True, "patched_version": "1.29.0",
    "kev_listed_count": 0,
    "cves": [
        {"id": "CVE-2022-48174", "cvss": 9.8, "summary": "stack overflow", "kev_listed": False, "kev_date_added": None},
    ],
    "notes": [],
}


# -- GET /vuln-intel/status --------------------------------------------------


def test_status_reports_unknown_when_no_evidence_has_used_grype(client):
    body = client.get("/vuln-intel/status").json()
    assert body == {
        "known": False, "vuln_db_built_at": None, "vuln_db_checksum": None,
        "observed_at": None, "observed_from_evidence_id": None, "observed_from_device_id": None,
    }


def test_status_reports_the_most_recently_observed_snapshot(client, conn):
    _seed_manifest_evidence(
        conn, "EV-OLD", "device-insecure", [OPENSSL_PACKAGE_WITH_KEV],
        vuln_db_built_at="2026-03-09 00:31:20 +0000 UTC", vuln_db_checksum="sha256:old",
        timestamp="now() - interval '1 day'",
    )
    _seed_manifest_evidence(
        conn, "EV-NEW", "device-hardened", [BUSYBOX_PACKAGE_NO_KEV],
        vuln_db_built_at="2026-07-30 12:00:00 +0000 UTC", vuln_db_checksum="sha256:new",
    )

    body = client.get("/vuln-intel/status").json()

    assert body["known"] is True
    assert body["vuln_db_checksum"] == "sha256:new"
    assert body["observed_from_evidence_id"] == "EV-NEW"
    assert body["observed_from_device_id"] == "device-hardened"


def test_status_ignores_evidence_that_never_used_grype(client, conn):
    # A test_id whose observations have no vuln_db_built_at key at all (e.g.
    # a plain nmap scan) must never be picked up here.
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-UNRELATED', 'device-insecure', 'TEST-NET-PORTSCAN', 'nmap', '7.94',
                'nmap -sV device-insecure', now(), 'ports found', '{"open_ports": [80]}'::jsonb,
                'document-store/raw/x.txt', 'high', 'abc123')
        """
    )
    conn.commit()

    assert client.get("/vuln-intel/status").json()["known"] is False


# -- GET /vuln-intel/fleet-summary -------------------------------------------


def test_fleet_summary_is_empty_with_no_manifest_evidence(client):
    body = client.get("/vuln-intel/fleet-summary").json()
    assert body == {"devices": [], "total_cves": 0, "total_kev_listed_cves": 0}


def test_fleet_summary_aggregates_and_sorts_kev_listed_devices_first(client, conn):
    _seed_manifest_evidence(conn, "EV-1", "device-hardened", [BUSYBOX_PACKAGE_NO_KEV])
    _seed_manifest_evidence(conn, "EV-2", "device-insecure", [OPENSSL_PACKAGE_WITH_KEV, BUSYBOX_PACKAGE_NO_KEV])

    body = client.get("/vuln-intel/fleet-summary").json()

    assert [d["device_id"] for d in body["devices"]] == ["device-insecure", "device-hardened"]
    insecure = body["devices"][0]
    assert insecure["total_cves"] == 3
    assert insecure["kev_listed_cves"] == 1
    assert insecure["highest_cvss"] == 9.8
    assert body["total_cves"] == 4
    assert body["total_kev_listed_cves"] == 1


def test_fleet_summary_uses_only_the_most_recent_scan_per_device(client, conn):
    _seed_manifest_evidence(
        conn, "EV-OLD", "device-insecure", [OPENSSL_PACKAGE_WITH_KEV], timestamp="now() - interval '1 day'",
    )
    _seed_manifest_evidence(conn, "EV-NEW", "device-insecure", [BUSYBOX_PACKAGE_NO_KEV])

    body = client.get("/vuln-intel/fleet-summary").json()

    assert len(body["devices"]) == 1
    assert body["devices"][0]["kev_listed_cves"] == 0  # the newer, KEV-free scan wins


# -- GET /vuln-intel/devices/{device_id} -------------------------------------


def test_device_vuln_summary_reports_no_data_when_never_scanned(client):
    body = client.get("/vuln-intel/devices/device-insecure").json()
    assert body["has_data"] is False
    assert body["packages"] == []
    assert body["total_cves"] == 0


def test_device_vuln_summary_returns_real_package_and_cve_data(client, conn):
    _seed_manifest_evidence(conn, "EV-1", "device-insecure", [OPENSSL_PACKAGE_WITH_KEV, BUSYBOX_PACKAGE_NO_KEV])

    body = client.get("/vuln-intel/devices/device-insecure").json()

    assert body["has_data"] is True
    assert body["evidence_id"] == "EV-1"
    assert body["total_packages"] == 2
    assert body["outdated_packages"] == 2
    assert body["total_cves"] == 3
    assert body["kev_listed_cves"] == 1
    assert body["highest_cvss"] == 9.8
    assert [p["name"] for p in body["packages"]] == ["openssl", "busybox"]


def test_device_vuln_summary_rejects_an_invalid_device_id(client):
    response = client.get("/vuln-intel/devices/NOT valid!!")
    assert response.status_code == 400
