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


# -- GET /vuln-intel/devices/{id}: the device-level (no-firmware) half -------
# Package-level and device-level data are independently gated: a device may
# have either, both, or neither. `has_data` deliberately keeps its narrower
# "a firmware manifest scan happened" meaning (report.py, risk_routes.py and
# the frontend's lib/pipeline.ts all read it that way).


def _seed_device_cve_evidence(conn, evidence_id, device_id, observations):
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES (%s, %s, 'TEST-DEVICE-CVE-LOOKUP', 'python3', '3.12',
                'device_cve_lookup.py', now(), 'device-level CVE lookup', %s::jsonb,
                'document-store/raw/test.txt', 'high', 'abc123')
        """,
        (evidence_id, device_id, json.dumps(observations)),
    )
    conn.commit()


NETGEAR_DEVICE_CVE_OBSERVATIONS = {
    "vendor": "Netgear", "model": "R7000", "firmware_version": "V1.0.11.132_10.2.132",
    "cpe": "o:netgear:r7000_firmware", "cpe_matched": True,
    "device_cves": [
        {"id": "CVE-2021-34991", "cvss": 8.8, "summary": "UPnP RCE",
         "kev_listed": True, "kev_date_added": "2022-01-10"},
        {"id": "CVE-2016-6277", "cvss": 8.8, "summary": "CSRF",
         "kev_listed": False, "kev_date_added": None},
    ],
    "total_device_cves": 2, "kev_listed_device_cves": 1, "highest_device_cvss": 8.8,
    "notes": ["2 CVE(s) are published against Netgear R7000 at the device level"],
}


def test_device_summary_reports_no_device_cve_data_when_none_was_ever_collected(client, conn):
    _seed_manifest_evidence(conn, "EV-FW-ONLY", "device-insecure", [OPENSSL_PACKAGE_WITH_KEV])

    body = client.get("/vuln-intel/devices/device-insecure").json()

    assert body["has_data"] is True  # package-level, unchanged
    assert body["has_device_cve_data"] is False
    assert body["device_identity"] is None
    assert body["device_cves"] == []
    assert body["total_device_cves"] == 0


def test_device_summary_returns_device_cves_with_no_firmware_scan_at_all(client, conn):
    # The feature's whole premise: real CVE data for a device that has never
    # had a firmware archive uploaded.
    _seed_device_cve_evidence(conn, "EV-DEV-1", "device-router-gw", NETGEAR_DEVICE_CVE_OBSERVATIONS)

    body = client.get("/vuln-intel/devices/device-router-gw").json()

    assert body["has_data"] is False  # no firmware manifest, and that stays false
    assert body["has_device_cve_data"] is True
    assert body["device_cve_evidence_id"] == "EV-DEV-1"
    assert body["device_identity"] == {
        "vendor": "Netgear", "model": "R7000", "firmware_version": "V1.0.11.132_10.2.132",
        "cpe": "o:netgear:r7000_firmware", "cpe_matched": True,
    }
    assert [c["id"] for c in body["device_cves"]] == ["CVE-2021-34991", "CVE-2016-6277"]
    assert body["kev_listed_device_cves"] == 1
    assert body["highest_device_cvss"] == 8.8


def test_device_summary_returns_both_sources_together(client, conn):
    _seed_manifest_evidence(conn, "EV-FW-BOTH", "device-router-gw", [BUSYBOX_PACKAGE_NO_KEV])
    _seed_device_cve_evidence(conn, "EV-DEV-BOTH", "device-router-gw", NETGEAR_DEVICE_CVE_OBSERVATIONS)

    body = client.get("/vuln-intel/devices/device-router-gw").json()

    assert body["has_data"] is True
    assert body["has_device_cve_data"] is True
    assert body["total_packages"] == 1          # package-level rollup intact
    assert body["total_cves"] == 1
    assert body["total_device_cves"] == 2       # and independent of it


def test_device_summary_reports_an_unmatched_cpe_as_a_real_checked_result(client, conn):
    # device-nvr's real case - Dahua NVR4108-8P has no NVD CPE coverage.
    _seed_device_cve_evidence(conn, "EV-DEV-NOCPE", "device-nvr", {
        "vendor": "Dahua", "model": "NVR4108-8P", "firmware_version": "3.218.0000019.0",
        "cpe": None, "cpe_matched": False, "device_cves": [],
        "total_device_cves": 0, "kev_listed_device_cves": 0, "highest_device_cvss": None,
        "notes": ["No CPE mapping is available for Dahua NVR4108-8P"],
    })

    body = client.get("/vuln-intel/devices/device-nvr").json()

    # has_device_cve_data is True - the lookup DID run and produced a real
    # answer. cpe_matched carries the "we could not map this product" nuance,
    # so the UI never renders a gap as a clean bill of health.
    assert body["has_device_cve_data"] is True
    assert body["device_identity"]["cpe_matched"] is False
    assert body["device_cves"] == []
    assert any("No CPE mapping" in note for note in body["notes"])


def test_device_summary_uses_only_the_most_recent_device_cve_evidence(client, conn):
    _seed_device_cve_evidence(conn, "EV-DEV-OLD", "device-router-gw", {
        **NETGEAR_DEVICE_CVE_OBSERVATIONS, "device_cves": [], "total_device_cves": 0,
    })
    _seed_device_cve_evidence(conn, "EV-DEV-NEW", "device-router-gw", NETGEAR_DEVICE_CVE_OBSERVATIONS)

    body = client.get("/vuln-intel/devices/device-router-gw").json()

    assert body["device_cve_evidence_id"] == "EV-DEV-NEW"
    assert body["total_device_cves"] == 2


def test_device_summary_carries_the_firmware_currency_verdict(client, conn):
    _seed_device_cve_evidence(conn, "EV-CURRENCY", "device-router-gw", {
        **NETGEAR_DEVICE_CVE_OBSERVATIONS,
        "firmware_currency": {
            "status": "outdated",
            "reason": "1 published CVE(s) are fixed in a newer firmware version.",
            "sources_checked": ["nvd_version_range"],
            "affected_count": 1, "affected_no_fix_count": 0,
            "not_affected_count": 1, "unknown_count": 0,
        },
    })

    body = client.get("/vuln-intel/devices/device-router-gw").json()

    assert body["firmware_currency"]["status"] == "outdated"
    assert body["firmware_currency"]["sources_checked"] == ["nvd_version_range"]


def test_device_summary_reports_null_currency_for_evidence_that_predates_the_check(client, conn):
    # Evidence recorded before the firmware-currency feature existed simply has
    # no such key. It must come back null - absent, not a claim of any status.
    _seed_device_cve_evidence(conn, "EV-OLD-SHAPE", "device-router-gw", NETGEAR_DEVICE_CVE_OBSERVATIONS)

    assert client.get("/vuln-intel/devices/device-router-gw").json()["firmware_currency"] is None


def test_device_summary_with_no_evidence_at_all_has_a_null_currency_key(client):
    body = client.get("/vuln-intel/devices/device-nvr").json()
    assert body["has_device_cve_data"] is False
    assert body["firmware_currency"] is None
