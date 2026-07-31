import json

import psycopg
import pytest
from fastapi.testclient import TestClient


def _register(conn, device_id="route-cam"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host, source)
        VALUES (%s, 'Route Cam', '', 'insecure', 'device-insecure', 'manual')
        """,
        (device_id,),
    )
    conn.execute(
        """
        INSERT INTO device_services (device_id, service_type, port, published_port)
        VALUES (%s, 'http', 80, 8081)
        """,
        (device_id,),
    )
    conn.commit()


# Matches the client fixture convention used by every other test file in this
# suite: postgres_url + monkeypatch set DATABASE_URL before main.app is
# imported, since main.get_connection() reads DATABASE_URL lazily at request
# time via os.environ[...].
@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def test_unknown_device_returns_404(client):
    assert client.get("/devices/no-such-device/report.pdf").status_code == 404


def test_malformed_device_id_returns_400_with_field(client):
    response = client.get("/devices/Bad_Device/report.pdf")
    assert response.status_code == 400
    assert response.json()["field"] == "device_id"


def test_returns_a_pdf_with_a_download_filename(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    pytest.importorskip("weasyprint")
    response = client.get("/devices/route-cam/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "iotguard-route-cam-" in disposition
    assert response.content.startswith(b"%PDF-")


def test_unknown_device_returns_404_for_html(client):
    assert client.get("/devices/no-such-device/report.html").status_code == 404


def test_unknown_device_returns_404_for_json(client):
    assert client.get("/devices/no-such-device/report.json").status_code == 404


def test_html_report_renders_real_content_without_weasyprint(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    response = client.get("/devices/route-cam/report.html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Route Cam" in response.text
    assert "<style>" in response.text  # the stylesheet is inlined, not a relative <link>


def test_html_report_renders_the_vulnerability_intelligence_section(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
        conn.execute(
            """
            INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                                  command, timestamp, finding, observations,
                                  raw_output_path, confidence, sha256)
            VALUES ('EV-VULN-1', 'route-cam', 'TEST-FW-MANIFEST', 'python3', '3.12',
                    'firmware_check.py manifest', now(), 'firmware manifest analyzed', %s::jsonb,
                    'document-store/raw/x.txt', 'high', 'abc123')
            """,
            (json.dumps({
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
            }),),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.get("/devices/route-cam/report.html")

    assert response.status_code == 200
    assert "openssl@1.0.1e" in response.text
    assert "CVE-2014-0160" in response.text
    assert "1 KEV-LISTED" in response.text


def test_html_report_renders_the_risk_assessment_section(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    response = client.get("/devices/route-cam/report.html")

    assert response.status_code == 200
    assert "Risk assessment" in response.text
    assert "Compliance (NCA CGIoT-1:2024)" in response.text
    assert "Device criticality" in response.text


def test_json_report_includes_methodology_and_disclaimer(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    response = client.get("/devices/route-cam/report.json")
    assert response.status_code == 200
    body = response.json()
    assert body["device"]["display_name"] == "Route Cam"
    assert "deterministic rule evaluator" in body["methodology"]
    assert "not an official certification" in body["disclaimer"]
    assert isinstance(body["controls_not_assessed"], list)


def test_generating_a_report_records_it_in_report_history(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    assert client.get("/devices/route-cam/report.json").status_code == 200
    assert client.get("/devices/route-cam/report.html").status_code == 200

    history = client.get("/devices/route-cam/report-history").json()
    assert [entry["format"] for entry in history] == ["html", "json"]  # newest first
    assert all(entry["id"].startswith("RPT-") for entry in history)
    assert all(entry["generated_at"] for entry in history)


def test_a_404_report_request_is_not_recorded_in_report_history(client):
    assert client.get("/devices/no-such-device/report.json").status_code == 404
    assert client.get("/devices/no-such-device/report-history").json() == []


def test_report_history_is_empty_for_a_device_that_was_never_exported(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    assert client.get("/devices/route-cam/report-history").json() == []
