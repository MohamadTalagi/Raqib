import psycopg
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(postgres_url, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    from main import app
    return TestClient(app)


def _register(conn, device_id="summary-cam"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host, source)
        VALUES (%s, 'Summary Cam', '', 'insecure', 'device-insecure', 'manual')
        """,
        (device_id,),
    )
    conn.commit()


def test_get_executive_summary_with_no_devices(client):
    response = client.get("/executive-summary")
    assert response.status_code == 200
    body = response.json()
    assert body["devices"] == []
    assert body["fleet_summary"]["total_devices"] == 0


def test_get_executive_summary_includes_a_registered_device(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    response = client.get("/executive-summary")
    assert response.status_code == 200
    body = response.json()
    assert len(body["devices"]) == 1
    assert body["devices"][0]["device_id"] == "summary-cam"
    assert body["devices"][0]["priority_rank"] == 1


def test_report_pdf_renders(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    pytest.importorskip("weasyprint")
    response = client.get("/executive-summary/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "iotguard-executive-summary-" in disposition
    assert response.content.startswith(b"%PDF-")


def test_report_html_renders_real_content_without_weasyprint(client, postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register(conn)
    finally:
        conn.close()

    response = client.get("/executive-summary/report.html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Summary Cam" in response.text
    assert "<style>" in response.text
    assert "no AI-generated narrative text" in response.text
