import psycopg
import pytest
from fastapi.testclient import TestClient


# Matches every other test file's client fixture convention: postgres_url +
# monkeypatch set DATABASE_URL before main.app is imported, since
# get_connection() reads DATABASE_URL lazily at request time.
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


def _seed_control(conn, control_id, *, domain_id="2", scope_type="device", required=True, severity="high"):
    guideline_id = "-".join(control_id.rsplit("-", 3)[-3:])
    subdomain_id = "-".join(guideline_id.split("-")[:2])
    conn.execute(
        """
        INSERT INTO compliance_controls (
            id, domain_id, domain_name, subdomain_id, subdomain_name, guideline_id,
            canonical_requirement, implementation_summary, scope_type, assessment_type,
            required, severity
        ) VALUES (%s, %s, 'Cybersecurity Defense', %s, 'Access and Permission Restriction',
                  %s, 'Do not use default or hard-coded passwords.', 'No default creds.',
                  %s, 'automated', %s, %s)
        """,
        (control_id, domain_id, subdomain_id, guideline_id, scope_type, required, severity),
    )
    conn.commit()


def _register_device(conn, device_id="cam-1"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host, source)
        VALUES (%s, 'Test Cam', '', 'insecure', 'device-insecure', 'manual')
        """,
        (device_id,),
    )
    conn.commit()


CONTROL_ID = "NCA-CGIoT-1_2024-2-2-2"


def test_summary_reports_product_label_and_disclaimer(client):
    body = client.get("/nca/summary").json()
    assert body["product_label"] == "NCA CGIoT-1:2024 Alignment"
    assert "not an NCA certification" in body["disclaimer"]


def test_controls_list_is_empty_until_seeded(client):
    assert client.get("/nca/controls").json() == []


def test_control_filters_by_domain_id(client, conn):
    _seed_control(conn, CONTROL_ID)
    _seed_control(conn, "NCA-CGIoT-1_2024-1-1-1", domain_id="1", scope_type="organization")
    assert len(client.get("/nca/controls", params={"domain_id": "2"}).json()) == 1
    assert len(client.get("/nca/controls", params={"domain_id": "1"}).json()) == 1


def test_get_unknown_control_is_404(client):
    assert client.get("/nca/controls/no-such-control").status_code == 404


def test_device_with_no_assessments_reads_not_tested(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    body = client.get("/nca/devices/cam-1").json()
    assert body["overall_status"] == "not_tested"
    assert body["score"] is None


def test_create_assessment_requires_reviewer_identity(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated",
            # assessed_by deliberately omitted
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "assessed_by"


def test_create_assessment_requires_exactly_one_scope(client, conn):
    _seed_control(conn, CONTROL_ID)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "status": "fail", "severity": "high",
            "test_method": "automated", "assessed_by": "reviewer",
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "device_id"


def test_create_assessment_drives_device_overall_status_to_fail(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "finding": "default creds accepted",
        },
    )
    assert response.status_code == 201
    assert response.json()["superseded_by"] is None

    detail = client.get("/nca/devices/cam-1").json()
    assert detail["overall_status"] == "fail"


def test_reassessing_supersedes_the_prior_row_and_writes_an_audit_event(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer-1",
        },
    ).json()

    second = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "pass",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer-2",
            "reason": "credentials rotated",
        },
    ).json()

    control_detail = client.get(f"/nca/controls/{CONTROL_ID}").json()
    superseded = next(a for a in control_detail["assessments"] if a["id"] == first["id"])
    assert superseded["superseded_by"] == second["id"]

    events = control_detail["audit_events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "assessment_superseded"
    assert events[0]["actor"] == "reviewer-2"
    assert events[0]["before_value"]["status"] == "fail"
    assert events[0]["after_value"]["status"] == "pass"

    # Original result is never mutated - it's still readable exactly as recorded.
    assert first["status"] == "fail"


def test_retest_marks_retest_status_from_the_new_result(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer-1",
        },
    ).json()

    retested = client.post(
        f"/nca/assessments/{first['id']}/retest",
        json={"status": "pass", "assessed_by": "reviewer-2", "finding": "fixed"},
    ).json()
    assert retested["retest_status"] == "passed"
    assert retested["retested_at"] is not None


def test_retest_unknown_assessment_is_404(client):
    response = client.post("/nca/assessments/no-such-id/retest", json={"status": "pass", "assessed_by": "x"})
    assert response.status_code == 404


def test_exception_excludes_control_from_device_score(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
        },
    )
    assert client.get("/nca/devices/cam-1").json()["overall_status"] == "fail"

    exception = client.post(
        "/nca/exceptions",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1",
            "reason": "compensating network segmentation in place",
            "requested_by": "reviewer", "expires_at": "2099-01-01T00:00:00Z",
        },
    ).json()

    approved = client.post(f"/nca/exceptions/{exception['id']}/approve", json={"approved_by": "approver"})
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    # The fail is now excluded from the denominator entirely.
    assert client.get("/nca/devices/cam-1").json()["overall_status"] == "not_tested"


def test_approve_exception_without_approved_by_is_422(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    exception = client.post(
        "/nca/exceptions",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "reason": "reason",
            "requested_by": "reviewer", "expires_at": "2099-01-01T00:00:00Z",
        },
    ).json()
    response = client.post(f"/nca/exceptions/{exception['id']}/approve", json={})
    assert response.status_code == 422


def test_reject_exception_without_rejected_by_is_422(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    exception = client.post(
        "/nca/exceptions",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "reason": "reason",
            "requested_by": "reviewer", "expires_at": "2099-01-01T00:00:00Z",
        },
    ).json()
    response = client.post(f"/nca/exceptions/{exception['id']}/reject", json={})
    assert response.status_code == 422


def test_exception_requires_expiry(client, conn):
    _seed_control(conn, CONTROL_ID)
    response = client.post(
        "/nca/exceptions",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "reason": "reason",
            "requested_by": "reviewer",
            # expires_at deliberately omitted
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "expires_at"


def test_recompute_is_idempotent(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    conn.execute(
        """
        INSERT INTO compliance_finding_mappings (finding_key, description, control_id, match_rule)
        VALUES ('default-creds-accepted', 'test mapping', %s,
                '{"field": "observations.default_creds", "op": "equals", "value": true}')
        """,
        (CONTROL_ID,),
    )
    conn.execute(
        """
        INSERT INTO evidence (
            evidence_id, device_id, test_id, tool, tool_version, command, timestamp,
            finding, observations, raw_output_path, confidence, sha256
        ) VALUES ('EV-TEST-0001', 'device-insecure', 'TEST-AUTH-DEFAULT-CREDS', 'curl', '8.5.0',
                  'curl ...', now(), 'default creds accepted',
                  '{"default_creds": true}', 'document-store/raw/EV-TEST-0001.txt', 'high', 'abc123')
        """
    )
    conn.commit()

    first = client.post("/nca/assessments/recompute").json()
    assert first["created"] == 1

    second = client.post("/nca/assessments/recompute").json()
    assert second["created"] == 0


def test_recompute_never_overwrites_an_existing_manual_assessment(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    conn.execute(
        """
        INSERT INTO compliance_finding_mappings (finding_key, description, control_id, match_rule)
        VALUES ('default-creds-accepted', 'test mapping', %s,
                '{"field": "observations.default_creds", "op": "equals", "value": true}')
        """,
        (CONTROL_ID,),
    )
    conn.execute(
        """
        INSERT INTO evidence (
            evidence_id, device_id, test_id, tool, tool_version, command, timestamp,
            finding, observations, raw_output_path, confidence, sha256
        ) VALUES ('EV-TEST-0002', 'device-insecure', 'TEST-AUTH-DEFAULT-CREDS', 'curl', '8.5.0',
                  'curl ...', now(), 'default creds accepted',
                  '{"default_creds": true}', 'document-store/raw/EV-TEST-0002.txt', 'high', 'abc123')
        """
    )
    conn.commit()

    client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "device-insecure", "status": "fail",
            "severity": "high", "test_method": "manual", "assessed_by": "reviewer",
        },
    )
    result = client.post("/nca/assessments/recompute").json()
    assert result["created"] == 0


def test_devices_report_csv_includes_disclaimer_and_header_row(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.get("/nca/reports/devices.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    text = response.text
    assert "NCA CGIoT-1:2024 Alignment" in text
    assert "device_id,display_name,tier,overall_status,score" in text
    assert "cam-1" in text


def test_controls_report_json_includes_framework_metadata(client, conn):
    _seed_control(conn, CONTROL_ID)
    body = client.get("/nca/reports/controls.json").json()
    assert body["framework"] == "NCA-CGIoT"
    assert body["framework_version"] == "1:2024"
    assert len(body["controls"]) == 1


def test_executive_pdf_report_renders(client, conn):
    pytest.importorskip("weasyprint")
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.get("/nca/reports/executive.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
