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


def _seed_control(
    conn, control_id, *, domain_id="2", scope_type="device", required=True, severity="high", blocking=False
):
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
                  %s, 'automated', %s, %s, %s)
        """,
        (control_id, domain_id, subdomain_id, guideline_id, scope_type, required, severity, blocking),
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


def test_create_assessment_requires_attestation_confirmed(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            # attestation_confirmed deliberately omitted
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "attestation_confirmed"


def test_create_assessment_rejects_attestation_confirmed_false(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attestation_confirmed": False, "attested_role": "Auditor",
            "attestation_statement": "text",
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "attestation_confirmed"


def test_create_assessment_requires_attested_role(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attestation_confirmed": True, "attestation_statement": "text",
            # attested_role deliberately omitted
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "attested_role"


def test_create_assessment_stores_attestation_fields(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    body = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed and certified.",
        },
    ).json()
    assert body["attested_role"] == "Lead Auditor"
    assert body["attestation_confirmed"] is True
    assert body["attestation_statement"] == "Reviewed and certified."


def test_recompute_placeholder_needs_no_attestation(client, conn):
    # /assessments/recompute's own system-generated not_tested placeholder
    # (see the INSERT in recompute_assessments) must still succeed - it is
    # not a human verdict, so the attestation requirement doesn't apply to
    # it. Exercised indirectly here via the same validation path a real
    # not_tested assessment would go through.
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "not_tested",
            "severity": "high", "test_method": "automated", "assessed_by": "system:recompute",
            # no attestation fields at all
        },
    )
    assert response.status_code == 201


def test_create_assessment_requires_exactly_one_scope(client, conn):
    _seed_control(conn, CONTROL_ID)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "status": "fail", "severity": "high",
            "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
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
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
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
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()

    second = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "pass",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer-2",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
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
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()

    retested = client.post(
        f"/nca/assessments/{first['id']}/retest",
        json={
            "status": "pass", "assessed_by": "reviewer-2", "finding": "fixed",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
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
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
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
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
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


# ---------------------------------------------------------------------------
# Readiness classification (Passed / Partially Passed / Failed)
# ---------------------------------------------------------------------------


def test_device_detail_includes_readiness_classification(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    body = client.get("/nca/devices/cam-1").json()
    assert body["readiness"]["classification"] == "failed"  # nothing tested yet
    assert body["readiness"]["score"] is None


def test_device_readiness_failed_when_blocking_control_fails(client, conn):
    _seed_control(conn, CONTROL_ID, blocking=True)
    _register_device(conn)
    client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    )
    body = client.get("/nca/devices/cam-1").json()
    assert body["readiness"]["classification"] == "failed"
    assert body["readiness"]["blocking_control_ids"] == [CONTROL_ID]


def test_organization_detail_includes_readiness_classification(client, conn):
    _seed_control(conn, "NCA-CGIoT-1_2024-1-1-1", domain_id="1", scope_type="organization")
    body = client.get("/nca/organization").json()
    assert body["readiness"]["classification"] == "failed"


def test_devices_list_includes_readiness_classification(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    body = client.get("/nca/devices").json()
    assert body[0]["readiness_classification"] == "failed"


def test_control_accepts_blocking_field(client, conn):
    _seed_control(conn, CONTROL_ID, blocking=True)
    body = client.get(f"/nca/controls/{CONTROL_ID}").json()["control"]
    assert body["blocking"] is True


# ---------------------------------------------------------------------------
# review_required status
# ---------------------------------------------------------------------------


def test_create_assessment_accepts_review_required_status(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "review_required",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
            "finding": "conflicting evidence - needs a second look",
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "review_required"

    detail = client.get("/nca/devices/cam-1").json()
    assert detail["overall_status"] == "partial"


def test_create_assessment_rejects_unknown_status(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    response = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "bogus",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "status"


# ---------------------------------------------------------------------------
# Auditor override
# ---------------------------------------------------------------------------


def test_override_requires_justification(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()
    response = client.post(
        f"/nca/assessments/{first['id']}/override",
        json={"status": "pass", "overridden_by": "auditor-1"},
    )
    assert response.status_code == 400
    assert response.json()["field"] == "justification"


def test_override_requires_auditor_identity(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()
    response = client.post(
        f"/nca/assessments/{first['id']}/override",
        json={"status": "pass", "justification": "risk accepted after compensating control review"},
    )
    assert response.status_code == 400
    assert response.json()["field"] == "overridden_by"


def test_override_unknown_assessment_is_404(client):
    response = client.post(
        "/nca/assessments/no-such-id/override",
        json={"status": "pass", "justification": "reason", "overridden_by": "auditor-1"},
    )
    assert response.status_code == 404


def test_override_supersedes_original_and_writes_audit_trail(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()

    response = client.post(
        f"/nca/assessments/{first['id']}/override",
        json={
            "status": "pass",
            "justification": "compensating network segmentation verified on-site",
            "overridden_by": "auditor-1",
            "original_status": "fail",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    )
    assert response.status_code == 201
    overridden = response.json()
    assert overridden["status"] == "pass"
    assert overridden["original_status"] == "fail"
    assert "compensating network segmentation" in overridden["override_justification"]

    # The original result is never mutated, and both the original and the
    # override remain permanently visible in the control's audit trail.
    control_detail = client.get(f"/nca/controls/{CONTROL_ID}").json()
    original = next(a for a in control_detail["assessments"] if a["id"] == first["id"])
    assert original["status"] == "fail"
    assert original["superseded_by"] == overridden["id"]

    events = control_detail["audit_events"]
    assert any(e["event_type"] == "assessment_overridden" and e["actor"] == "auditor-1" for e in events)
    override_event = next(e for e in events if e["event_type"] == "assessment_overridden")
    assert "compensating network segmentation" in override_event["reason"]

    # The device now reflects the overridden (passing) result, not the original.
    detail = client.get("/nca/devices/cam-1").json()
    assert detail["overall_status"] == "pass"


def test_override_carries_forward_audit_trail_fields_not_in_the_payload(client, conn):
    # override_assessment used to build its merged payload from an explicit
    # field list that omitted raw_result_reference/scanner_tool/
    # scanner_tool_version/firmware_version_assessed/remediation_due_date -
    # an override that didn't re-supply them silently erased which
    # scanner/tool/firmware version produced the original finding.
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
            "raw_result_reference": "EV-2026-08-05-0001",
            "scanner_tool": "nmap", "scanner_tool_version": "7.95",
            "firmware_version_assessed": "1.0.0-old",
            "remediation_due_date": "2026-09-01T00:00:00Z",
        },
    ).json()
    assert first["raw_result_reference"] == "EV-2026-08-05-0001"  # sanity: the seed actually carries them

    overridden = client.post(
        f"/nca/assessments/{first['id']}/override",
        json={
            "status": "pass",
            "justification": "compensating control verified on-site",
            "overridden_by": "auditor-1",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
            # Deliberately NOT re-supplying any of the 5 fields below.
        },
    ).json()

    assert overridden["raw_result_reference"] == "EV-2026-08-05-0001"
    assert overridden["scanner_tool"] == "nmap"
    assert overridden["scanner_tool_version"] == "7.95"
    assert overridden["firmware_version_assessed"] == "1.0.0-old"
    assert overridden["remediation_due_date"] is not None
    assert overridden["remediation_due_date"].startswith("2026-09-01")


def test_override_still_allows_an_explicit_value_to_win(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
            "scanner_tool": "nmap",
        },
    ).json()

    overridden = client.post(
        f"/nca/assessments/{first['id']}/override",
        json={
            "status": "pass",
            "justification": "reassessed with a different tool",
            "overridden_by": "auditor-1",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
            "scanner_tool": "openssl",
        },
    ).json()

    assert overridden["scanner_tool"] == "openssl"


def test_retest_carries_forward_audit_trail_fields_not_in_the_payload(client, conn):
    # The sibling retest_assessment endpoint had the identical bug -
    # its merged dict also omitted these 5 fields before spreading
    # **payload, so a retest that didn't re-supply them lost them too.
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer-1",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
            "raw_result_reference": "EV-2026-08-05-0002",
            "scanner_tool": "curl", "scanner_tool_version": "8.5.0",
            "firmware_version_assessed": "1.0.0-old",
        },
    ).json()

    retested = client.post(
        f"/nca/assessments/{first['id']}/retest",
        json={
            "status": "pass", "assessed_by": "reviewer-2", "finding": "fixed",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()

    assert retested["raw_result_reference"] == "EV-2026-08-05-0002"
    assert retested["scanner_tool"] == "curl"
    assert retested["scanner_tool_version"] == "8.5.0"
    assert retested["firmware_version_assessed"] == "1.0.0-old"


def test_override_rejects_stale_original_status(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post(
        "/nca/assessments",
        json={
            "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
            "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
            "attested_role": "Lead Auditor", "attestation_confirmed": True,
            "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
        },
    ).json()

    response = client.post(
        f"/nca/assessments/{first['id']}/override",
        json={
            "status": "pass",
            "justification": "reason",
            "overridden_by": "auditor-1",
            "original_status": "pass",  # doesn't match the assessment's real current status ("fail")
        },
    )
    assert response.status_code == 400
    assert response.json()["field"] == "original_status"


# ---------------------------------------------------------------------------
# Auto-verdict suggestions (per-device assessment workspace)
# ---------------------------------------------------------------------------


def _seed_mapping(conn, control_id, finding_key, match_rule, *, verdict_hint="fail", description="m"):
    conn.execute(
        """
        INSERT INTO compliance_finding_mappings
            (finding_key, description, control_id, match_rule, verdict_hint)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (finding_key, description, control_id, match_rule, verdict_hint),
    )
    conn.commit()


def _seed_evidence(conn, evidence_id, device_id, observations, *, test_id="TEST-X"):
    conn.execute(
        """
        INSERT INTO evidence (
            evidence_id, device_id, test_id, tool, tool_version, command, timestamp,
            finding, observations, raw_output_path, confidence, sha256
        ) VALUES (%s, %s, %s, 'curl', '8.5.0', 'curl ...', now(), 'finding',
                  %s, 'document-store/raw/x.txt', 'high', 'abc123')
        """,
        (evidence_id, device_id, test_id, observations),
    )
    conn.commit()


def test_suggestions_404_for_unknown_device(client):
    assert client.get("/nca/devices/nope/suggestions").status_code == 404


def test_suggestions_empty_when_no_matching_evidence(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    body = client.get("/nca/devices/device-insecure/suggestions").json()
    assert body["device_id"] == "device-insecure"
    assert body["suggestions"] == {}


def test_suggestions_fail_from_matching_insecure_evidence(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    _seed_mapping(
        conn, CONTROL_ID, "default-creds-accepted",
        '{"field": "observations.default_creds", "op": "equals", "value": true}',
        description="Default credential accepted.",
    )
    _seed_evidence(conn, "EV-SUG-0001", "device-insecure", '{"default_creds": true}',
                   test_id="TEST-AUTH-DEFAULT-CREDS")

    body = client.get("/nca/devices/device-insecure/suggestions").json()
    suggestion = body["suggestions"][CONTROL_ID]
    assert suggestion["suggested_status"] == "fail"
    assert "EV-SUG-0001" in suggestion["evidence_ids"]
    assert "TEST-AUTH-DEFAULT-CREDS" in suggestion["test_ids"]
    assert any("EV-SUG-0001" in reason for reason in suggestion["reasons"])


def test_suggestions_review_required_when_only_review_hint_matches(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    _seed_mapping(
        conn, CONTROL_ID, "firmware-manifest-present",
        '{"field": "observations.manifest_present", "op": "equals", "value": true}',
        verdict_hint="review_required",
    )
    _seed_evidence(conn, "EV-SUG-0002", "device-insecure", '{"manifest_present": true}')

    suggestion = client.get("/nca/devices/device-insecure/suggestions").json()["suggestions"][CONTROL_ID]
    assert suggestion["suggested_status"] == "review_required"


def test_suggestions_fail_dominates_review_for_same_control(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    _seed_mapping(
        conn, CONTROL_ID, "review-one",
        '{"field": "observations.manifest_present", "op": "equals", "value": true}',
        verdict_hint="review_required",
    )
    _seed_mapping(
        conn, CONTROL_ID, "fail-one",
        '{"field": "observations.default_creds", "op": "equals", "value": true}',
        verdict_hint="fail",
    )
    _seed_evidence(conn, "EV-SUG-0003", "device-insecure",
                   '{"manifest_present": true, "default_creds": true}')

    suggestion = client.get("/nca/devices/device-insecure/suggestions").json()["suggestions"][CONTROL_ID]
    assert suggestion["suggested_status"] == "fail"


def test_suggestions_ignore_other_devices_evidence(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "device-insecure")
    _register_device(conn, "device-hardened")
    _seed_mapping(
        conn, CONTROL_ID, "default-creds-accepted",
        '{"field": "observations.default_creds", "op": "equals", "value": true}',
    )
    _seed_evidence(conn, "EV-SUG-0004", "device-hardened", '{"default_creds": true}')

    body = client.get("/nca/devices/device-insecure/suggestions").json()
    assert body["suggestions"] == {}


def _seed_checklist(conn, control_id, questions, suggestion_rule):
    import json as json_module

    conn.execute(
        """
        INSERT INTO compliance_control_checklists (control_id, questions, suggestion_rule)
        VALUES (%s, %s, %s)
        """,
        (control_id, json_module.dumps(questions), json_module.dumps(suggestion_rule)),
    )
    conn.commit()


def test_get_checklist_404_when_none_authored_yet(client, conn):
    _seed_control(conn, CONTROL_ID)
    response = client.get(f"/nca/controls/{CONTROL_ID}/checklist")
    assert response.status_code == 404


def test_get_checklist_returns_authored_questions(client, conn):
    _seed_control(conn, CONTROL_ID)
    questions = [{"key": "exists", "label": "Does it exist?", "type": "yes_no", "required": True}]
    rule = [{"conditions": [{"field": "answers.exists", "op": "equals", "value": True}], "suggested_status": "pass"}]
    _seed_checklist(conn, CONTROL_ID, questions, rule)

    response = client.get(f"/nca/controls/{CONTROL_ID}/checklist")
    assert response.status_code == 200
    body = response.json()
    assert body["questions"] == questions
    assert body["suggestion_rule"] == rule


def test_evaluate_checklist_404_when_none_authored_yet(client, conn):
    _seed_control(conn, CONTROL_ID)
    response = client.post(f"/nca/controls/{CONTROL_ID}/checklist/evaluate", json={"answers": {}})
    assert response.status_code == 404


def test_evaluate_checklist_returns_suggested_status(client, conn):
    _seed_control(conn, CONTROL_ID)
    rule = [{"conditions": [{"field": "answers.exists", "op": "equals", "value": True}], "suggested_status": "pass"}]
    _seed_checklist(conn, CONTROL_ID, [], rule)

    response = client.post(f"/nca/controls/{CONTROL_ID}/checklist/evaluate", json={"answers": {"exists": True}})
    assert response.status_code == 200
    assert response.json()["suggested_status"] == "pass"


def test_evaluate_checklist_returns_none_when_nothing_matches(client, conn):
    _seed_control(conn, CONTROL_ID)
    rule = [{"conditions": [{"field": "answers.exists", "op": "equals", "value": True}], "suggested_status": "pass"}]
    _seed_checklist(conn, CONTROL_ID, [], rule)

    response = client.post(f"/nca/controls/{CONTROL_ID}/checklist/evaluate", json={"answers": {"exists": False}})
    assert response.status_code == 200
    assert response.json()["suggested_status"] is None


def test_evaluate_checklist_requires_answers_object(client, conn):
    _seed_control(conn, CONTROL_ID)
    _seed_checklist(conn, CONTROL_ID, [], [])
    response = client.post(f"/nca/controls/{CONTROL_ID}/checklist/evaluate", json={})
    assert response.status_code == 400
    assert response.json()["field"] == "answers"


def test_coverage_reports_total_and_guided_or_automated_counts(client, conn):
    # _seed_control's fixed INSERT always writes assessment_type='automated',
    # regardless of scope_type - both seeded rows count toward
    # automated_or_hybrid_count here; the checklist is the only guided signal.
    _seed_control(conn, CONTROL_ID)
    _seed_control(conn, "NCA-CGIoT-1_2024-1-1-1", domain_id="1", scope_type="organization")
    conn.execute(
        """
        INSERT INTO compliance_control_checklists (control_id, questions, suggestion_rule)
        VALUES (%s, '[]'::jsonb, '[]'::jsonb)
        """,
        ("NCA-CGIoT-1_2024-1-1-1",),
    )
    conn.commit()

    body = client.get("/nca/coverage").json()
    assert body["total_guidelines"] == 2
    assert body["automated_or_hybrid_count"] == 2
    assert body["checklist_count"] == 1
    assert body["guided_or_automated_count"] == 3


def _assessment_payload(**overrides):
    payload = {
        "control_id": CONTROL_ID, "device_id": "cam-1", "status": "fail",
        "severity": "high", "test_method": "automated", "assessed_by": "reviewer",
        "attested_role": "Lead Auditor", "attestation_confirmed": True,
        "attestation_statement": "Reviewed the evidence and reasons above; this finding is certified.",
    }
    payload.update(overrides)
    return payload


def test_list_all_assessments_returns_only_the_latest_non_superseded_row(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn)
    first = client.post("/nca/assessments", json=_assessment_payload()).json()
    client.post(f"/nca/assessments/{first['id']}/retest", json=_assessment_payload(status="pass"))

    body = client.get("/nca/assessments").json()
    matching = [a for a in body if a["control_id"] == CONTROL_ID and a["device_id"] == "cam-1"]
    assert len(matching) == 1
    assert matching[0]["status"] == "pass"
    assert matching[0]["superseded_by"] is None


def test_list_all_assessments_filters_by_status(client, conn):
    _seed_control(conn, CONTROL_ID)
    _register_device(conn, "cam-1")
    _register_device(conn, "cam-2")
    client.post("/nca/assessments", json=_assessment_payload(device_id="cam-1", status="fail"))
    client.post("/nca/assessments", json=_assessment_payload(device_id="cam-2", status="pass"))

    failing = client.get("/nca/assessments", params={"status": "fail"}).json()
    assert all(a["status"] == "fail" for a in failing)
    assert any(a["device_id"] == "cam-1" for a in failing)
    assert not any(a["device_id"] == "cam-2" for a in failing)


def test_list_all_assessments_spans_device_and_organizational_scope(client, conn):
    _seed_control(conn, CONTROL_ID)
    _seed_control(conn, "NCA-CGIoT-1_2024-1-1-1", domain_id="1", scope_type="organization")
    _register_device(conn)
    client.post("/nca/assessments", json=_assessment_payload())
    client.post(
        "/nca/assessments",
        json=_assessment_payload(
            control_id="NCA-CGIoT-1_2024-1-1-1", device_id=None,
            organizational_scope_id="default", status="pass", test_method="manual",
        ),
    )

    body = client.get("/nca/assessments").json()
    control_ids = {a["control_id"] for a in body}
    assert CONTROL_ID in control_ids
    assert "NCA-CGIoT-1_2024-1-1-1" in control_ids
