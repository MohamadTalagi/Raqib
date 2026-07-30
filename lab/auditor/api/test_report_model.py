import json

import psycopg
import pytest

from report import build_report_model


def _register_device(conn, device_id="report-cam"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host,
                             vendor, model, location, owner, notes, source)
        VALUES (%s, 'Report Cam', 'A camera under test.', 'insecure',
                'device-insecure', 'AcmeCam', NULL, 'Bench 2', NULL, NULL, 'manual')
        """,
        (device_id,),
    )
    conn.execute(
        """
        INSERT INTO device_services (device_id, service_type, port, published_port)
        VALUES (%s, 'http', 80, 8081), (%s, 'mqtt', 1883, NULL)
        """,
        (device_id, device_id),
    )


def _add_evidence(conn, device_id="report-cam"):
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES ('EV-REPORT-1', %s, 'TEST-AUTH-DEFAULT-CREDS', 'curl', '8.5.0',
                'curl -s -X POST http://device-insecure/login', now(),
                'Default creds admin/admin accepted', '{}'::jsonb,
                'document-store/raw/EV-REPORT-1.txt', 'high',
                '7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61')
        """,
        (device_id,),
    )


def _add_verdict(conn, control_id, status, device_id="report-cam", verdict_id="VD-R-1"):
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                              evidence_ids, reason, saudi_source, remediation, timestamp)
        VALUES (%s, %s, %s, %s, 'high', '["EV-REPORT-1"]'::jsonb,
                'observations.default_creds equals True', '{}'::jsonb,
                'stored remediation', now())
        """,
        (verdict_id, control_id, device_id, status),
    )


def test_returns_none_for_unknown_device(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        assert build_report_model(conn, "does-not-exist") is None
    finally:
        conn.close()


def test_device_and_services_are_populated(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    assert model["device"]["display_name"] == "Report Cam"
    assert model["device"]["vendor"] == "AcmeCam"
    assert model["device"]["model"] is None
    assert len(model["services"]) == 2
    mqtt = next(s for s in model["services"] if s["service_type"] == "mqtt")
    assert mqtt["published_port"] is None


def test_device_with_no_evidence_returns_empty_lists_not_an_error(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    assert model["evidence"] == []
    assert model["controls"] == []
    assert model["counts"] == {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0, "NOT_APPLICABLE": 0}


def test_provenance_fields_survive_byte_for_byte(postgres_url):
    # This is the reproducibility claim: a reader must be able to re-run the
    # command and check the hash. Assert it explicitly rather than assuming.
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_evidence(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    row = model["evidence"][0]
    assert row["evidence_id"] == "EV-REPORT-1"
    assert row["tool"] == "curl"
    assert row["tool_version"] == "8.5.0"
    assert row["command"] == "curl -s -X POST http://device-insecure/login"
    assert row["sha256"] == (
        "7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61"
    )
    assert row["raw_output_path"] == "document-store/raw/EV-REPORT-1.txt"
    assert row["confidence"] == "high"


def test_verdict_joins_control_metadata_from_yaml(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_verdict(conn, "SA-IOT-002", "FAIL")
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    control = model["controls"][0]
    assert control["control_id"] == "SA-IOT-002"
    assert control["control_found"] is True
    assert control["title"] == "No default or hard-coded credentials"
    assert control["framework"] == "CGIoT-1:2024"
    assert control["reference"] == "2-2-2"
    assert "default and hard-coded passwords" in control["clause"]
    assert control["status"] == "FAIL"
    assert control["reason"] == "observations.default_creds equals True"
    assert model["counts"]["FAIL"] == 1


def test_verdict_with_missing_control_yaml_still_appears(postgres_url):
    # Verdicts are database rows; controls are files. They can drift. Dropping a
    # verdict whose control file vanished would silently remove a FAIL from a
    # compliance document - the dangerous failure.
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_verdict(conn, "SA-IOT-999", "FAIL")
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    control = model["controls"][0]
    assert control["control_id"] == "SA-IOT-999"
    assert control["control_found"] is False
    assert control["status"] == "FAIL"
    assert control["title"] is None
    assert control["clause"] is None
    assert model["counts"]["FAIL"] == 1


def test_model_includes_methodology_scope_and_disclaimer(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    assert "deterministic rule evaluator" in model["methodology"]
    assert "not an official certification" in model["disclaimer"]
    assert "report-cam" in model["assessment_scope"]
    assert "http" in model["assessment_scope"]


def test_controls_not_assessed_lists_mapped_controls_with_no_verdict(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_verdict(conn, "SA-IOT-002", "FAIL")
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    not_assessed_ids = {c["control_id"] for c in model["controls_not_assessed"]}
    assert "SA-IOT-002" not in not_assessed_ids  # it has a verdict
    assert "SA-IOT-005" in not_assessed_ids  # no verdict was recorded for it
    entry = next(c for c in model["controls_not_assessed"] if c["control_id"] == "SA-IOT-005")
    assert entry["title"] == "Strong TLS configuration for device communications"


def test_verdict_includes_policy_version_and_conflict_fields(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.execute(
            """
            INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                                  evidence_ids, reason, saudi_source, remediation, timestamp,
                                  policy_version, conflict_detected, conflict_reason)
            VALUES ('VD-R-2', 'SA-IOT-002', 'report-cam', 'FAIL', 'high', '["EV-1"]'::jsonb,
                    'because', '{}'::jsonb, 'fix it', now(), '1.0.0', true, 'documentation disagreed')
            """
        )
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    control = model["controls"][0]
    assert control["policy_version"] == "1.0.0"
    assert control["conflict_detected"] is True
    assert control["conflict_reason"] == "documentation disagreed"
    assert control["limitations"]  # SA-IOT-002.yaml has a real limitations string now


def test_verdict_with_path_traversal_control_id_still_appears_and_does_not_raise(
    postgres_url,
):
    # verdict.schema.json leaves control_id an unconstrained string, so a
    # verdict written with a path-traversal control_id must be handled the
    # same way as a missing control file: control_found False, no exception,
    # and - critically - the verdict itself must not be dropped, since
    # dropping it would silently remove a FAIL from a compliance document.
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_verdict(conn, "../../etc/passwd", "FAIL")
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    control = model["controls"][0]
    assert control["control_id"] == "../../etc/passwd"
    assert control["control_found"] is False
    assert control["status"] == "FAIL"
    assert control["title"] is None
    assert control["clause"] is None
    assert model["counts"]["FAIL"] == 1


def test_vulnerabilities_reports_no_data_when_never_scanned(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    assert model["vulnerabilities"] == {
        "has_data": False, "evidence_id": None, "observed_at": None, "packages": [],
    }


def _add_manifest_evidence(conn, device_id="report-cam", evidence_id="EV-MANIFEST-1"):
    observations = {
        "manifest_present": True,
        "vuln_db_built_at": "2026-03-09 00:31:20 +0000 UTC",
        "packages": [
            {
                "name": "openssl", "version": "1.0.1e", "outdated": True, "eol": None,
                "latest_known_version": None, "official_patch_available": True,
                "patched_version": "1.0.1g", "kev_listed_count": 1,
                "cves": [
                    {"id": "CVE-2014-0160", "cvss": 7.5, "summary": "Heartbleed",
                     "kev_listed": True, "kev_date_added": "2022-05-04"},
                ],
                "notes": [],
            },
        ],
        "notes": [],
    }
    conn.execute(
        """
        INSERT INTO evidence (evidence_id, device_id, test_id, tool, tool_version,
                              command, timestamp, finding, observations,
                              raw_output_path, confidence, sha256)
        VALUES (%s, %s, 'TEST-FW-MANIFEST', 'python3', '3.12', 'firmware_check.py manifest',
                now(), 'firmware manifest analyzed', %s::jsonb,
                'document-store/raw/test.txt', 'high', 'abc123')
        """,
        (evidence_id, device_id, json.dumps(observations)),
    )


def test_vulnerabilities_reports_real_package_and_cve_data(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_manifest_evidence(conn)
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    vulns = model["vulnerabilities"]
    assert vulns["has_data"] is True
    assert vulns["evidence_id"] == "EV-MANIFEST-1"
    assert vulns["total_cves"] == 1
    assert vulns["kev_listed_cves"] == 1
    assert vulns["vuln_db_built_at"] == "2026-03-09 00:31:20 +0000 UTC"
    assert vulns["packages"][0]["name"] == "openssl"


def test_report_includes_a_real_risk_score_and_breakdown(postgres_url):
    conn = psycopg.connect(postgres_url)
    try:
        _register_device(conn)
        _add_manifest_evidence(conn)  # gives this device a real CVSS/KEV signal
        conn.commit()
        model = build_report_model(conn, "report-cam")
    finally:
        conn.close()

    risk = model["risk"]
    assert 0 <= risk["risk_score"] <= 100
    assert risk["risk_category"] in ("low", "medium", "high", "critical")
    assert risk["breakdown"]["cvss"]["raw_value"] == 7.5
    assert risk["breakdown"]["exploit_availability"]["raw_value"] is True
    # A never-assessed device (this fixture has no NCA assessment) scores
    # maximum risk from the compliance factor - same honesty rule
    # policies/nca/evaluator.py's device_score() already applies.
    assert risk["breakdown"]["compliance"]["raw_value"] is None
    assert risk["breakdown"]["compliance"]["normalized"] == 100
