from datetime import datetime, timezone

import psycopg
import pytest

from executive_summary import build_executive_summary_model


@pytest.fixture
def conn(postgres_url):
    connection = psycopg.connect(postgres_url)
    yield connection
    connection.close()


def _register_device(conn, device_id, *, criticality="medium", exposure="internal_only"):
    conn.execute(
        """
        INSERT INTO devices (device_id, display_name, description, tier, host, source, criticality, exposure)
        VALUES (%s, %s, '', 'insecure', %s, 'manual', %s, %s)
        """,
        (device_id, f"Device {device_id}", device_id, criticality, exposure),
    )
    conn.commit()


def _add_verdict(conn, device_id, control_id, status, verdict_id):
    conn.execute(
        """
        INSERT INTO verdicts (verdict_id, control_id, device_id, status, severity,
                              evidence_ids, reason, saudi_source, remediation, timestamp)
        VALUES (%s, %s, %s, %s, 'high', '[]'::jsonb, 'reason text', '{}'::jsonb,
                'stored remediation', now())
        """,
        (verdict_id, control_id, device_id, status),
    )
    conn.commit()


def _seed_nca_control(conn, control_id, *, blocking=False):
    guideline_id = "-".join(control_id.rsplit("-", 3)[-3:])
    subdomain_id = "-".join(guideline_id.split("-")[:2])
    conn.execute(
        """
        INSERT INTO compliance_controls (
            id, domain_id, domain_name, subdomain_id, subdomain_name, guideline_id,
            canonical_requirement, implementation_summary, scope_type, assessment_type,
            required, severity, blocking
        ) VALUES (%s, '2', 'Cybersecurity Defense', %s, 'Access and Permission Restriction',
                  %s, 'Do not use default or hard-coded passwords.', 'No default creds.',
                  'device', 'automated', true, 'high', %s)
        """,
        (control_id, subdomain_id, guideline_id, blocking),
    )
    conn.commit()


def _seed_nca_assessment(conn, assessment_id, control_id, device_id, status):
    conn.execute(
        """
        INSERT INTO compliance_assessments (
            id, control_id, device_id, applicability, status, severity, finding,
            test_method, assessed_by, attested_role, attestation_confirmed, attestation_statement
        ) VALUES (%s, %s, %s, 'applicable', %s, 'high', 'a finding', 'automated',
                  'reviewer', 'Lead Auditor', true, 'Reviewed and certified.')
        """,
        (assessment_id, control_id, device_id, status),
    )
    conn.commit()


def _add_remediation(conn, blueprint_id, device_id, control_id, finding_type, finding_id, *, priority="immediate", reviewed=False):
    conn.execute(
        """
        INSERT INTO remediation_blueprints (
            id, finding_type, finding_id, device_id, control_id, model,
            root_cause, remediation_steps, priority, estimated_effort, caveats,
            reviewed, reviewed_by, reviewed_at
        ) VALUES (%s, %s, %s, %s, %s, 'gemini-3.5-flash-lite', 'root cause text',
                  '["step one", "step two"]'::jsonb, %s, '1 hour', 'a caveat',
                  %s, %s, %s)
        """,
        (
            blueprint_id, finding_type, finding_id, device_id, control_id, priority,
            reviewed, "Lead Auditor" if reviewed else None,
            datetime.now(timezone.utc) if reviewed else None,
        ),
    )
    conn.commit()


def test_empty_fleet_has_no_devices_and_null_averages(conn):
    model = build_executive_summary_model(conn)
    assert model["devices"] == []
    assert model["fleet_summary"]["total_devices"] == 0
    assert model["fleet_summary"]["average_risk_score"] is None
    assert model["fleet_summary"]["remediation_coverage_pct"] is None
    assert model["priority_recommendations"] == []
    assert model["significant_compliance_gaps"] == []


def test_devices_are_ranked_by_risk_score_descending(conn):
    _register_device(conn, "device-low-risk", criticality="low", exposure="internal_only")
    _register_device(conn, "device-high-risk", criticality="critical", exposure="internet_facing")

    model = build_executive_summary_model(conn)

    assert [d["device_id"] for d in model["devices"]] == ["device-high-risk", "device-low-risk"]
    assert model["devices"][0]["risk_score"] >= model["devices"][1]["risk_score"]
    assert model["devices"][0]["priority_rank"] == 1
    assert model["devices"][1]["priority_rank"] == 2


def test_device_with_no_remediation_shows_an_empty_list_not_fabricated(conn):
    _register_device(conn, "device-clean")
    model = build_executive_summary_model(conn)
    assert model["devices"][0]["remediation"] == []


def test_sa_iot_gap_appears_under_its_device_but_a_pass_does_not(conn):
    _register_device(conn, "device-1")
    _add_verdict(conn, "device-1", "SA-IOT-002", "FAIL", "VD-1")
    _add_verdict(conn, "device-1", "SA-IOT-003", "PASS", "VD-2")

    model = build_executive_summary_model(conn)
    gaps = model["devices"][0]["sa_iot_gaps"]
    assert len(gaps) == 1
    assert gaps[0]["control_id"] == "SA-IOT-002"
    assert model["fleet_summary"]["total_compliance_gaps"] == 1


def test_nca_gap_appears_under_its_device(conn):
    _register_device(conn, "device-1")
    _seed_nca_control(conn, "NCA-CGIoT-1_2024-2-2-2")
    _seed_nca_assessment(conn, "ASM-1", "NCA-CGIoT-1_2024-2-2-2", "device-1", "fail")

    model = build_executive_summary_model(conn)
    gaps = model["devices"][0]["nca_gaps"]
    assert len(gaps) == 1
    assert gaps[0]["guideline_id"] == "2-2-2"
    assert gaps[0]["status"] == "fail"


def test_remediation_blueprint_appears_under_its_device(conn):
    _register_device(conn, "device-1")
    _add_verdict(conn, "device-1", "SA-IOT-002", "FAIL", "VD-1")
    _add_remediation(conn, "RB-1", "device-1", "SA-IOT-002", "sa_iot_verdict", "VD-1")

    model = build_executive_summary_model(conn)
    remediation = model["devices"][0]["remediation"]
    assert len(remediation) == 1
    assert remediation[0]["id"] == "RB-1"
    assert model["fleet_summary"]["remediation_generated"] == 1
    assert model["fleet_summary"]["remediation_reviewed"] == 0
    assert model["fleet_summary"]["remediation_coverage_pct"] == 100


def test_priority_recommendations_only_include_unreviewed_immediate_priority(conn):
    _register_device(conn, "device-1")
    _add_verdict(conn, "device-1", "SA-IOT-002", "FAIL", "VD-1")
    _add_verdict(conn, "device-1", "SA-IOT-003", "FAIL", "VD-2")
    _add_remediation(conn, "RB-1", "device-1", "SA-IOT-002", "sa_iot_verdict", "VD-1", priority="immediate", reviewed=False)
    _add_remediation(conn, "RB-2", "device-1", "SA-IOT-003", "sa_iot_verdict", "VD-2", priority="immediate", reviewed=True)

    model = build_executive_summary_model(conn)
    recs = model["priority_recommendations"]
    assert len(recs) == 1
    assert recs[0]["id"] == "RB-1"


def test_significant_compliance_gaps_only_include_blocking_failures(conn):
    _register_device(conn, "device-1")
    _seed_nca_control(conn, "NCA-CGIoT-1_2024-2-2-2", blocking=True)
    _seed_nca_control(conn, "NCA-CGIoT-1_2024-2-4-3", blocking=False)
    _seed_nca_assessment(conn, "ASM-1", "NCA-CGIoT-1_2024-2-2-2", "device-1", "fail")
    _seed_nca_assessment(conn, "ASM-2", "NCA-CGIoT-1_2024-2-4-3", "device-1", "fail")

    model = build_executive_summary_model(conn)
    gaps = model["significant_compliance_gaps"]
    assert len(gaps) == 1
    assert gaps[0]["guideline_id"] == "2-2-2"
