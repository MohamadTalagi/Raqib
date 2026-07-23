"""Database persistence test (Week 1 brief, task 10): data written through
one connection/process must still be readable through a completely separate
one - proving it was actually committed to the database, not held in
memory by a single session. This is the practical, testable proxy for "the
system must retain previous assessments after restart": a fresh connection
is exactly what a freshly restarted API process would open.
"""

import psycopg
import pytest


def test_device_written_via_one_connection_is_visible_via_a_fresh_one(postgres_url):
    writer = psycopg.connect(postgres_url)
    try:
        writer.execute(
            """
            INSERT INTO devices (device_id, display_name, description, tier, host, source)
            VALUES ('persist-cam', 'Persistence Cam', '', 'insecure', 'persist-cam', 'manual')
            """
        )
        writer.commit()
    finally:
        writer.close()

    reader = psycopg.connect(postgres_url)
    try:
        row = reader.execute(
            "SELECT display_name FROM devices WHERE device_id = 'persist-cam'"
        ).fetchone()
    finally:
        reader.close()

    assert row is not None
    assert row[0] == "Persistence Cam"


def test_assessment_and_its_jobs_survive_across_connections(postgres_url):
    writer = psycopg.connect(postgres_url)
    try:
        writer.execute(
            """
            INSERT INTO devices (device_id, display_name, description, tier, host, source)
            VALUES ('persist-cam-2', 'Persistence Cam 2', '', 'insecure', 'persist-cam-2', 'manual')
            """
        )
        writer.execute(
            """
            INSERT INTO assessments (id, device_id, status, policy_version)
            VALUES ('ASMT-PERSIST-0001', 'persist-cam-2', 'completed', '1.0.0')
            """
        )
        writer.execute(
            """
            INSERT INTO scan_jobs (device_id, test_id, status, assessment_id)
            VALUES ('persist-cam-2', 'TEST-NET-REACHABILITY', 'recorded', 'ASMT-PERSIST-0001')
            """
        )
        writer.commit()
    finally:
        writer.close()

    reader = psycopg.connect(postgres_url)
    try:
        assessment = reader.execute(
            "SELECT status, policy_version FROM assessments WHERE id = 'ASMT-PERSIST-0001'"
        ).fetchone()
        job = reader.execute(
            "SELECT status FROM scan_jobs WHERE assessment_id = 'ASMT-PERSIST-0001'"
        ).fetchone()
    finally:
        reader.close()

    assert assessment == ("completed", "1.0.0")
    assert job == ("recorded",)


def test_evidence_and_verdict_survive_across_connections(postgres_url):
    writer = psycopg.connect(postgres_url)
    try:
        writer.execute(
            """
            INSERT INTO evidence (
                evidence_id, device_id, test_id, tool, tool_version, command, timestamp,
                finding, observations, raw_output_path, confidence, sha256
            ) VALUES (
                'EV-PERSIST-0001', 'persist-cam-3', 'TEST-AUTH-DEFAULT-CREDS', 'curl', '8.5.0',
                'curl ...', now(), 'default creds accepted', '{"default_creds": true}'::jsonb,
                'document-store/raw/EV-PERSIST-0001.txt', 'high', %s
            )
            """,
            ("a" * 64,),
        )
        writer.execute(
            """
            INSERT INTO verdicts (
                verdict_id, control_id, device_id, status, severity, evidence_ids,
                reason, saudi_source, remediation, timestamp
            ) VALUES (
                'VD-PERSIST-0001', 'SA-IOT-002', 'persist-cam-3', 'FAIL', 'high',
                '["EV-PERSIST-0001"]'::jsonb, 'because', '{}'::jsonb, 'fix it', now()
            )
            """
        )
        writer.commit()
    finally:
        writer.close()

    reader = psycopg.connect(postgres_url)
    try:
        evidence = reader.execute(
            "SELECT finding FROM evidence WHERE evidence_id = 'EV-PERSIST-0001'"
        ).fetchone()
        verdict = reader.execute(
            "SELECT status FROM verdicts WHERE verdict_id = 'VD-PERSIST-0001'"
        ).fetchone()
    finally:
        reader.close()

    assert evidence == ("default creds accepted",)
    assert verdict == ("FAIL",)
