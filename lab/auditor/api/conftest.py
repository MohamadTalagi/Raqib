import subprocess
import time

import psycopg
import pytest

TEST_DB_URL = "postgresql://auditor:auditor-lab-pw@localhost:55432/auditor"
CONTAINER_NAME = "auditor-api-test-db"


@pytest.fixture(scope="session")
def postgres_url():
    subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", CONTAINER_NAME,
            "-e", "POSTGRES_DB=auditor",
            "-e", "POSTGRES_USER=auditor",
            "-e", "POSTGRES_PASSWORD=auditor-lab-pw",
            "-p", "55432:5432",
            "postgres:16-alpine",
        ],
        check=True,
    )
    try:
        for _ in range(30):
            try:
                conn = psycopg.connect(TEST_DB_URL)
                conn.close()
                break
            except psycopg.OperationalError:
                time.sleep(1)
        else:
            raise RuntimeError("test postgres did not become ready in time")

        with open("../db/init.sql") as f:
            schema_sql = f.read()
        conn = psycopg.connect(TEST_DB_URL)
        conn.execute(schema_sql)
        conn.commit()
        conn.close()

        yield TEST_DB_URL
    finally:
        subprocess.run(["docker", "stop", CONTAINER_NAME], check=False)


@pytest.fixture(autouse=True)
def clean_tables(postgres_url):
    conn = psycopg.connect(postgres_url)
    conn.execute(
        "TRUNCATE evidence, verdicts, scan_jobs, assessments, device_services, devices, "
        "network_scans, network_scopes, report_records, automated_runs, remediation_blueprints, "
        "compliance_audit_events, compliance_exceptions, compliance_evidence, "
        "compliance_assessments, compliance_finding_mappings, compliance_controls "
        "RESTART IDENTITY CASCADE"
    )
    # network_scopes is never left empty on a real fresh install - the lab
    # preset row is always seeded (see migrations/015-network-scope-configuration.sql).
    # Re-seeding it here means every test starts from that same real-world
    # baseline instead of an empty allowlist no actual deployment ever has.
    conn.execute(
        "INSERT INTO network_scopes (label, cidr, kind, source, is_active, added_by) "
        "VALUES ('Lab environment (Docker audit-network)', '172.30.0.0/24', "
        "'lab_preset', 'manual', true, 'system:migration')"
    )
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def reset_network_scope_config():
    """device_validation.ALLOWED_NETWORKS and scan_tests.ACTIVE_SCOPES are
    process-global mutable state (see device_validation.py's own docstring
    for why) - a test that calls configure_allowed_networks()/
    configure_active_scopes() would otherwise leak its configuration into
    every test that runs afterward in this same pytest process."""
    from device_validation import configure_allowed_networks
    from policies.catalog.scan_tests import configure_active_scopes

    yield
    configure_allowed_networks(["172.30.0.0/24"])
    configure_active_scopes(["172.30.0.0/24"])
