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
        "compliance_audit_events, compliance_exceptions, compliance_evidence, "
        "compliance_assessments, compliance_finding_mappings, compliance_controls "
        "RESTART IDENTITY CASCADE"
    )
    conn.commit()
    conn.close()
