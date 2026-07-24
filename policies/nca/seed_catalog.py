"""Upserts the committed policies/nca/catalog_1_2024.json artifact into the
compliance_controls table.

Idempotent (ON CONFLICT on the same (framework, framework_version,
guideline_id) unique constraint the table already enforces): safe to run
against a freshly-migrated database or re-run after catalog_1_2024.json is
regenerated for wording fixes. Never deletes a row - retiring a guideline
means setting enabled=false in the catalog, so devices keep the assessment
history for their old, no-longer-current guideline_id (see
docs/nca-compliance.md's "add a new framework version" section).
"""

import json
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parent / "catalog_1_2024.json"


def seed(conn) -> int:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    upserted = 0
    for entry in catalog["guidelines"]:
        result = conn.execute(
            """
            INSERT INTO compliance_controls (
                id, framework, framework_version, domain_id, domain_name,
                subdomain_id, subdomain_name, guideline_id,
                canonical_requirement, implementation_summary, source_page,
                scope_type, assessment_type, required, severity, blocking,
                evidence_requirements, remediation_guidance, enabled
            )
            VALUES (
                %(id)s, %(framework)s, %(framework_version)s, %(domain_id)s,
                %(domain_name)s, %(subdomain_id)s, %(subdomain_name)s,
                %(guideline_id)s, %(canonical_requirement)s,
                %(implementation_summary)s, %(source_page)s, %(scope_type)s,
                %(assessment_type)s, %(required)s, %(severity)s, %(blocking)s,
                %(evidence_requirements)s, %(remediation_guidance)s, %(enabled)s
            )
            ON CONFLICT (framework, framework_version, guideline_id) DO UPDATE SET
                domain_name = EXCLUDED.domain_name,
                subdomain_name = EXCLUDED.subdomain_name,
                canonical_requirement = EXCLUDED.canonical_requirement,
                implementation_summary = EXCLUDED.implementation_summary,
                source_page = EXCLUDED.source_page,
                scope_type = EXCLUDED.scope_type,
                assessment_type = EXCLUDED.assessment_type,
                required = EXCLUDED.required,
                severity = EXCLUDED.severity,
                blocking = EXCLUDED.blocking,
                evidence_requirements = EXCLUDED.evidence_requirements,
                remediation_guidance = EXCLUDED.remediation_guidance,
                enabled = EXCLUDED.enabled,
                updated_at = now()
            """,
            {
                **entry,
                "evidence_requirements": json.dumps(entry["evidence_requirements"]),
            },
        )
        if result.rowcount != 0:
            upserted += 1
    conn.commit()
    return upserted


if __name__ == "__main__":
    import os

    import psycopg

    url = os.environ["DATABASE_URL"]
    connection = psycopg.connect(url)
    try:
        print(f"Upserted {seed(connection)} controls")
    finally:
        connection.close()
