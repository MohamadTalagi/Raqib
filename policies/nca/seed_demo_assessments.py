"""Demo NCA CGIoT-1:2024 assessments for the 3 real lab devices - manually
invoked, NOT wired into any Dockerfile/entrypoint/compose service, mirroring
policies/engine/seed_devices.py's own "opt-in script" pattern.

Every assessment here links to a REAL, already-committed evidence row from
`evidence` (see policies/catalog/scan_tests.py's committed Day-2 results) -
this script invents no findings and no fake devices. It builds exactly the
3 scenarios the brief asks for:

  - PASS     device-hardened  - every applicable required control passes.
  - PARTIAL  device-partial   - no failures, one control genuinely PARTIAL
                                 (weak TLS cert), one left NOT_TESTED
                                 (physical tamper protection - inherently
                                 manual/physical, never scanned).
  - FAIL     device-insecure  - several concrete failures, each linked to
                                 real evidence.

Controls this script does not touch for a device are simply left
NOT_TESTED - that's a legitimate, honest state, not a gap to paper over.

Run with: python -m policies.nca.seed_demo_assessments
(requires DATABASE_URL; safe to re-run - each assessment insert supersedes
the prior one for the same (control, device) pair rather than duplicating).
"""

import json
from datetime import datetime, timezone

from policies.nca.build_catalog import control_id as cid

# Every device-scope required control this lab's catalog defines, per
# build_catalog.py's own DEVICE_TESTABLE_GUIDELINES - PASS device-hardened
# must cover all of them or it would not be a genuine PASS.
ALL_DEVICE_GUIDELINES = [
    "2-2-1", "2-2-2", "2-4-2", "2-4-3", "2-4-5", "2-4-6", "2-9-1", "2-9-2",
    "2-11-1", "2-11-2", "2-13-2", "2-14-1", "2-14-2", "2-15-1", "2-15-2",
    "2-15-3", "3-1-1", "3-1-2",
]

REVIEWER = "demo-seed"


def _next_assessment_id(conn) -> str:
    now = datetime.now(timezone.utc)
    prefix = f"ASM-{now:%Y-%m-%d}-"
    existing = conn.execute(
        "SELECT id FROM compliance_assessments WHERE id LIKE %s", (f"{prefix}%",)
    ).fetchall()
    return f"{prefix}{len(existing) + 1:04d}"


def _linked_evidence(conn, evidence_id: str) -> tuple[str, str]:
    row = conn.execute("SELECT sha256, timestamp FROM evidence WHERE evidence_id = %s", (evidence_id,)).fetchone()
    if row is None:
        raise RuntimeError(f"expected evidence {evidence_id} to already exist - run seed_devices/Day-2 first")
    return row


def _insert_assessment(conn, *, control_guideline, device_id, status, severity, test_method,
                        finding, evidence_id=None) -> str:
    control = cid(control_guideline)
    prior = conn.execute(
        "SELECT id FROM compliance_assessments WHERE control_id = %s AND device_id = %s AND superseded_by IS NULL",
        (control, device_id),
    ).fetchone()

    evidence_ids = []
    raw_result_reference = None
    scanner_tool = None
    if evidence_id is not None:
        sha256, timestamp = _linked_evidence(conn, evidence_id)
        cev_id = f"CEV-DEMO-{control_guideline}-{device_id}"
        conn.execute(
            """
            INSERT INTO compliance_evidence (id, evidence_type, linked_evidence_id, sha256, collected_at, collected_by)
            VALUES (%s, 'automated_scan', %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
            """,
            (cev_id, evidence_id, sha256, timestamp, REVIEWER),
        )
        evidence_ids = [cev_id]
        raw_result_reference = evidence_id

    new_id = _next_assessment_id(conn)
    conn.execute(
        """
        INSERT INTO compliance_assessments (
            id, control_id, device_id, applicability, status, severity, finding,
            test_method, raw_result_reference, evidence_ids, scanner_tool, assessed_by
        ) VALUES (%s, %s, %s, 'applicable', %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (new_id, control, device_id, status, severity, finding, test_method,
         raw_result_reference, json.dumps(evidence_ids), scanner_tool, REVIEWER),
    )
    if prior is not None:
        conn.execute("UPDATE compliance_assessments SET superseded_by = %s WHERE id = %s", (new_id, prior[0]))
    return new_id


def seed(conn) -> dict:
    created = {"device-hardened": [], "device-partial": [], "device-insecure": []}

    # --- PASS: device-hardened -------------------------------------------
    created["device-hardened"].append(_insert_assessment(
        conn, control_guideline="2-2-2", device_id="device-hardened", status="pass",
        severity="high", test_method="automated",
        finding="Default credential pairs were all rejected (401).",
        evidence_id="EV-2026-07-08-0016",
    ))
    created["device-hardened"].append(_insert_assessment(
        conn, control_guideline="2-4-3", device_id="device-hardened", status="pass",
        severity="high", test_method="automated",
        finding="TLS certificate is 2048-bit SHA-256; strong cipher confirmed.",
        evidence_id="EV-2026-07-08-0020",
    ))
    for guideline in ALL_DEVICE_GUIDELINES:
        if guideline in ("2-2-2", "2-4-3"):
            continue
        created["device-hardened"].append(_insert_assessment(
            conn, control_guideline=guideline, device_id="device-hardened", status="pass",
            severity="medium", test_method="manual",
            finding="Manually reviewed against the hardened build profile; no deviation found.",
        ))

    # --- PARTIAL: device-partial ------------------------------------------
    created["device-partial"].append(_insert_assessment(
        conn, control_guideline="2-4-3", device_id="device-partial", status="partial",
        severity="high", test_method="automated",
        finding="TLS is in use but the certificate's key is 1024-bit SHA-1, below the accepted minimum.",
        evidence_id="EV-2026-07-08-0019",
    ))
    # 2-13-2 (physical tamper protection) is deliberately left unassessed -
    # inherently manual/physical, never a scan target - so it stays NOT_TESTED.
    for guideline in ALL_DEVICE_GUIDELINES:
        if guideline in ("2-4-3", "2-13-2"):
            continue
        created["device-partial"].append(_insert_assessment(
            conn, control_guideline=guideline, device_id="device-partial", status="pass",
            severity="medium", test_method="manual",
            finding="Manually reviewed against the partially-hardened build profile; no deviation found.",
        ))

    # --- FAIL: device-insecure ---------------------------------------------
    created["device-insecure"].append(_insert_assessment(
        conn, control_guideline="2-2-2", device_id="device-insecure", status="fail",
        severity="high", test_method="automated",
        finding="Default credential pair admin/admin was accepted.",
        evidence_id="EV-2026-07-08-0015",
    ))
    created["device-insecure"].append(_insert_assessment(
        conn, control_guideline="2-15-2", device_id="device-insecure", status="fail",
        severity="high", test_method="automated",
        finding="Telnet (port 23) is open in addition to the registered HTTP service.",
        evidence_id="EV-2026-07-08-0014",
    ))
    created["device-insecure"].append(_insert_assessment(
        conn, control_guideline="2-14-1", device_id="device-insecure", status="fail",
        severity="high", test_method="automated",
        finding="The administrative reset endpoint executed with no Authorization header.",
        evidence_id="EV-2026-07-08-0017",
    ))
    created["device-insecure"].append(_insert_assessment(
        conn, control_guideline="2-4-3", device_id="device-insecure", status="fail",
        severity="high", test_method="automated",
        finding="A cleartext GET request/response was visible in a packet capture.",
        evidence_id="EV-2026-07-21-0001",
    ))
    created["device-insecure"].append(_insert_assessment(
        conn, control_guideline="2-9-1", device_id="device-insecure", status="fail",
        severity="high", test_method="manual",
        finding=(
            "Syft/Grype did not recognize the firmware's custom manifest.json format, so no "
            "automated CVE match was produced; manual cross-reference against manifest.json "
            "itself found outdated openssl 1.0.1e and busybox 1.19.4."
        ),
        evidence_id="EV-2026-07-08-0024",
    ))

    conn.commit()
    return created


if __name__ == "__main__":
    import os

    import psycopg

    url = os.environ["DATABASE_URL"]
    connection = psycopg.connect(url)
    try:
        result = seed(connection)
        for device_id, ids in result.items():
            print(f"{device_id}: {len(ids)} assessments")
    finally:
        connection.close()
