"""Builds and renders the per-device PDF assessment report.

Split deliberately in two: build_report_model() is a pure data function with no
rendering dependency, so report *content* can be tested without WeasyPrint and
without parsing a PDF. render_report_pdf() is the only part that needs the
renderer.

Nothing here generates narrative text. Every value is a database value or text
copied verbatim from a control YAML - a generated summary paragraph would
contradict the report's own determinism claim.
"""
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

VERDICT_STATUSES = ("PASS", "FAIL", "PARTIAL", "INCONCLUSIVE")


# Read lazily rather than as a module-level constant so it reflects the
# environment at request time, matching how main.py resolves CONTROLS_DIR.
def _controls_dir() -> Path:
    return Path(os.environ.get("CONTROLS_DIR", "/work/policies/controls"))


def _load_control(control_id: str) -> dict | None:
    """Load one control YAML, or None if the file is gone.

    Controls are files and verdicts are database rows, so they can drift.
    """
    path = _controls_dir() / f"{control_id}.yaml"
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _first_saudi_source(control: dict) -> dict:
    sources = control.get("saudi_source") or []
    return sources[0] if sources else {}


def build_report_model(conn, device_id: str) -> dict | None:
    """Assemble everything the report template needs. None if device is unknown."""
    device_row = conn.execute(
        """
        SELECT device_id, display_name, description, tier, host, vendor, model,
               location, owner, notes, source, created_at, updated_at
        FROM devices WHERE device_id = %s
        """,
        (device_id,),
    ).fetchone()
    if device_row is None:
        return None

    device_keys = (
        "device_id", "display_name", "description", "tier", "host", "vendor",
        "model", "location", "owner", "notes", "source", "created_at", "updated_at",
    )
    device = dict(zip(device_keys, device_row))
    device["created_at"] = device["created_at"].isoformat()
    device["updated_at"] = device["updated_at"].isoformat()

    service_rows = conn.execute(
        """
        SELECT service_type, port, published_port, enabled
        FROM device_services WHERE device_id = %s ORDER BY id
        """,
        (device_id,),
    ).fetchall()
    services = [
        {"service_type": r[0], "port": r[1], "published_port": r[2], "enabled": r[3]}
        for r in service_rows
    ]

    verdict_rows = conn.execute(
        """
        SELECT verdict_id, control_id, status, severity, reason, timestamp
        FROM verdicts WHERE device_id = %s ORDER BY control_id
        """,
        (device_id,),
    ).fetchall()

    controls = []
    counts = {status: 0 for status in VERDICT_STATUSES}
    for verdict_id, control_id, status, severity, reason, timestamp in verdict_rows:
        control = _load_control(control_id)
        source = _first_saudi_source(control) if control else {}
        controls.append(
            {
                "control_id": control_id,
                "title": control.get("title") if control else None,
                "severity": severity,
                "framework": source.get("framework"),
                "reference": source.get("reference"),
                "clause": source.get("clause"),
                "remediation": control.get("remediation") if control else None,
                "status": status,
                "reason": reason,
                "verdict_id": verdict_id,
                "timestamp": timestamp.isoformat(),
                "control_found": control is not None,
            }
        )
        if status in counts:
            counts[status] += 1

    evidence_rows = conn.execute(
        """
        SELECT evidence_id, test_id, tool, tool_version, command, timestamp,
               finding, confidence, raw_output_path, sha256
        FROM evidence WHERE device_id = %s ORDER BY timestamp
        """,
        (device_id,),
    ).fetchall()
    evidence = [
        {
            "evidence_id": r[0], "test_id": r[1], "tool": r[2], "tool_version": r[3],
            "command": r[4], "timestamp": r[5].isoformat(), "finding": r[6],
            "confidence": r[7], "raw_output_path": r[8], "sha256": r[9],
        }
        for r in evidence_rows
    ]

    return {
        "device": device,
        "services": services,
        "controls": controls,
        "counts": counts,
        "evidence": evidence,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
