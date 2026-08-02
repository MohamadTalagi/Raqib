"""Builds and renders the AI Executive Summary (IoTGuard Stage 08) - the
final analytical stage of the pipeline, summarizing overall fleet posture
for both technical and non-technical stakeholders.

Split into build (pure, testable without WeasyPrint) and render (the only
part that needs the renderer), same convention as report.py/nca_report.py.
This module reuses those two wholesale rather than reimplementing anything:
report.build_report_model() already assembles a device's SA-IOT compliance,
evidence+tools, vulnerability summary, and risk score in one call - this
module calls it once per device and adds the two things it doesn't cover
(NCA compliance gaps, remediation blueprints).

**Deliberately no AI-generated narrative text** - confirmed with the
project owner before building this. Every other report in this app already
carries the same rule ("a generated summary paragraph would contradict the
report's own determinism claim") and a document aimed at non-technical
stakeholders is exactly where a hallucinated claim would do the most
damage. The "AI" in this stage's name is satisfied by aggregating the
already-AI-generated, human-reviewed Remediation blueprints from Stage 07 -
every sentence here is a template filled with real, already-computed
values, never new prose.
"""
from datetime import datetime, timezone
from pathlib import Path

from nca_routes import _evaluator_rows_for_scope
from policies.nca.evaluator import _applicable_required, effective_status
from report import build_report_model
from risk_routes import _compute_risk_for_device

REMEDIATION_COLUMNS = (
    "id, finding_type, finding_id, device_id, control_id, model, root_cause, "
    "remediation_steps, priority, estimated_effort, caveats, generated_at, "
    "reviewed, reviewed_by, reviewed_at, superseded_by"
)

PRIORITY_ORDER = {"immediate": 0, "short_term": 1, "long_term": 2}


def _row_to_blueprint(row) -> dict:
    (id_, finding_type, finding_id, device_id, control_id, model, root_cause,
     remediation_steps, priority, estimated_effort, caveats, generated_at,
     reviewed, reviewed_by, reviewed_at, superseded_by) = row
    return {
        "id": id_, "finding_type": finding_type, "finding_id": finding_id,
        "device_id": device_id, "control_id": control_id, "model": model,
        "root_cause": root_cause, "remediation_steps": remediation_steps,
        "priority": priority, "estimated_effort": estimated_effort, "caveats": caveats,
        "generated_at": generated_at.isoformat(),
        "reviewed": reviewed, "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at.isoformat() if reviewed_at else None,
        "superseded_by": superseded_by,
    }


def _remediation_for_device(conn, device_id: str) -> list[dict]:
    rows = conn.execute(
        f"SELECT {REMEDIATION_COLUMNS} FROM remediation_blueprints "
        "WHERE device_id = %s AND superseded_by IS NULL",
        (device_id,),
    ).fetchall()
    blueprints = [_row_to_blueprint(r) for r in rows]
    blueprints.sort(key=lambda b: (PRIORITY_ORDER[b["priority"]], b["generated_at"]))
    return blueprints


def _nca_gaps_for_device(conn, device_id: str) -> list[dict]:
    """Currently fail/partial, applicable+required NCA controls for this
    device - same effective-status/applicability rules
    policies/nca/evaluator.py's own aggregate functions already use, so this
    can never disagree with the device's own NCA readiness classification."""
    rows = _evaluator_rows_for_scope(conn, device_id=device_id)
    gaps = [r for r in _applicable_required(rows) if effective_status(r) in ("fail", "partial")]
    if not gaps:
        return []

    control_rows = conn.execute(
        "SELECT id, domain_name, subdomain_name, guideline_id, canonical_requirement, blocking "
        "FROM compliance_controls WHERE id = ANY(%s)",
        ([g["control_id"] for g in gaps],),
    ).fetchall()
    names_by_id = {r[0]: r for r in control_rows}

    result = []
    for gap in gaps:
        control = names_by_id.get(gap["control_id"])
        if control is None:
            continue
        result.append({
            "control_id": gap["control_id"],
            "domain_name": control[1],
            "subdomain_name": control[2],
            "guideline_id": control[3],
            "canonical_requirement": control[4],
            "blocking": control[5],
            "status": effective_status(gap),
        })
    return result


def build_executive_summary_model(conn) -> dict:
    device_rows = conn.execute(
        "SELECT device_id, display_name FROM devices ORDER BY device_id"
    ).fetchall()

    devices = []
    total_sa_iot_gaps = 0
    total_nca_gaps = 0
    total_remediation = 0
    total_reviewed = 0
    all_immediate_unreviewed = []
    all_blocking_gaps = []

    for device_id, display_name in device_rows:
        report_model = build_report_model(conn, device_id)
        risk = _compute_risk_for_device(conn, device_id)

        sa_iot_gaps = [c for c in report_model["controls"] if c["status"] in ("FAIL", "PARTIAL")]
        nca_gaps = _nca_gaps_for_device(conn, device_id)
        remediation = _remediation_for_device(conn, device_id)

        total_sa_iot_gaps += len(sa_iot_gaps)
        total_nca_gaps += len(nca_gaps)
        total_remediation += len(remediation)
        total_reviewed += sum(1 for b in remediation if b["reviewed"])

        for blueprint in remediation:
            if blueprint["priority"] == "immediate" and not blueprint["reviewed"]:
                all_immediate_unreviewed.append({**blueprint, "device_display_name": display_name})
        for gap in nca_gaps:
            if gap["blocking"] and gap["status"] == "fail":
                all_blocking_gaps.append({**gap, "device_id": device_id, "device_display_name": display_name})

        devices.append({
            "device_id": device_id,
            "display_name": display_name,
            "risk_score": risk["risk_score"],
            "risk_category": risk["risk_category"],
            "sa_iot_gaps": sa_iot_gaps,
            "nca_gaps": nca_gaps,
            "evidence": report_model["evidence"],
            "vulnerabilities": report_model["vulnerabilities"],
            "remediation": remediation,
        })

    devices.sort(key=lambda d: d["risk_score"], reverse=True)
    for rank, device in enumerate(devices, start=1):
        device["priority_rank"] = rank

    rank_by_device = {d["device_id"]: d["priority_rank"] for d in devices}
    all_immediate_unreviewed.sort(key=lambda b: rank_by_device.get(b["device_id"], len(devices) + 1))

    by_category = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for device in devices:
        by_category[device["risk_category"]] += 1

    total_findings = total_sa_iot_gaps + total_nca_gaps
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "devices": devices,
        "fleet_summary": {
            "total_devices": len(devices),
            "average_risk_score": (
                round(sum(d["risk_score"] for d in devices) / len(devices)) if devices else None
            ),
            "risk_by_category": by_category,
            "total_compliance_gaps": total_findings,
            "remediation_generated": total_remediation,
            "remediation_reviewed": total_reviewed,
            "remediation_coverage_pct": (
                round(total_remediation / total_findings * 100) if total_findings else None
            ),
        },
        "priority_recommendations": all_immediate_unreviewed,
        "significant_compliance_gaps": all_blocking_gaps,
    }


TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_executive_summary_pdf(model: dict) -> bytes:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from weasyprint import CSS, HTML
    from weasyprint.text.fonts import FontConfiguration

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    html = env.get_template("executive_summary.html").render(**model)

    # font_config MUST be passed to BOTH CSS() and write_pdf() - see
    # report.py's render_report_pdf for the full story on why the fallback
    # is otherwise invisible.
    font_config = FontConfiguration()
    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(
        stylesheets=[CSS(filename=str(TEMPLATE_DIR / "report.css"), font_config=font_config)],
        font_config=font_config,
    )


def render_executive_summary_html(model: dict) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    css_text = (TEMPLATE_DIR / "report.css").read_text(encoding="utf-8")
    return env.get_template("executive_summary.html").render(**model, inline_css=css_text)
