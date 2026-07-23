"""Builds and renders the NCA CGIoT-1:2024 executive compliance report.

Split into build (pure, testable without WeasyPrint) and render (the only
part that needs the renderer) - mirrors report.py's split, for the identical
reason: report *content* should be verifiable without an installed PDF
engine. Nothing here generates narrative text: every string is a database
value or one of policies/nca/compliance_text.py's fixed strings.
"""

from datetime import datetime, timezone
from pathlib import Path

from policies.nca.compliance_text import (
    DISCLAIMER,
    METHODOLOGY_TEXT,
    PRODUCT_LABEL,
    STATUS_DEFINITIONS,
)
from policies.nca.evaluator import device_overall_status, device_score, domain_summary


def build_nca_executive_report_model(conn, evaluator_rows_for_scope) -> dict:
    """evaluator_rows_for_scope is nca_routes._evaluator_rows_for_scope,
    passed in rather than imported to avoid a nca_report <-> nca_routes
    import cycle (nca_routes imports render_nca_executive_report_pdf from
    this module)."""
    device_rows = conn.execute(
        "SELECT device_id, display_name, tier FROM devices ORDER BY device_id"
    ).fetchall()

    devices = []
    all_rows = []
    failed_or_partial = []
    for device_id, display_name, tier in device_rows:
        rows = evaluator_rows_for_scope(conn, device_id=device_id)
        all_rows.extend(rows)
        overall = device_overall_status(rows)
        score = device_score(rows)
        devices.append(
            {
                "device_id": device_id,
                "display_name": display_name,
                "tier": tier,
                "overall_status": overall,
                "score": score,
            }
        )
        if overall in ("fail", "partial"):
            control_names = conn.execute(
                "SELECT id, domain_name, subdomain_name, guideline_id, canonical_requirement "
                "FROM compliance_controls WHERE id = ANY(%s)",
                ([r["control_id"] for r in rows if r["required"]],),
            ).fetchall()
            names_by_id = {r[0]: r for r in control_names}
            for row in rows:
                if not row["required"]:
                    continue
                effective = row["status"]
                if effective not in ("fail", "partial", "not_tested"):
                    continue
                control = names_by_id.get(row["control_id"])
                if control is None:
                    continue
                failed_or_partial.append(
                    {
                        "device_id": device_id,
                        "control_id": row["control_id"],
                        "domain_name": control[1],
                        "subdomain_name": control[2],
                        "guideline_id": control[3],
                        "status": effective,
                    }
                )

    exception_rows = conn.execute(
        """
        SELECT id, control_id, device_id, organizational_scope_id, reason,
               compensating_control, approved_by, approved_at, expires_at
        FROM compliance_exceptions WHERE status = 'approved' ORDER BY control_id
        """
    ).fetchall()
    approved_exceptions = [
        {
            "id": r[0], "control_id": r[1], "device_id": r[2],
            "organizational_scope_id": r[3], "reason": r[4],
            "compensating_control": r[5], "approved_by": r[6],
            "approved_at": r[7].isoformat() if r[7] else None,
            "expires_at": r[8].isoformat(),
        }
        for r in exception_rows
    ]

    return {
        "product_label": PRODUCT_LABEL,
        "framework": "NCA-CGIoT",
        "framework_version": "1:2024",
        "disclaimer": DISCLAIMER,
        "methodology": METHODOLOGY_TEXT,
        "status_definitions": STATUS_DEFINITIONS,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "devices": devices,
        "domain_summary": domain_summary(all_rows),
        "failed_or_partial_controls": failed_or_partial,
        "approved_exceptions": approved_exceptions,
    }


TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_nca_executive_report_pdf(model: dict) -> bytes:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from weasyprint import CSS, HTML
    from weasyprint.text.fonts import FontConfiguration

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    html = env.get_template("nca_executive_report.html").render(**model)

    # font_config MUST be passed to BOTH CSS() and write_pdf() - see
    # report.py's render_report_pdf for the full story on why the fallback is
    # otherwise invisible.
    font_config = FontConfiguration()
    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(
        stylesheets=[CSS(filename=str(TEMPLATE_DIR / "report.css"), font_config=font_config)],
        font_config=font_config,
    )
