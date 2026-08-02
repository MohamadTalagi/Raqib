"""AI Executive Summary (IoTGuard Stage 08) - a new APIRouter, same pattern
as nca_routes.py/risk_routes.py/remediation_routes.py.

No write endpoints - like risk_routes.py, everything here is derived live
from data recorded elsewhere and never cached or persisted, so it can never
drift out of sync with the dashboard. Not logged to report_records (that
table's device_id column is scoped to a single device by design; a
fleet-wide report has no single device to log against - a deliberate,
documented scope cut, see docs/executive-summary.md).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Response

from db import get_connection
from executive_summary import (
    build_executive_summary_model,
    render_executive_summary_html,
    render_executive_summary_pdf,
)

router = APIRouter(prefix="/executive-summary", tags=["executive-summary"])


@router.get("")
def get_executive_summary() -> dict:
    conn = get_connection()
    try:
        return build_executive_summary_model(conn)
    finally:
        conn.close()


@router.get("/report.pdf")
def get_executive_summary_report_pdf():
    conn = get_connection()
    try:
        model = build_executive_summary_model(conn)
    finally:
        conn.close()

    pdf = render_executive_summary_pdf(model)
    filename = f"iotguard-executive-summary-{datetime.now(timezone.utc):%Y-%m-%d}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report.html")
def get_executive_summary_report_html():
    conn = get_connection()
    try:
        model = build_executive_summary_model(conn)
    finally:
        conn.close()
    return Response(content=render_executive_summary_html(model), media_type="text/html")
