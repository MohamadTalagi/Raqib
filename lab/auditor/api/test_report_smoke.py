"""Proves WeasyPrint renders and the vendored fonts carry the glyphs we need.

Skipped when WeasyPrint is not installed locally, following the same pattern
policies/engine/test_seed_devices.py uses for an absent database.
"""
import re
import zlib
from pathlib import Path

import pytest

weasyprint = pytest.importorskip("weasyprint")

FONT_DIR = Path(__file__).parent / "assets" / "fonts"

_STREAM_RE = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)


def _decompressed_pdf_text(pdf: bytes) -> bytes:
    """Return the PDF bytes with every FlateDecode stream inflated and appended.

    WeasyPrint/pydyf write PDF 1.7 output with compressed object streams, so
    dictionary entries such as /BaseFont /ABCDEF+Inter or /FontName
    /ABCDEF+DejaVuSans do not appear as plain text in the raw PDF bytes --
    they are inside zlib-compressed stream objects. A naive `b"Inter" in pdf`
    check therefore produces a false negative even when the font genuinely
    embedded correctly, and would produce an equally false negative for the
    DejaVu fallback, i.e. it cannot distinguish the two cases at all. Every
    FlateDecode stream must be inflated before searching for the font name.
    """
    chunks = [pdf]
    for match in _STREAM_RE.finditer(pdf):
        try:
            chunks.append(zlib.decompress(match.group(1)))
        except zlib.error:
            continue
    return b"".join(chunks)


def test_font_files_are_vendored():
    files = list(FONT_DIR.glob("*"))
    assert files, f"no font files found in {FONT_DIR}"


def test_weasyprint_renders_a_pdf():
    html = weasyprint.HTML(string="<html><body><p>hello</p></body></html>")
    pdf = html.write_pdf()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500


def test_rendered_pdf_is_not_empty_for_our_special_characters():
    # The real data contains section signs in NCA references and em-dashes in
    # display names ("Smart Camera — Insecure"), plus 64-char SHA-256 strings.
    # A missing glyph renders as a blank box in exactly the place a reader looks.
    html = weasyprint.HTML(
        string="<html><body><p>CGIoT-1:2024 §2-2-2 — Smart Camera</p>"
        "<p>7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61</p>"
        "</body></html>"
    )
    pdf = html.write_pdf()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500


def test_vendored_font_is_actually_embedded_not_dejavu_fallback() -> None:
    """Renders through @font-face with FontConfiguration wired correctly, then
    inspects the raw PDF bytes for the embedded font's subset name.

    WeasyPrint requires an explicit FontConfiguration() instance passed to
    BOTH CSS(...) and write_pdf(...). Omit either one and every @font-face
    rule is silently ignored -- rendering falls back to DejaVu Sans with no
    error, no warning, and (critically) no visible difference: DejaVu covers
    the section sign, the em-dash and hex digits, and ships distinct
    Regular/Bold weights. A human looking at the output PDF cannot tell the
    vendored font was never used. The only way to catch this is to inspect
    the embedded font descriptor bytes, which is what this test does.
    """
    from weasyprint import CSS
    from weasyprint.text.fonts import FontConfiguration

    font_path = FONT_DIR / "Inter-Regular.ttf"
    assert font_path.is_file(), f"expected vendored font at {font_path}"

    font_config = FontConfiguration()
    css = CSS(
        string=f"""
        @font-face {{
            font-family: 'Inter';
            src: url('{font_path.as_uri()}');
            font-weight: 400;
        }}
        body {{ font-family: 'Inter', sans-serif; }}
        """,
        font_config=font_config,
    )
    html = weasyprint.HTML(
        string="<html><body><p>CGIoT-1:2024 §2-2-2 — vendored font check</p></body></html>"
    )
    pdf = html.write_pdf(stylesheets=[css], font_config=font_config)
    assert pdf.startswith(b"%PDF-")

    inflated = _decompressed_pdf_text(pdf)
    assert b"Inter" in inflated, (
        "the vendored Inter family was not embedded -- @font-face was not "
        "applied (check that font_config is passed to both CSS() and write_pdf())"
    )
    assert b"DejaVu" not in inflated, (
        "rendering fell back to DejaVu Sans -- the vendored font was never "
        "loaded despite the @font-face rule"
    )


def test_omitting_font_config_reproduces_the_dejavu_fallback() -> None:
    """Regression control for the detector above.

    Renders the identical @font-face CSS but WITHOUT a FontConfiguration
    instance -- the exact mistake this whole test file exists to catch. If
    this test ever starts asserting the opposite, `_decompressed_pdf_text`
    (or WeasyPrint's own behaviour) has changed and the detector above can no
    longer be trusted to fail loudly on a real regression.
    """
    font_path = FONT_DIR / "Inter-Regular.ttf"
    css = weasyprint.CSS(
        string=f"""
        @font-face {{
            font-family: 'Inter';
            src: url('{font_path.as_uri()}');
            font-weight: 400;
        }}
        body {{ font-family: 'Inter', sans-serif; }}
        """
        # No font_config= here -- this is the bug, reproduced on purpose.
    )
    html = weasyprint.HTML(
        string="<html><body><p>CGIoT-1:2024 §2-2-2 — vendored font check</p></body></html>"
    )
    pdf = html.write_pdf(stylesheets=[css])
    inflated = _decompressed_pdf_text(pdf)

    assert b"DejaVu" in inflated, (
        "expected the DejaVu fallback when font_config is omitted -- if this "
        "no longer reproduces, WeasyPrint's default behaviour changed"
    )
    assert b"Inter" not in inflated


# Reused by test_renders_the_real_template_end_to_end and by the manual
# render-and-open step (see .superpowers/sdd/task-3-report.md) so the sample
# used for a visual check is exactly the sample covered by an automated test.
SAMPLE_MODEL = {
    "device": {
        "device_id": "device-insecure", "display_name": "Smart Camera — Insecure",
        "description": "Default creds, plain HTTP.", "tier": "insecure",
        "host": "device-insecure", "vendor": "AcmeCam", "model": None,
        "location": None, "owner": None, "notes": None, "source": "seeded",
        "created_at": "2026-07-19T00:00:00+00:00",
        "updated_at": "2026-07-19T00:00:00+00:00",
    },
    "services": [
        {"service_type": "http", "port": 80, "published_port": 8081, "enabled": True},
        {"service_type": "mqtt", "port": 1883, "published_port": None, "enabled": True},
    ],
    "controls": [
        {
            "control_id": "SA-IOT-002", "title": "No default or hard-coded credentials",
            "severity": "high", "framework": "CGIoT-1:2024", "reference": "2-2-2",
            "clause": "Prevent the users from using default and hard-coded passwords.",
            "remediation": "Force a unique strong password on first boot.",
            "status": "FAIL", "reason": "observations.default_creds equals True",
            "verdict_id": "VD-1", "timestamp": "2026-07-08T08:58:44+00:00",
            "control_found": True,
        },
        {
            "control_id": "SA-IOT-999", "title": None, "severity": "high",
            "framework": None, "reference": None, "clause": None,
            "remediation": None, "status": "FAIL", "reason": "stored reason",
            "verdict_id": "VD-2", "timestamp": "2026-07-08T08:58:44+00:00",
            "control_found": False,
        },
    ],
    "counts": {"PASS": 0, "FAIL": 2, "PARTIAL": 0, "INCONCLUSIVE": 0},
    "evidence": [
        {
            "evidence_id": "EV-1", "test_id": "TEST-AUTH-DEFAULT-CREDS",
            "tool": "curl", "tool_version": "8.5.0",
            "command": "curl -s -X POST http://device-insecure/login",
            "timestamp": "2026-07-08T08:58:44+00:00",
            "finding": "Default creds admin/admin accepted", "confidence": "high",
            "raw_output_path": "document-store/raw/EV-1.txt",
            "sha256": "7421af31aecc115c92498182563413bdb941aed43c90ff7d528544d52945ed61",
        }
    ],
    "generated_at": "2026-07-19T12:00:00+00:00",
}


def test_renders_the_real_template_end_to_end():
    from report import render_report_pdf

    pdf = render_report_pdf(SAMPLE_MODEL)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 3000


def test_renders_a_device_with_no_evidence():
    from report import render_report_pdf

    pdf = render_report_pdf(
        {
            "device": {
                "device_id": "telnet-sim", "display_name": "Telnet Service Simulator",
                "description": "", "tier": "insecure", "host": "telnet-sim",
                "vendor": None, "model": None, "location": None, "owner": None,
                "notes": None, "source": "seeded",
                "created_at": "2026-07-19T00:00:00+00:00",
                "updated_at": "2026-07-19T00:00:00+00:00",
            },
            "services": [
                {"service_type": "telnet", "port": 23, "published_port": None, "enabled": True}
            ],
            "controls": [],
            "counts": {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "INCONCLUSIVE": 0},
            "evidence": [],
            "generated_at": "2026-07-19T12:00:00+00:00",
        }
    )
    assert pdf.startswith(b"%PDF-")
